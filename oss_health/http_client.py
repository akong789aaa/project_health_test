"""HTTP 客户端：重试、磁盘缓存、ETag、录制 / 离线回放、GitHub 限流感知。

设计目标：

* 默认情况下把响应缓存到本地（TTL 内直接命中），避免重复消耗 GitHub 配额；
* ``--record DIR`` 把真实响应录制成快照；
* ``--offline DIR`` 只读快照，完全离线复现一份报告（demo / 测试用）；
* 注入 ``transport`` 可在测试中完全替换网络层。
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from .config import DEFAULT_CACHE_TTL_HOURS, USER_AGENT
from .util import parse_iso, utcnow

CACHE_VERSION = 1


class HttpError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, url: str = "", body: str = ""):
        super().__init__(message)
        self.status = status
        self.url = url
        self.body = body


class NotFound(HttpError):
    pass


class RateLimited(HttpError):
    def __init__(self, message: str, reset_at: Optional[datetime] = None, url: str = ""):
        super().__init__(message, status=403, url=url)
        self.reset_at = reset_at


class OfflineMiss(HttpError):
    pass


@dataclass
class Response:
    status: int
    url: str
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    from_cache: bool = False

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except json.JSONDecodeError as exc:
            raise HttpError(f"响应不是合法 JSON: {self.url}: {exc}", status=self.status, url=self.url) from exc

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


_PERSIST_HEADERS = (
    "etag",
    "last-modified",
    "content-type",
    "x-ratelimit-remaining",
    "x-ratelimit-limit",
    "x-ratelimit-reset",
    "x-ratelimit-resource",
)


class HttpClient:
    def __init__(
        self,
        *,
        cache_dir: Optional[str | Path] = None,
        ttl_hours: float = DEFAULT_CACHE_TTL_HOURS,
        offline_dir: Optional[str | Path] = None,
        record_dir: Optional[str | Path] = None,
        timeout: float = 25.0,
        retries: int = 2,
        github_token: Optional[str] = None,
        verbose: bool = False,
        transport: Optional[Callable[[str, str, dict[str, str], Optional[bytes]], Response]] = None,
        user_agent: str = USER_AGENT,
    ):
        self.cache_dir = Path(cache_dir).expanduser() if cache_dir else None
        self.ttl_seconds = max(0.0, float(ttl_hours)) * 3600.0
        self.offline_dir = Path(offline_dir).expanduser() if offline_dir else None
        self.record_dir = Path(record_dir).expanduser() if record_dir else None
        self.timeout = timeout
        self.retries = max(0, retries)
        self.github_token = (
            github_token
            or os.environ.get("GITHUB_TOKEN")
            or os.environ.get("GH_TOKEN")
            or ""
        ).strip()
        self.verbose = verbose
        self.transport = transport
        self.user_agent = user_agent

        self.request_count = 0
        self.cache_hits = 0
        self.offline_hits = 0
        self.github_remaining: Optional[int] = None
        self.github_limit: Optional[int] = None
        self.github_reset: Optional[datetime] = None

        if self.cache_dir:
            self._ensure_dir(self.cache_dir)
        if self.record_dir:
            self._ensure_dir(self.record_dir)

    # ------------------------------------------------------------------
    # 公共入口
    # ------------------------------------------------------------------

    def get(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        accept: str = "application/json",
    ) -> Response:
        merged = {"Accept": accept}
        if headers:
            merged.update(headers)
        return self.request("GET", url, headers=merged)

    def get_json(self, url: str, *, headers: Optional[dict[str, str]] = None, accept: str = "application/json") -> Any:
        return self.get(url, headers=headers, accept=accept).json()

    def post_json(self, url: str, payload: Any, *, headers: Optional[dict[str, str]] = None) -> Any:
        merged = {"Content-Type": "application/json"}
        if headers:
            merged.update(headers)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self.request("POST", url, headers=merged, body=body).json()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Response:
        method = method.upper()
        headers = dict(headers or {})
        key = self._cache_key(method, url, body)

        # 1) 离线回放
        if self.offline_dir is not None:
            entry = self._load_entry(self.offline_dir, key)
            if entry is None and method == "GET":
                entry = self._load_offline_fallback(self.offline_dir, url)
            if entry is None:
                raise OfflineMiss(f"离线快照中缺少响应: {method} {url}", url=url)
            self.offline_hits += 1
            response = self._entry_to_response(entry, from_cache=True)
            self._raise_for_status(response)
            return response

        # 2) 测试注入的 transport
        if self.transport is not None:
            self.request_count += 1
            response = self.transport(method, url, self._default_headers(url, headers), body)
            self._update_rate_limit(response.headers)
            self._raise_for_status(response)
            return response

        # 3) 本地缓存（新鲜则直接返回）。录制模式下也会复用缓存，并把结果写入快照
        cached = self._load_entry(self.cache_dir, key) if self.cache_dir else None
        if cached is not None and self._is_fresh(cached):
            self.cache_hits += 1
            if self.record_dir is not None and cached.get("status", 200) < 500:
                self._record(key, self._entry_to_response(cached, from_cache=True))
            return self._entry_to_response(cached, from_cache=True)

        # 4) 真实请求（过期缓存做条件请求；录制时总是取最新内容）
        req_headers = self._default_headers(url, headers)
        if (
            method == "GET"
            and cached is not None
            and cached.get("headers", {}).get("etag")
            and self.record_dir is None
        ):
            req_headers["If-None-Match"] = cached["headers"]["etag"]

        last_error: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                response = self._do_http(method, url, req_headers, body)
            except _NotModified:
                if cached is not None:
                    cached["stored_at"] = utcnow().isoformat()
                    self._store_entry(self.cache_dir, key, cached, refresh_only=True)
                    self.cache_hits += 1
                    return self._entry_to_response(cached, from_cache=True)
                raise HttpError(f"收到 304 但没有可用缓存: {url}", status=304, url=url)
            except NotFound:
                raise
            except RateLimited:
                raise
            except (HttpError, urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                if isinstance(exc, HttpError) and exc.status and 400 <= exc.status < 500:
                    raise  # 4xx 重试无意义
                if attempt < self.retries:
                    delay = 1.0 * (attempt + 1)
                    self._log(f"请求失败，{delay:.0f}s 后重试 ({attempt + 1}/{self.retries}): {url}")
                    time.sleep(delay)
                    continue
                break

            self.request_count += 1
            self._update_rate_limit(response.headers)
            if response.status != 202:  # GitHub stats API 计算中返回 202，不能缓存
                self._store_entry(self.cache_dir, key, self._response_to_entry(response))
                self._record(key, response)
            self._log(f"{response.status} {method} {url} ({len(response.body)}B)")
            return response

        if isinstance(last_error, HttpError):
            raise last_error
        raise HttpError(f"请求失败: {method} {url}: {last_error}", url=url)

    # ------------------------------------------------------------------
    # 状态码处理
    # ------------------------------------------------------------------

    def _raise_for_status(self, response: Response) -> None:
        if 200 <= response.status < 300:
            return
        text = response.text[:300]
        if response.status == 404:
            raise NotFound(f"资源不存在 (404): {response.url}", status=404, url=response.url, body=text)
        if response.status in (403, 429):
            raise RateLimited(
                f"请求被限流 ({response.status})：{response.url}",
                url=response.url,
            )
        raise HttpError(
            f"HTTP {response.status}: {response.url}",
            status=response.status,
            url=response.url,
            body=text,
        )

    # ------------------------------------------------------------------
    # 网络层
    # ------------------------------------------------------------------

    def _default_headers(self, url: str, extra: dict[str, str]) -> dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept-Encoding": "identity",
        }
        if "api.github.com" in url:
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            headers["Accept"] = "application/vnd.github+json"
            if self.github_token:
                headers["Authorization"] = f"Bearer {self.github_token}"
        headers.update(extra)
        return headers

    def _do_http(
        self, method: str, url: str, headers: dict[str, str], body: Optional[bytes]
    ) -> Response:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as raw:
                data = raw.read()
                resp_headers = {k.lower(): v for k, v in raw.headers.items()}
                if resp_headers.get("content-encoding", "").lower() == "gzip":
                    try:
                        data = gzip.decompress(data)
                    except OSError:
                        pass
                return Response(
                    status=int(raw.status),
                    url=url,
                    body=data,
                    headers=resp_headers,
                )
        except urllib.error.HTTPError as exc:
            hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
            raw_body = b""
            try:
                raw_body = exc.read() or b""
            except Exception:
                pass
            content_encoding = hdrs.get("content-encoding", "").lower()
            if content_encoding == "gzip" and raw_body:
                try:
                    raw_body = gzip.decompress(raw_body)
                except OSError:
                    pass
            text = raw_body.decode("utf-8", errors="replace")
            if exc.code == 304:
                raise _NotModified() from exc
            if exc.code in (403, 429) and self._is_rate_limited(hdrs):
                reset_at = None
                remaining = hdrs.get("x-ratelimit-reset")
                if remaining:
                    try:
                        reset_at = datetime.fromtimestamp(int(remaining), tz=utcnow().tzinfo)
                    except (ValueError, OSError):
                        reset_at = None
                raise RateLimited(
                    "GitHub API 配额已用尽"
                    + (f"，{reset_at.astimezone().strftime('%H:%M')} 后重置" if reset_at else "")
                    + "。设置 GITHUB_TOKEN 可将上限从 60 次/小时提升到 5000 次/小时。",
                    reset_at=reset_at,
                    url=url,
                ) from exc
            if exc.code == 404:
                raise NotFound(f"资源不存在 (404): {url}", status=404, url=url, body=text) from exc
            if exc.code >= 500 and exc.code not in (501,):
                raise HttpError(f"服务端错误 {exc.code}: {url}", status=exc.code, url=url, body=text) from exc
            raise HttpError(f"HTTP {exc.code}: {url}", status=exc.code, url=url, body=text) from exc
        except TimeoutError as exc:
            raise HttpError(f"请求超时: {url}", url=url) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, TimeoutError):
                raise HttpError(f"请求超时: {url}", url=url) from exc
            raise HttpError(f"网络错误: {url}: {reason}", url=url) from exc

    def _is_rate_limited(self, headers: dict[str, str]) -> bool:
        remaining = headers.get("x-ratelimit-remaining")
        if remaining is not None:
            try:
                return int(remaining) <= 0
            except ValueError:
                pass
        return True  # 403/429 且没有配额头，按限流处理

    def _update_rate_limit(self, headers: dict[str, str]) -> None:
        headers = {k.lower(): v for k, v in headers.items()}
        remaining = headers.get("x-ratelimit-remaining")
        limit = headers.get("x-ratelimit-limit")
        reset = headers.get("x-ratelimit-reset")
        if remaining is not None:
            try:
                self.github_remaining = int(remaining)
            except ValueError:
                pass
        if limit is not None:
            try:
                self.github_limit = int(limit)
            except ValueError:
                pass
        if reset is not None:
            try:
                self.github_reset = datetime.fromtimestamp(int(reset), tz=utcnow().tzinfo)
            except (ValueError, OSError):
                pass

    # ------------------------------------------------------------------
    # 缓存 / 录制
    # ------------------------------------------------------------------

    def _load_offline_fallback(self, directory: Path, url: str) -> Optional[dict[str, Any]]:
        """离线回放兜底：时间窗口参数（since）会随日期变化，忽略它再匹配一次。"""
        try:
            base, _, query = url.partition("?")
            stable = sorted(
                part for part in query.split("&") if part and not part.startswith("since=")
            )
            for path in directory.glob("*.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if not isinstance(data, dict):
                    continue
                entry_url = str(data.get("url") or "")
                entry_base, _, entry_query = entry_url.partition("?")
                if entry_base != base:
                    continue
                entry_stable = sorted(
                    part for part in entry_query.split("&") if part and not part.startswith("since=")
                )
                if entry_stable == stable and data.get("v") == CACHE_VERSION:
                    return data
        except OSError:
            return None
        return None

    @staticmethod
    def _cache_key(method: str, url: str, body: Optional[bytes]) -> str:
        payload = f"{method}\n{url}\n" + (body.decode("utf-8", "replace") if body else "")
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _ensure_dir(path: Path) -> None:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _entry_path(self, directory: Path, key: str) -> Path:
        return directory / f"{key}.json"

    def _load_entry(self, directory: Optional[Path], key: str) -> Optional[dict[str, Any]]:
        if directory is None:
            return None
        path = self._entry_path(directory, key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("v") == CACHE_VERSION:
                return data
        except (OSError, json.JSONDecodeError):
            return None
        return None

    def _store_entry(
        self, directory: Optional[Path], key: str, entry: dict[str, Any], refresh_only: bool = False
    ) -> None:
        if directory is None or not entry:
            return
        if refresh_only:
            old = self._load_entry(directory, key) or {}
            old["stored_at"] = entry.get("stored_at", utcnow().isoformat())
            entry = old
        try:
            self._ensure_dir(directory)
            self._entry_path(directory, key).write_text(
                json.dumps(entry, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as exc:
            self._log(f"无法写入缓存 {directory}: {exc}")

    def _record(self, key: str, response: Response) -> None:
        if self.record_dir is None:
            return
        if response.status >= 500:
            return
        entry = self._response_to_entry(response)
        try:
            self._ensure_dir(self.record_dir)
            self._entry_path(self.record_dir, key).write_text(
                json.dumps(entry, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as exc:
            self._log(f"无法写入快照 {self.record_dir}: {exc}")

    def _is_fresh(self, entry: dict[str, Any]) -> bool:
        stored_at = parse_iso(entry.get("stored_at"))
        if stored_at is None:
            return False
        return (utcnow() - stored_at).total_seconds() < self.ttl_seconds

    def _response_to_entry(self, response: Response) -> dict[str, Any]:
        headers = {k.lower(): v for k, v in response.headers.items() if k.lower() in _PERSIST_HEADERS}
        return {
            "v": CACHE_VERSION,
            "url": response.url,
            "status": response.status,
            "headers": headers,
            "stored_at": utcnow().isoformat(),
            "body": response.body.decode("utf-8", errors="replace"),
        }

    @staticmethod
    def _entry_to_response(entry: dict[str, Any], from_cache: bool) -> Response:
        return Response(
            status=int(entry.get("status", 200)),
            url=entry.get("url", ""),
            body=str(entry.get("body", "")).encode("utf-8", errors="replace"),
            headers=dict(entry.get("headers", {})),
            from_cache=from_cache,
        )

    # ------------------------------------------------------------------

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[http] {message}", file=sys.stderr)


class _NotModified(Exception):
    pass


def default_cache_dir(cwd: Optional[Path] = None) -> Optional[Path]:
    """选择一个可写的缓存目录。

    优先环境变量 / XDG 缓存目录；如果当前沙箱不允许写 home（例如受限制的运行环境），
    退回到工作目录下的 ``.oss-health-cache``。
    """
    env = os.environ.get("OSS_HEALTH_CACHE_DIR")
    cwd = cwd or Path.cwd()
    candidates: list[Path] = []
    if env:
        candidates.append(Path(env).expanduser())
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        candidates.append(Path(xdg).expanduser() / "oss-health")
    else:
        candidates.append(Path.home() / ".cache" / "oss-health")
    candidates.append(cwd / ".oss-health-cache")
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return path
        except OSError:
            continue
    return None
