"""通用小工具：时间、数值、URL 解析。"""

from __future__ import annotations

import math
import re
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

UTC = timezone.utc

_ISO_FRACTION = re.compile(r"(\.\d{6})\d+")


def utcnow() -> datetime:
    return datetime.now(UTC)


def parse_iso(value: Any) -> Optional[datetime]:
    """解析 GitHub/OSV 常见的 ISO8601 时间（兼容 Z、超长小数、无时区）。"""
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        s = _ISO_FRACTION.sub(r"\1", s)
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            try:
                dt = datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                try:
                    dt = datetime.fromisoformat(s[:10])
                except ValueError:
                    return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def age_days(when: Optional[datetime], now: Optional[datetime] = None) -> Optional[int]:
    if not when:
        return None
    now = now or utcnow()
    return max(0, int((now - when).total_seconds() // 86400))


def hours_between(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    if not start or not end:
        return None
    return max(0.0, (end - start).total_seconds() / 3600.0)


def days_between(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    h = hours_between(start, end)
    return None if h is None else h / 24.0


def fmt_date(when: Optional[datetime]) -> str:
    return when.strftime("%Y-%m-%d") if when else "—"


def fmt_datetime(when: Optional[datetime]) -> str:
    return when.strftime("%Y-%m-%d %H:%M UTC") if when else "—"


def fmt_ago(when: Optional[datetime], now: Optional[datetime] = None) -> str:
    d = age_days(when, now)
    if d is None:
        return "未知"
    if d == 0:
        return "今天"
    if d < 30:
        return f"{d} 天前"
    if d < 365:
        return f"{d // 30} 个月前"
    years = d / 365.0
    return f"{years:.1f} 年前"


def fmt_days(days: Optional[float]) -> str:
    if days is None:
        return "—"
    if days < 1:
        return "< 1 天"
    return f"{days:.1f} 天"


def fmt_hours(hours: Optional[float]) -> str:
    if hours is None:
        return "—"
    if hours < 1:
        return "< 1 小时"
    if hours < 48:
        return f"{hours:.1f} 小时"
    return f"{hours / 24:.1f} 天"


def median(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return None
    return float(statistics.median(vals))


def mean(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = [float(v) for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def safe_div(a: float, b: float) -> Optional[float]:
    if not b:
        return None
    return a / b


def pct(a: float, b: float) -> Optional[float]:
    d = safe_div(a, b)
    return None if d is None else d * 100.0


def fmt_pct(value: Optional[float], digits: int = 0) -> str:
    return "—" if value is None else f"{value:.{digits}f}%"


def fmt_human_int(n: Optional[float]) -> str:
    if n is None:
        return "—"
    n = float(n)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 10_000:
        return f"{n / 1000:.1f}k"
    return f"{int(n):,}" if n == int(n) else f"{n:.1f}"


_GITHUB_URL_RE = re.compile(
    r"^(?:git\+)?(?:https?|ssh|git)://(?:www\.)?github\.com[/:](?P<owner>[^/\s]+)/(?P<repo>[^/\s#?]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
_GITHUB_SHORT_RE = re.compile(r"^github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s#?]+?)(?:\.git)?/?$", re.IGNORECASE)
_SLUG_RE = re.compile(r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)$")


def parse_github_url(url: Optional[str]) -> Optional[str]:
    """从各种 GitHub 仓库地址中提取 ``owner/repo``；非 GitHub 地址返回 None。"""
    if not url:
        return None
    text = str(url).strip()
    text = text.split("#", 1)[0].split("?", 1)[0]
    for regex in (_GITHUB_URL_RE, _GITHUB_SHORT_RE):
        m = regex.match(text)
        if m:
            repo = m.group("repo").rstrip("/")
            if repo.endswith(".git"):
                repo = repo[:-4]
            return f"{m.group('owner')}/{repo}"
    return None


def parse_repo_slug(text: Optional[str]) -> Optional[str]:
    """把 ``owner/repo``、GitHub URL 统一成 ``owner/repo``。"""
    if not text:
        return None
    slug = parse_github_url(text)
    if slug:
        return slug
    m = _SLUG_RE.match(str(text).strip())
    if m:
        return f"{m.group('owner')}/{m.group('repo')}"
    return None


def parse_owner_repo(slug: str) -> tuple[str, str]:
    owner, _, repo = slug.partition("/")
    return owner, repo


def slugify(text: str, max_len: int = 60) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(text)).strip("-").lower()
    return (s or "report")[:max_len]


def dedupe(items: Iterable[Any]) -> list[Any]:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def round_half_up(value: float) -> float:
    return math.floor(value + 0.5)


def strip_blank(text: Optional[str]) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", str(text)).strip()


def isoformat_z(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def window_start(now: datetime, window_days: int) -> datetime:
    return now - timedelta(days=window_days)
