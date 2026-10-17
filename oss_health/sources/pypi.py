"""PyPI 数据源：包元数据、发布节奏、声明的 Python 版本、直接依赖。"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import quote

from ..http_client import HttpClient, HttpError, NotFound
from ..models import Dependency, PackageInfo
from ..util import parse_iso, parse_github_url, strip_blank
from ..versions import equal_versions

_PY_CLASSIFIER = re.compile(r"Programming Language :: Python :: (\d+)\.(\d+)\s*$")
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?\s*(.*)$")
_EXTRA_MARKER = re.compile(r'^\s*extra\s*==\s*["\'][^"\']+["\']\s*$')


def parse_requirement(spec: str) -> Optional[Dependency]:
    """解析 PyPI ``requires_dist`` 中的一条 PEP 508 依赖（轻量实现）。"""
    if not spec or not spec.strip():
        return None
    m = _REQ_RE.match(spec)
    if not m:
        return None
    name = m.group(1)
    rest = (m.group(3) or "").strip()
    marker = ""
    constraint = rest
    if ";" in rest:
        constraint, marker = rest.split(";", 1)
        constraint, marker = constraint.strip(), marker.strip()
    constraint = constraint.strip().strip("()").strip()
    kind = "extra" if _EXTRA_MARKER.match(marker or "") else "runtime"
    return Dependency(name=name, spec=constraint, kind=kind, ecosystem="pypi")


def _release_upload_date(files: list[dict[str, Any]]) -> Optional[Any]:
    dates = []
    for f in files or []:
        dt = parse_iso(f.get("upload_time_iso_8601") or f.get("upload_time"))
        if dt:
            dates.append(dt)
    return max(dates) if dates else None


class PyPISource:
    BASE = "https://pypi.org/pypi"

    def __init__(self, client: HttpClient):
        self.client = client

    def _fetch(self, name: str, version: Optional[str] = None) -> dict[str, Any]:
        path = f"{self.BASE}/{quote(name)}/json"
        if version:
            path = f"{self.BASE}/{quote(name)}/{quote(version)}/json"
        return self.client.get_json(path)

    def resolve(self, name: str, version: Optional[str] = None) -> PackageInfo:
        latest_raw = self._fetch(name)
        latest_info = latest_raw.get("info") or {}
        latest_version = str(latest_info.get("version") or "")
        releases: dict[str, list[dict[str, Any]]] = latest_raw.get("releases") or {}

        target_info = latest_info
        target_version = latest_version
        raw_for_urls = latest_raw
        if version and not equal_versions(version, latest_version, "pypi"):
            try:
                version_raw = self._fetch(name, version)
            except NotFound as exc:
                raise NotFound(
                    f"PyPI 上找不到 {name}=={version}（可能已被 yank 或版本号有误）",
                    status=404,
                    url=exc.url,
                ) from exc
            target_info = version_raw.get("info") or {}
            target_version = str(target_info.get("version") or version)
            raw_for_urls = version_raw

        display_name = str(target_info.get("name") or latest_info.get("name") or name)

        # 发布历史 / 节奏
        release_dates = []
        release_count = 0
        for ver, files in releases.items():
            if not files:
                continue
            release_count += 1
            dt = _release_upload_date(files)
            if dt:
                release_dates.append(dt)
        release_dates.sort()

        published_at = _release_upload_date(releases.get(target_version) or [])
        if published_at is None:
            published_at = _release_upload_date(raw_for_urls.get("urls") or [])

        # 仓库地址
        repo_url = self._extract_repo_url(target_info) or self._extract_repo_url(latest_info)

        # Python 版本声明
        python_versions = self._python_versions(target_info.get("classifiers") or [])

        # 依赖
        deps: list[Dependency] = []
        for spec in target_info.get("requires_dist") or []:
            dep = parse_requirement(str(spec))
            if dep:
                deps.append(dep)

        license_text = str(
            target_info.get("license_expression")
            or target_info.get("license")
            or ""
        ).strip()
        if len(license_text) > 120:
            license_text = license_text.splitlines()[0][:120]

        yanked = bool(target_info.get("yanked"))
        info = PackageInfo(
            ecosystem="pypi",
            name=display_name,
            version=target_version,
            latest_version=latest_version,
            published_at=published_at,
            release_count=release_count,
            summary=strip_blank(target_info.get("summary")),
            homepage=self._homepage(target_info),
            repo_url=repo_url or "",
            license=license_text,
            deprecated=False,
            deprecation_message="",
            requires_python=str(target_info.get("requires_python") or ""),
            python_versions=python_versions,
            dependencies=deps,
            release_dates=release_dates,
            yanked=yanked,
            source=f"{self.BASE}/{display_name}/json",
        )
        return info

    def latest_dependency_version(self, name: str) -> Optional[str]:
        try:
            data = self.client.get_json(f"{self.BASE}/{quote(name)}/json")
        except NotFound:
            return None
        return str((data.get("info") or {}).get("version") or "") or None

    # ------------------------------------------------------------------

    @staticmethod
    def _python_versions(classifiers: list[str]) -> list[str]:
        found: list[str] = []
        for clf in classifiers:
            m = _PY_CLASSIFIER.search(str(clf))
            if m:
                key = f"{m.group(1)}.{m.group(2)}"
                if key not in found:
                    found.append(key)
        found.sort(key=lambda x: tuple(int(p) for p in x.split(".") if p.isdigit()))
        return found

    @staticmethod
    def _homepage(info: dict[str, Any]) -> str:
        urls = info.get("project_urls") or {}
        for key in ("Homepage", "Home", "Website", "Documentation", "Docs"):
            if isinstance(urls, dict) and urls.get(key):
                return str(urls[key])
        return str(info.get("home_page") or "")

    @staticmethod
    def _extract_repo_url(info: dict[str, Any]) -> Optional[str]:
        project_urls = info.get("project_urls") or {}
        priority_keys = (
            "Source",
            "Source Code",
            "Repository",
            "Code",
            "GitHub",
            "Homepage",
            "Home",
            "Changelog",
        )
        candidates: list[str] = []
        if isinstance(project_urls, dict):
            for key in priority_keys:
                if project_urls.get(key):
                    candidates.append(str(project_urls[key]))
            candidates.extend(str(v) for v in project_urls.values() if v)
        if info.get("home_page"):
            candidates.append(str(info["home_page"]))
        for url in candidates:
            slug = parse_github_url(url)
            if slug:
                return f"https://github.com/{slug}"
        return None
