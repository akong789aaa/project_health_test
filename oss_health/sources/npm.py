"""npm registry 数据源。"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import quote

from ..http_client import HttpClient, NotFound
from ..models import Dependency, PackageInfo
from ..util import parse_github_url, parse_iso, strip_blank
from ..versions import equal_versions

_NODE_MAJOR = re.compile(r"(\d+)")


def _repo_url(value: Any) -> Optional[str]:
    if not value:
        return None
    if isinstance(value, dict):
        value = value.get("url") or ""
    if isinstance(value, str):
        slug = parse_github_url(value)
        if slug:
            return f"https://github.com/{slug}"
    return None


class NpmSource:
    BASE = "https://registry.npmjs.org"

    def __init__(self, client: HttpClient):
        self.client = client

    def _packument(self, name: str) -> dict[str, Any]:
        return self.client.get_json(f"{self.BASE}/{quote(name, safe='@')}")

    def resolve(self, name: str, version: Optional[str] = None) -> PackageInfo:
        packument = self._packument(name)
        versions: dict[str, Any] = packument.get("versions") or {}
        dist_tags: dict[str, str] = packument.get("dist-tags") or {}
        latest_version = str(dist_tags.get("latest") or "")
        if not latest_version:
            latest_version = max(versions.keys(), key=lambda v: v) if versions else ""
        if not versions:
            raise NotFound(f"npm 包 {name} 没有任何已发布版本", status=404)

        target_version = latest_version
        if version and not equal_versions(version, latest_version, "npm"):
            match = None
            for key in versions:
                if equal_versions(key, version, "npm"):
                    match = key
                    break
            if match is None:
                raise NotFound(f"npm 上找不到 {name}@{version}")
            target_version = match

        data = versions.get(target_version) or {}
        times: dict[str, str] = packument.get("time") or {}
        release_dates = []
        for ver, ts in times.items():
            if ver in ("created", "modified", "unpublished"):
                continue
            dt = parse_iso(ts)
            if dt:
                release_dates.append(dt)
        release_dates.sort()

        engines = data.get("engines") or {}
        node_engines = str(engines.get("node") or "") if isinstance(engines, dict) else ""
        node_versions: list[int] = []
        for token in _NODE_MAJOR.findall(node_engines):
            major = int(token)
            if major not in node_versions:
                node_versions.append(major)
        node_versions.sort()

        deprecated_msg = str(data.get("deprecated") or "")
        dependencies: list[Dependency] = []
        for dep_name, spec in (data.get("dependencies") or {}).items():
            dependencies.append(Dependency(name=dep_name, spec=str(spec), kind="runtime", ecosystem="npm"))
        for dep_name, spec in (data.get("optionalDependencies") or {}).items():
            dependencies.append(Dependency(name=dep_name, spec=str(spec), kind="optional", ecosystem="npm"))
        for dep_name, spec in (data.get("peerDependencies") or {}).items():
            dependencies.append(Dependency(name=dep_name, spec=str(spec), kind="peer", ecosystem="npm"))

        license_text = data.get("license")
        if isinstance(license_text, dict):
            license_text = license_text.get("type")
        repo = _repo_url(data.get("repository")) or _repo_url(packument.get("repository"))

        return PackageInfo(
            ecosystem="npm",
            name=str(packument.get("name") or name),
            version=target_version,
            latest_version=latest_version,
            published_at=parse_iso(times.get(target_version)),
            release_count=len([v for v in times if v not in ("created", "modified", "unpublished")]),
            summary=strip_blank(data.get("description") or packument.get("description")),
            homepage=str(data.get("homepage") or packument.get("homepage") or ""),
            repo_url=repo or "",
            license=str(license_text or ""),
            deprecated=bool(deprecated_msg),
            deprecation_message=deprecated_msg,
            node_engines=node_engines,
            node_versions=node_versions,
            dependencies=dependencies,
            release_dates=release_dates,
            source=f"{self.BASE}/{name}",
        )

    def latest_dependency_version(self, name: str) -> Optional[str]:
        try:
            data = self.client.get_json(f"{self.BASE}/{quote(name, safe='@')}/latest")
        except NotFound:
            return None
        return str(data.get("version") or "") or None
