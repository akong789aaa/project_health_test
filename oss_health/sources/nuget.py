"""NuGet 数据源（registration5 API）：版本历史、TFM、依赖。"""

from __future__ import annotations

import functools
from typing import Any, Optional

from ..http_client import HttpClient, NotFound
from ..models import Dependency, PackageInfo
from ..util import parse_github_url, parse_iso, strip_blank
from ..versions import compare_versions, equal_versions, latest_version

_TFM_PREFIXES = (
    (".netframework", "net"),
    (".netstandard", "netstandard"),
    (".netcoreapp", "netcoreapp"),
    (".netportable", "portable"),
    (".netplatform", "netplatform"),
)


def normalize_tfm(raw: str) -> str:
    """把 NuGet 返回的 targetFramework 统一成短 TFM，例如 ``.NETStandard2.0`` -> ``netstandard2.0``。"""
    if not raw:
        return ""
    value = str(raw).strip()
    lower = value.lower()
    for prefix, short in _TFM_PREFIXES:
        if lower.startswith(prefix):
            version = value[len(prefix) :]
            version = version.strip().lower()
            if short == "net":
                version = version.replace(".", "")
            return f"{short}{version}"
    return lower


class NuGetSource:
    BASE = "https://api.nuget.org/v3"

    def __init__(self, client: HttpClient):
        self.client = client

    # ------------------------------------------------------------------

    def _catalog_entries(self, name: str) -> list[dict[str, Any]]:
        url = f"{self.BASE}/registration5-gz-semver2/{name.lower()}/index.json"
        try:
            index = self.client.get_json(url)
        except NotFound as exc:
            raise NotFound(f"NuGet 上找不到包 {name}", status=404, url=exc.url) from exc
        entries: list[dict[str, Any]] = []
        for page in index.get("items") or []:
            page_items = page.get("items")
            if not page_items and page.get("@id"):
                try:
                    page_data = self.client.get_json(str(page["@id"]))
                    page_items = page_data.get("items") or []
                except NotFound:
                    page_items = []
            for item in page_items or []:
                entry = item.get("catalogEntry")
                if entry:
                    entries.append(entry)
        return entries

    @staticmethod
    def _is_listed(entry: dict[str, Any]) -> bool:
        listed = entry.get("listed")
        if listed is False:
            return False
        published = parse_iso(entry.get("published"))
        if published is not None and published.year <= 1901:
            return False
        return True

    @staticmethod
    def _is_stable(version: str) -> bool:
        return "-" not in str(version)

    def resolve(self, name: str, version: Optional[str] = None) -> PackageInfo:
        entries = [e for e in self._catalog_entries(name) if e.get("version")]
        listed = [e for e in entries if self._is_listed(e)]
        if not listed:
            raise NotFound(f"NuGet 包 {name} 没有已发布的稳定版本")
        stable = [e for e in listed if self._is_stable(str(e["version"]))]
        pool = stable or listed
        latest_entry = max(
            pool,
            key=functools.cmp_to_key(
                lambda a, b: compare_versions(str(a["version"]), str(b["version"]), "nuget")
            ),
        )
        latest_version = str(latest_entry["version"])

        target_entry = latest_entry
        if version and not equal_versions(version, latest_version, "nuget"):
            match = None
            for entry in listed:
                if equal_versions(str(entry["version"]), version, "nuget"):
                    match = entry
                    break
            if match is None:
                raise NotFound(f"NuGet 上找不到 {name} {version}")
            target_entry = match

        target_version = str(target_entry["version"])
        release_dates = []
        for entry in listed:
            dt = parse_iso(entry.get("published"))
            if dt and dt.year > 1901:
                release_dates.append(dt)
        release_dates.sort()

        tfms: list[str] = []
        for group in target_entry.get("dependencyGroups") or []:
            tfm = normalize_tfm(str(group.get("targetFramework") or ""))
            if tfm and tfm not in tfms:
                tfms.append(tfm)

        dependencies: list[Dependency] = []
        seen_deps: set[str] = set()
        for group in target_entry.get("dependencyGroups") or []:
            for dep in group.get("dependencies") or []:
                dep_name = str(dep.get("id") or "")
                if not dep_name or dep_name.lower() in seen_deps:
                    continue
                seen_deps.add(dep_name.lower())
                dependencies.append(
                    Dependency(
                        name=dep_name,
                        spec=str(dep.get("range") or ""),
                        kind="runtime",
                        ecosystem="nuget",
                    )
                )

        project_url = str(target_entry.get("projectUrl") or "")
        # registration 元数据里常常没有 repository 字段，nuspec 里才有；只在拿到 GitHub 地址时补一次请求
        if not isinstance(target_entry.get("repository"), dict) or not (target_entry.get("repository") or {}).get("url"):
            nuspec_repo = self._nuspec_repository(name, target_version)
            if nuspec_repo:
                target_entry = dict(target_entry)
                target_entry["repository"] = {"type": "git", "url": nuspec_repo}
        # NuGet 的 repository 字段（{url, type}）比 projectUrl 更可靠：很多包的官网页不是仓库
        repository = target_entry.get("repository") or {}
        repo_candidates = [
            str(repository.get("url") or "") if isinstance(repository, dict) else str(repository or ""),
            project_url,
        ]
        slug = ""
        for candidate in repo_candidates:
            slug = parse_github_url(candidate)
            if slug:
                break
        repo_url = f"https://github.com/{slug}" if slug else ""

        license_text = str(
            target_entry.get("licenseExpression") or target_entry.get("licenseUrl") or ""
        )

        return PackageInfo(
            ecosystem="nuget",
            name=str(target_entry.get("id") or name),
            version=target_version,
            latest_version=latest_version,
            published_at=parse_iso(target_entry.get("published")),
            release_count=len(listed),
            summary=strip_blank(target_entry.get("description") or target_entry.get("summary")),
            homepage=project_url,
            repo_url=repo_url,
            license=license_text,
            target_frameworks=tfms,
            dependencies=dependencies,
            release_dates=release_dates,
            source=f"https://www.nuget.org/packages/{name}",
        )

    def _nuspec_repository(self, name: str, version: str) -> str:
        """从 .nuspec 里取 <repository url="..."/>（registration 常常没这个字段）。"""
        url = f"{self.BASE}-flatcontainer/{name.lower()}/{version.lower()}/{name.lower()}.nuspec"
        try:
            response = self.client.request("GET", url, headers={"Accept": "application/xml"})
        except Exception:
            return ""
        text = response.text
        if not text:
            return ""
        import re

        match = re.search(r'<repository[^>]*url="([^"]+)"', text)
        return match.group(1) if match else ""

    def latest_dependency_version(self, name: str) -> Optional[str]:
        """flat container 版本列表里取最新的稳定版本。"""
        url = f"{self.BASE}-flatcontainer/{name.lower()}/index.json"
        try:
            data = self.client.get_json(url)
        except Exception:
            return None
        versions = [str(v) for v in (data.get("versions") or []) if self._is_stable(str(v))]
        if not versions:
            versions = [str(v) for v in (data.get("versions") or [])]
        return latest_version(versions, "nuget")
