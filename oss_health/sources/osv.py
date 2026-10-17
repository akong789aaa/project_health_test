"""OSV.dev 数据源：漏洞查询、CVSS/严重度解析、去重、修复版本推断。

OSV API 无需鉴权：

* ``POST /v1/query``        单个包/版本查询（返回完整公告）
* ``POST /v1/querybatch``   批量查询（只返回 id + modified，需再取详情）
* ``GET  /v1/vulns/{id}``   公告详情
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..config import OSV_ECOSYSTEMS
from ..cvss import parse_cvss, severity_from_score, normalize_severity
from ..http_client import HttpClient, HttpError
from ..models import SEVERITY_ORDER, Vulnerability
from ..util import parse_iso
from ..versions import compare_versions, equal_versions, in_range


@dataclass
class VulnQueryResult:
    current: list[Vulnerability] = field(default_factory=list)   # 影响当前版本
    history: list[Vulnerability] = field(default_factory=list)   # 历史上所有公告（含已修复）
    total_history: int = 0
    fixed_count: int = 0


def _norm_name(name: str, ecosystem: str) -> str:
    n = (name or "").strip().lower()
    if ecosystem == "pypi":
        return n.replace("_", "-")
    return n


def _matching_affected(raw: dict[str, Any], ecosystem: str, name: str) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    for entry in raw.get("affected") or []:
        pkg = entry.get("package") or {}
        entry_eco = str(pkg.get("ecosystem") or "")
        if entry_eco and entry_eco.lower() != (OSV_ECOSYSTEMS.get(ecosystem, "") or "").lower():
            continue
        if _norm_name(str(pkg.get("name") or ""), ecosystem) != _norm_name(name, ecosystem):
            continue
        matched.append(entry)
    return matched


def _range_hits(entry: dict[str, Any], version: Optional[str], ecosystem: str) -> bool:
    """判断版本是否命中该 affected 条目（优先 versions 列表，其次事件区间）。"""
    if version is None:
        return False
    versions = entry.get("versions") or []
    if versions:
        return any(equal_versions(version, v, ecosystem) for v in versions)
    for rng in entry.get("ranges") or []:
        events = rng.get("events") or []
        introduced: Optional[str] = None
        for event in events:
            if "introduced" in event:
                introduced = str(event.get("introduced"))
            elif "fixed" in event:
                if in_range(
                    version,
                    introduced=None if introduced in (None, "0") else introduced,
                    fixed=str(event.get("fixed")),
                    ecosystem=ecosystem,
                ):
                    return True
                introduced = None
            elif "last_affected" in event:
                if in_range(
                    version,
                    introduced=None if introduced in (None, "0") else introduced,
                    last_affected=str(event.get("last_affected")),
                    ecosystem=ecosystem,
                ):
                    return True
                introduced = None
        if introduced is not None:  # 开区间，一直到未来版本都受影响
            if in_range(version, introduced=None if introduced in ("0", "") else introduced, ecosystem=ecosystem):
                return True
    return False


def _fixed_versions(entries: Iterable[dict[str, Any]], current_version: Optional[str], ecosystem: str) -> list[str]:
    fixed: list[str] = []
    for entry in entries:
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                ver = event.get("fixed")
                if not ver:
                    continue
                ver = str(ver)
                if current_version is None:
                    fixed.append(ver)
                    continue
                try:
                    if compare_versions(ver, current_version, ecosystem) > 0:
                        fixed.append(ver)
                except Exception:
                    continue
    seen: set[str] = set()
    out: list[str] = []
    for v in fixed:
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    out.sort(key=functools.cmp_to_key(lambda a, b: compare_versions(a, b, ecosystem)))
    return out


def _severity_from_raw(raw: dict[str, Any]) -> tuple[Optional[float], str, str]:
    """返回 (cvss 分数, 向量, 严重度标签)。"""
    score: Optional[float] = None
    vector = ""
    for item in raw.get("severity") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "")
        value = str(item.get("score") or "")
        if kind.startswith("CVSS_V3"):
            parsed = parse_cvss(value)
            if parsed:
                score, _ = parsed
                vector = value
                break
        elif kind.startswith("CVSS_V4") and not vector:
            vector = value
    label = ""
    db_specific = raw.get("database_specific") or {}
    if isinstance(db_specific, dict):
        label = normalize_severity(str(db_specific.get("severity") or ""))
    if label in ("", "UNKNOWN"):
        label = severity_from_score(score)
    if score is None and label not in ("UNKNOWN", "NONE"):
        # 没有 CVSS 向量时给一个保守的中间值，仅用于展示排序
        score = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5}.get(label)
    return score, vector, label


def parse_vulnerability(
    raw: dict[str, Any],
    ecosystem: str,
    *,
    current_version: Optional[str] = None,
    force_affects: Optional[bool] = None,
    package_name: Optional[str] = None,
) -> Optional[Vulnerability]:
    if not isinstance(raw, dict) or raw.get("withdrawn"):
        return None
    vuln_id = str(raw.get("id") or "").strip()
    if not vuln_id:
        return None
    aliases = [str(a) for a in (raw.get("aliases") or []) if a]
    score, vector, severity = _severity_from_raw(raw)
    matched: list[dict[str, Any]] = []
    for entry in raw.get("affected") or []:
        pkg = entry.get("package") or {}
        if str(pkg.get("ecosystem") or "").lower() != (OSV_ECOSYSTEMS.get(ecosystem, "") or "").lower():
            continue
        if package_name and _norm_name(str(pkg.get("name") or ""), ecosystem) != _norm_name(package_name, ecosystem):
            continue
        matched.append(entry)
    if not matched:
        return None
    affects = force_affects
    if affects is None and current_version is not None:
        affects = any(_range_hits(entry, current_version, ecosystem) for entry in matched)
    if affects is None:
        affects = True
    fixed = _fixed_versions(matched, current_version, ecosystem)
    references = raw.get("references") or []
    url = ""
    for ref in references:
        ref_url = str(ref.get("url") or "")
        if "github.com/advisories" in ref_url:
            url = ref_url
            break
    if not url:
        for ref in references:
            ref_url = str(ref.get("url") or "")
            if ref_url.startswith("http"):
                url = ref_url
                break
    if not url:
        url = f"https://osv.dev/vulnerability/{vuln_id}"
    return Vulnerability(
        id=vuln_id,
        aliases=aliases,
        summary=str(raw.get("summary") or ""),
        published=parse_iso(raw.get("published")),
        modified=parse_iso(raw.get("modified")),
        cvss_score=score,
        cvss_vector=vector,
        severity=severity,
        affects_current=bool(affects),
        fixed_versions=fixed,
        url=url,
        ecosystem=ecosystem,
    )


def _identifiers(vuln: Vulnerability) -> set[str]:
    ids = {vuln.id.upper()}
    for alias in vuln.aliases:
        ids.add(str(alias).upper())
    return ids


def dedupe_advisories(vulns: Iterable[Vulnerability]) -> list[Vulnerability]:
    """合并 GHSA/CVE/PYSEC 等指向同一漏洞的多条记录。"""
    items = [v for v in vulns if v]
    n = len(items)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    owners: dict[str, int] = {}
    for idx, vuln in enumerate(items):
        for ident in _identifiers(vuln):
            if ident in owners:
                union(idx, owners[ident])
            else:
                owners[ident] = idx

    groups: dict[int, list[Vulnerability]] = {}
    for idx, vuln in enumerate(items):
        groups.setdefault(find(idx), []).append(vuln)

    merged: list[Vulnerability] = []
    for group in groups.values():
        primary = group[0]
        for candidate in group[1:]:
            if candidate.severity_rank > primary.severity_rank or (
                candidate.severity_rank == primary.severity_rank
                and (candidate.cvss_score or 0) > (primary.cvss_score or 0)
            ):
                primary = candidate
        aliases: list[str] = []
        fixed: list[str] = []
        affects = False
        for vuln in group:
            for alias in vuln.aliases:
                if alias not in aliases:
                    aliases.append(alias)
            for ver in vuln.fixed_versions:
                if ver not in fixed:
                    fixed.append(ver)
            affects = affects or vuln.affects_current
        aliases = [a for a in aliases if a != primary.id]
        merged_vuln = Vulnerability(
            id=primary.id,
            aliases=aliases,
            summary=primary.summary,
            published=primary.published,
            modified=primary.modified,
            cvss_score=primary.cvss_score,
            cvss_vector=primary.cvss_vector,
            severity=primary.severity,
            affects_current=affects,
            fixed_versions=fixed,
            url=primary.url,
            ecosystem=primary.ecosystem,
        )
        merged.append(merged_vuln)
    merged.sort(key=lambda v: (-v.severity_rank, -(v.cvss_score or 0), v.id))
    return merged


class OSVSource:
    BASE = "https://api.osv.dev/v1"

    def __init__(self, client: HttpClient):
        self.client = client
        self._detail_cache: dict[str, Optional[dict[str, Any]]] = {}

    @staticmethod
    def ecosystem_name(ecosystem: str) -> str:
        return OSV_ECOSYSTEMS.get(ecosystem, ecosystem)

    def package_vulns(self, ecosystem: str, name: str, version: str) -> VulnQueryResult:
        osv_eco = self.ecosystem_name(ecosystem)
        package = {"name": name, "ecosystem": osv_eco}
        current_raw: dict[str, Any] = {}
        history_raw: dict[str, Any] = {}
        try:
            current_raw = self.client.post_json(
                f"{self.BASE}/query", {"package": package, "version": version}
            )
        except HttpError:
            current_raw = {}
        try:
            history_raw = self.client.post_json(f"{self.BASE}/query", {"package": package})
        except HttpError:
            history_raw = {}
        current = dedupe_advisories(
            parse_vulnerability(
                raw, ecosystem, current_version=version, force_affects=True, package_name=name
            )
            for raw in current_raw.get("vulns") or []
        )
        history = dedupe_advisories(
            parse_vulnerability(raw, ecosystem, current_version=version, package_name=name)
            for raw in history_raw.get("vulns") or []
        )
        current_ids = [_identifiers(v) for v in current]
        fixed_count = 0
        for vuln in history:
            if not any(_identifiers(vuln) & ids for ids in current_ids):
                fixed_count += 1
        return VulnQueryResult(
            current=current,
            history=history,
            total_history=len(history),
            fixed_count=fixed_count,
        )

    def batch_query(self, queries: list[dict[str, Any]]) -> list[list[str]]:
        """OSV querybatch：返回每个 query 命中的漏洞 id 列表。"""
        if not queries:
            return []
        data = self.client.post_json(f"{self.BASE}/querybatch", {"queries": queries})
        out: list[list[str]] = []
        for result in data.get("results") or []:
            ids = [str(v.get("id")) for v in (result or {}).get("vulns") or [] if v.get("id")]
            out.append(ids)
        while len(out) < len(queries):
            out.append([])
        return out

    def vuln_detail(self, vuln_id: str) -> Optional[dict[str, Any]]:
        if vuln_id in self._detail_cache:
            return self._detail_cache[vuln_id]
        try:
            data = self.client.get_json(f"{self.BASE}/vulns/{vuln_id}")
        except HttpError:
            data = None
        self._detail_cache[vuln_id] = data
        return data

    def vulnerabilities_for_ids(
        self, ids: Iterable[str], ecosystem: str, version: str, package_name: Optional[str] = None
    ) -> list[Vulnerability]:
        out: list[Vulnerability] = []
        for vuln_id in ids:
            raw = self.vuln_detail(vuln_id)
            if not raw:
                continue
            vuln = parse_vulnerability(
                raw,
                ecosystem,
                current_version=version,
                force_affects=True,
                package_name=package_name,
            )
            if vuln:
                out.append(vuln)
        return dedupe_advisories(out)
