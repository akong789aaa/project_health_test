"""直接依赖安全分析：解析依赖版本 -> OSV querybatch -> 汇总未修复 CVE。

说明（报告里也会写明）：在没有完整依赖解析器的情况下，这里对**未锁定版本**的依赖
取其当前最新版本进行查询，代表「今天全新安装会拿到的依赖」；对 ``==`` / 精确版本的
依赖则直接查询锁定版本。因此它是启发式检查，不是完整的 SBOM 分析。
"""

from __future__ import annotations

import re
from typing import Optional

from ..config import WEIGHTS
from ..cvss import score_to_grade_zh
from ..http_client import HttpError
from ..models import Dependency, DependencyRisk, Dimension, PackageInfo, Vulnerability
from ..sources.npm import NpmSource
from ..sources.nuget import NuGetSource
from ..sources.osv import OSVSource
from ..sources.pypi import PyPISource

MAX_DEP_DETAIL_IDS = 120
_PY_PIN = re.compile(r"^\s*==\s*([A-Za-z0-9.+!_-]+)\s*$")
_NPM_PIN = re.compile(r"^\s*=?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\s*$")
_NUGET_PIN = re.compile(r"^\s*\[\s*([^,\]\s]+)\s*\]\s*$")


class DependencyResolver:
    """把依赖的版本约束解析成一个可用于查询 OSV 的具体版本。"""

    def __init__(
        self,
        ecosystem: str,
        *,
        pypi: Optional[PyPISource] = None,
        npm: Optional[NpmSource] = None,
        nuget: Optional[NuGetSource] = None,
    ):
        self.ecosystem = ecosystem
        self.pypi = pypi
        self.npm = npm
        self.nuget = nuget

    def pinned_version(self, dep: Dependency) -> Optional[str]:
        spec = dep.spec or ""
        if self.ecosystem == "pypi":
            m = _PY_PIN.match(spec)
        elif self.ecosystem == "npm":
            m = _NPM_PIN.match(spec)
        elif self.ecosystem == "nuget":
            m = _NUGET_PIN.match(spec)
        else:
            m = None
        return m.group(1) if m else None

    def latest(self, name: str) -> Optional[str]:
        try:
            if self.ecosystem == "pypi" and self.pypi is not None:
                return self.pypi.latest_dependency_version(name)
            if self.ecosystem == "npm" and self.npm is not None:
                return self.npm.latest_dependency_version(name)
            if self.ecosystem == "nuget" and self.nuget is not None:
                return self.nuget.latest_dependency_version(name)
        except HttpError:
            return None
        return None

    def resolve(self, dep: Dependency) -> tuple[Optional[str], str]:
        pinned = self.pinned_version(dep)
        if pinned:
            return pinned, "锁定版本"
        version = self.latest(dep.name)
        if version:
            return version, "按当前最新版本检查"
        return None, "无法解析版本"


def _norm_dep_name(name: str, ecosystem: str) -> str:
    name = (name or "").strip()
    if ecosystem == "pypi":
        return name.replace("_", "-")
    return name


def analyze(
    package: Optional[PackageInfo],
    osv: OSVSource,
    resolver: DependencyResolver,
    now,
    *,
    limit: int = 10,
) -> tuple[list[DependencyRisk], Dimension]:
    dim = Dimension(
        key="dependencies",
        title="依赖安全",
        weight=WEIGHTS["dependencies"],
        score=100,
        metrics={},
        evidence=[],
    )
    if package is None:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("没有包元数据，无法分析依赖")
        return [], dim

    runtime_deps = [d for d in package.dependencies if d.kind == "runtime"]
    dim.metrics["deps_total"] = len(runtime_deps)
    if not runtime_deps:
        dim.available = True
        dim.score = 100
        dim.evidence.append("没有声明运行时依赖，不存在依赖链漏洞风险")
        dim.status = "good"
        return [], dim

    selected = runtime_deps[:limit]
    resolved: list[tuple[Dependency, str, str]] = []
    failed: list[str] = []
    for dep in selected:
        version, note = resolver.resolve(dep)
        if version:
            resolved.append((dep, version, note))
        else:
            failed.append(dep.name)
    dim.metrics["deps_checked"] = len(resolved)
    dim.metrics["deps_failed"] = len(failed)
    if not resolved:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append(f"{len(selected)} 个直接依赖的版本都无法解析，无法查询漏洞")
        return [], dim

    dim.evidence.append(
        f"检查 {len(resolved)}/{len(runtime_deps)} 个直接运行时依赖"
        + (f"（仅检查前 {limit} 个，可用 --dep-check 调整）" if len(runtime_deps) > limit else "")
    )
    if failed:
        dim.notes.append(f"{len(failed)} 个依赖无法解析版本：{'、'.join(failed[:5])}")

    eco = package.ecosystem
    osv_eco = OSVSource.ecosystem_name(eco)
    queries = []
    query_meta: list[tuple[Dependency, str, str]] = []
    for dep, version, note in resolved:
        queries.append(
            {
                "package": {"name": _norm_dep_name(dep.name, eco), "ecosystem": osv_eco},
                "version": version,
            }
        )
        query_meta.append((dep, version, note))

    risks: list[DependencyRisk] = []
    try:
        batch_results = osv.batch_query(queries)
    except HttpError as exc:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append(f"OSV 批量查询失败：{exc}")
        return [], dim

    all_ids: set[str] = set()
    for ids in batch_results:
        all_ids.update(ids)
    detail_ids = list(all_ids)[:MAX_DEP_DETAIL_IDS]
    if len(all_ids) > MAX_DEP_DETAIL_IDS:
        dim.notes.append(f"依赖漏洞公告较多（{len(all_ids)} 条），只获取前 {MAX_DEP_DETAIL_IDS} 条详情")

    for (dep, version, note), ids in zip(query_meta, batch_results):
        risk = DependencyRisk(
            name=dep.name,
            ecosystem=eco,
            spec=dep.spec,
            checked_version=version,
        )
        if ids:
            usable = [i for i in ids if i in set(detail_ids)]
            risk.vulns = osv.vulnerabilities_for_ids(
                usable, eco, version, package_name=_norm_dep_name(dep.name, eco)
            )
            # 只保留影响该解析版本的漏洞
            risk.vulns = [v for v in risk.vulns if v.affects_current]
        risks.append(risk)

    risky = [r for r in risks if r.vulns]
    crit_high = sum(
        1
        for risk in risky
        for v in risk.vulns
        if v.severity in ("CRITICAL", "HIGH")
    )
    medium = sum(1 for risk in risky for v in risk.vulns if v.severity == "MEDIUM")
    dim.metrics.update(
        {
            "deps_with_vulns": len(risky),
            "dep_critical_high": crit_high,
            "dep_medium": medium,
        }
    )

    if not risky:
        dim.evidence.append("直接依赖中未发现影响当前解析版本的已知漏洞")
    else:
        dim.evidence.append(
            f"{len(risky)} 个直接依赖存在已知漏洞：严重/高危 {crit_high} 条，中危 {medium} 条"
        )
        for risk in sorted(
            risky,
            key=lambda r: (-sum(1 for v in r.vulns if v.severity in ("CRITICAL", "HIGH")), r.name),
        )[:6]:
            worst = sorted(
                risk.vulns,
                key=lambda v: (-v.severity_rank, -(v.cvss_score or 0)),
            )[0]
            fix = worst.best_fix_version
            dim.evidence.append(
                f"{risk.name}@{risk.checked_version}：{worst.cve or worst.id}"
                f"（{score_to_grade_zh(worst.severity)}）"
                + (f" → 升级到 {fix}" if fix else "（暂无修复版本）")
                + (f"；共 {len(risk.vulns)} 条" if len(risk.vulns) > 1 else "")
            )
        if crit_high:
            dim.add(min(36, 10 * crit_high), f"直接依赖中 {crit_high} 条严重/高危漏洞")
        if medium:
            dim.add(min(15, 3 * medium), f"直接依赖中 {medium} 条中危漏洞")
        if sum(1 for r in risky if any(v.severity in ("CRITICAL", "HIGH") for v in r.vulns)) >= 3:
            dim.add(10, "多个直接依赖存在高危漏洞，依赖链维护状况较差")

    dim.evidence.append("提示：未锁定版本的依赖按「当前最新版本」评估；完整 SBOM 分析请结合 pip-audit / npm audit")
    dim.clamp()
    dim.status = dim.score_status()
    return risks, dim
