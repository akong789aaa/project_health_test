"""自身漏洞分析：OSV.dev 中影响当前版本、且尚未修复的漏洞。"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from ..config import WEIGHTS
from ..cvss import score_to_grade_zh
from ..http_client import HttpError
from ..models import Dimension, PackageInfo, SecuritySignals, Vulnerability
from ..sources.osv import OSVSource
from ..util import fmt_date


def _vuln_label(v: Vulnerability) -> str:
    cve = v.cve
    name = cve or v.id
    score = f"CVSS {v.cvss_score:.1f}" if v.cvss_score is not None else v.severity
    return f"{name}（{score} {score_to_grade_zh(v.severity)}）"


def analyze(
    package: Optional[PackageInfo],
    osv: OSVSource,
    now: datetime,
) -> tuple[Optional[SecuritySignals], Dimension]:
    dim = Dimension(
        key="security",
        title="自身漏洞",
        weight=WEIGHTS["security"],
        score=100,
        metrics={},
        evidence=[],
    )
    if package is None:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("没有包元数据，无法查询漏洞数据库")
        return None, dim

    try:
        result = osv.package_vulns(package.ecosystem, package.name, package.version)
    except HttpError as exc:
        signals = SecuritySignals(
            ecosystem=package.ecosystem,
            package=package.name,
            version=package.version,
            db_available=False,
            warnings=[f"OSV.dev 查询失败：{exc}"],
        )
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("漏洞数据库查询失败，无法评估安全性")
        return signals, dim

    signals = SecuritySignals(
        ecosystem=package.ecosystem,
        package=package.name,
        version=package.version,
        vulns_current=result.current,
        history_count=result.total_history,
        fixed_count=result.fixed_count,
    )

    current = result.current
    metrics = dim.metrics
    metrics.update(
        {
            "unfixed_count": len(current),
            "critical": signals.count("CRITICAL"),
            "high": signals.count("HIGH"),
            "medium": signals.count("MEDIUM"),
            "low": signals.count("LOW"),
            "history_count": result.total_history,
            "fixed_count": result.fixed_count,
            "max_severity": signals.max_severity,
        }
    )

    if not current:
        dim.evidence.append(
            f"OSV.dev 未发现影响 {package.name} {package.version} 的未修复漏洞"
            + (f"（历史公告 {result.total_history} 条，均已在当前版本前修复）" if result.total_history else "")
        )
    else:
        dim.evidence.append(
            f"当前版本 {package.version} 存在 {len(current)} 条未修复漏洞："
            f"严重 {signals.count('CRITICAL')} / 高危 {signals.count('HIGH')} / "
            f"中危 {signals.count('MEDIUM')} / 低危 {signals.count('LOW')}"
        )
        if result.fixed_count:
            dim.evidence.append(
                f"另有 {result.fixed_count} 条历史公告在后续版本已修复（当前版本太旧或需要升级）"
            )
        recent = [v for v in current if v.published and (now - v.published).days <= 730]
        if recent:
            dim.evidence.append(f"其中 {len(recent)} 条是近 2 年公开的漏洞")
        for vuln in current[:5]:
            fix = vuln.best_fix_version
            dim.evidence.append(
                f"{_vuln_label(vuln)}：{vuln.summary[:60]}"
                + (f" → 升级到 {fix} 可修复" if fix else "（暂无修复版本）")
            )
        if len(current) > 5:
            dim.evidence.append(f"……另有 {len(current) - 5} 条见漏洞明细")

        # ---- 扣分：按严重度加权 ----
        crit = signals.count("CRITICAL")
        high = signals.count("HIGH")
        med = signals.count("MEDIUM")
        low = signals.count("LOW")
        if crit:
            dim.add(min(75, 55 * crit), f"{crit} 条未修复的严重漏洞（CVSS ≥ 9）")
        if high:
            dim.add(min(60, 28 * high), f"{high} 条未修复的高危漏洞（CVSS 7.0–8.9）")
        if med:
            dim.add(min(28, 8 * med), f"{med} 条未修复的中危漏洞")
        if low:
            dim.add(min(10, 2 * low), f"{low} 条未修复的低危漏洞")
        if len(current) >= 3:
            dim.add(8, f"当前版本累计存在 {len(current)} 条未修复漏洞")

    if package.yanked:
        dim.add(25, "当前版本已被 PyPI yank（不建议继续使用该版本）")
        dim.evidence.append("当前版本已被 yank")
    if package.deprecated:
        dim.add(20, "包已被标记废弃，漏洞不会再被修复")

    if not current and not result.total_history:
        dim.evidence.append("该包在 OSV 的漏洞库中没有历史记录")

    dim.clamp()
    dim.status = dim.score_status()
    return signals, dim


def summarize_for_report(signals: Optional[SecuritySignals]) -> list[str]:
    """给 Markdown/HTML 报告用的漏洞明细行。"""
    if not signals or not signals.vulns_current:
        return []
    lines: list[str] = []
    for vuln in signals.vulns_current[:20]:
        aliases = ", ".join(vuln.aliases[:4])
        fix = vuln.best_fix_version
        lines.append(
            f"{vuln.cve or vuln.id} | {score_to_grade_zh(vuln.severity)} | "
            f"CVSS {vuln.cvss_score if vuln.cvss_score is not None else '—'} | "
            f"{vuln.summary[:80]} | 修复版本: {fix or '无'} | 公开: {fmt_date(vuln.published)}"
        )
        if aliases:
            lines[-1] += f" | 别名: {aliases}"
    return lines
