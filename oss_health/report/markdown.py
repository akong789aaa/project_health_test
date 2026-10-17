"""Markdown 报告渲染。"""

from __future__ import annotations

from ..models import ScanReport, Vulnerability
from ..cvss import score_to_grade_zh
from . import common


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append(f"# 开源项目健康度报告：{common.short_target(report)}")
    lines.append("")
    lines.append(f"> 由 **{report.tool_version}** 生成于 {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}"
                 f" · 统计窗口近 {report.extra.get('window_days', 90)} 天"
                 f" · 耗时 {report.duration_seconds:.1f}s")
    if report.offline:
        lines.append(">")
        lines.append("> ⚠️ 本报告由离线快照回放生成，数据为录制时状态。")
    lines.append("")

    # ---- 结论 ----
    icon = common.VERDICT_ICONS.get(report.verdict_level, "🟡")
    lines.append("## 结论")
    lines.append("")
    lines.append("| 项目 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 目标 | `{_md_escape(common.short_target(report))}` |")
    repo_line = common.repo_line(report)
    if repo_line:
        lines.append(f"| 仓库 | {_md_escape(repo_line)} |")
    lines.append(f"| 综合评分 | **{report.score_int} / 100**（加权原始分 {report.raw_total}） |")
    lines.append(f"| 等级 / 结论 | {icon} **{report.grade} 级 · {_md_escape(report.verdict)}** |")
    lines.append(f"| 置信度 | {common.CONFIDENCE_LABELS.get(report.confidence, report.confidence)}"
                 f"（{common.CONFIDENCE_ICONS.get(report.confidence, '')}） |")
    lines.append("")
    if report.hard_flags:
        lines.append("### 触发的一票否决")
        lines.append("")
        for flag in report.hard_flags:
            lines.append(f"- ⛔ **{_md_escape(flag.reason)}** → 总分封顶 {flag.cap:.0f}")
        lines.append("")

    if report.confidence_reasons:
        lines.append("### 置信度说明")
        lines.append("")
        for reason in report.confidence_reasons:
            lines.append(f"- {reason}")
        lines.append("")

    # ---- 维度评分 ----
    lines.append("## 维度评分")
    lines.append("")
    lines.append("| 维度 | 得分 | 权重 | 状态 | 关键结论 |")
    lines.append("| --- | ---: | ---: | --- | --- |")
    for dim in report.dimensions:
        if dim.available:
            status = common.STATUS_LABELS.get(dim.status, dim.status)
            lines.append(
                f"| {dim.title} | **{dim.score}** / 100 | {dim.weight:.0f}% | {status} | "
                f"{_md_escape(common.evidence_summary(dim, 2))} |"
            )
        else:
            note = dim.notes[0] if dim.notes else "数据缺失"
            lines.append(f"| {dim.title} | — | {dim.weight:.0f}% | 未评估 | {_md_escape(note)} |")
    lines.append("")

    # ---- 关键指标 ----
    lines.append("## 关键指标")
    lines.append("")
    for dim in report.dimensions:
        rows = common.metric_rows(dim)
        if not rows or not dim.available:
            continue
        lines.append(f"### {dim.title}（{dim.score}/100）")
        lines.append("")
        lines.append("| 指标 | 数值 |")
        lines.append("| --- | --- |")
        for label, value in rows:
            lines.append(f"| {label} | {_md_escape(value)} |")
        lines.append("")
        if dim.deductions:
            lines.append("扣分项：")
            for deduction in dim.deductions:
                lines.append(f"- (-{deduction.points}) {deduction.reason}")
            lines.append("")
        if dim.notes:
            lines.append("说明：" + "；".join(dim.notes))
            lines.append("")

    # ---- 证据 ----
    lines.append("## 全部证据")
    lines.append("")
    for dim in report.dimensions:
        if not dim.evidence:
            continue
        lines.append(f"- **{dim.title}**")
        for evidence in dim.evidence:
            lines.append(f"  - {evidence}")
    lines.append("")

    # ---- 漏洞明细 ----
    security = report.security
    if security is not None:
        lines.append("## 漏洞明细")
        lines.append("")
        if security.db_available:
            lines.append(
                f"OSV.dev：当前版本 **{security.version}** 存在 "
                f"**{len(security.vulns_current)}** 条未修复漏洞；历史公告 {security.history_count} 条，"
                f"其中 {security.fixed_count} 条已在当前版本前修复。"
            )
        lines.append("")
        if security.vulns_current:
            lines.append("| 编号 | 严重度 | CVSS | 摘要 | 修复版本 | 公开时间 |")
            lines.append("| --- | --- | ---: | --- | --- | --- |")
            for vuln in security.vulns_current:
                lines.append(_vuln_row(vuln))
            lines.append("")
        elif security.db_available:
            lines.append("✅ 未发现影响当前版本的已知漏洞。")
            lines.append("")

        # 依赖漏洞
        risky = [r for r in report.dep_risks if getattr(r, "vulns", None)]
        lines.append("## 依赖漏洞")
        lines.append("")
        dep_dim = report.dimension("dependencies")
        if dep_dim is not None and dep_dim.metrics:
            lines.append(
                f"检查 {dep_dim.metrics.get('deps_checked', 0)}/{dep_dim.metrics.get('deps_total', 0)} "
                f"个直接运行时依赖，{dep_dim.metrics.get('deps_with_vulns', 0)} 个存在已知漏洞。"
            )
            lines.append("")
        if risky:
            lines.append("| 依赖 | 检查版本 | 编号 | 严重度 | CVSS | 摘要 | 修复版本 |")
            lines.append("| --- | --- | --- | --- | ---: | --- | --- |")
            for risk in risky:
                for vuln in risk.vulns:
                    lines.append(
                        f"| `{_md_escape(risk.name)}` | {_md_escape(risk.checked_version)} | "
                        f"{vuln.cve or vuln.id} | {score_to_grade_zh(vuln.severity)} | "
                        f"{vuln.cvss_score if vuln.cvss_score is not None else '—'} | "
                        f"{_md_escape((vuln.summary or '')[:100])} | {vuln.best_fix_version or '无'} |"
                    )
            lines.append("")
        elif dep_dim is not None and dep_dim.available:
            lines.append("✅ 直接依赖中未发现影响当前解析版本的已知漏洞。")
            lines.append("")

    # ---- 运行时 ----
    if report.framework is not None and report.framework.status != "unknown":
        fw = report.framework
        lines.append("## 运行时 / 框架支持")
        lines.append("")
        lines.append(f"- 运行时：**{fw.runtime}**，声明支持：{_md_escape('、'.join(fw.declared) or '—')}")
        if fw.latest_supported:
            lines.append(f"- 官方最新：**{fw.latest_supported}**，仍在支持的版本：{'、'.join(fw.supported_cycles) or '—'}")
        if fw.eol_declared:
            lines.append(f"- ⚠️ 已 EOL 的声明：{'、'.join(fw.eol_declared)}")
        for evidence in fw.evidence:
            lines.append(f"- {evidence}")
        lines.append("")

    # ---- 建议 ----
    lines.append("## 行动建议")
    lines.append("")
    for index, rec in enumerate(report.recommendations, 1):
        lines.append(f"{index}. {rec}")
    lines.append("")

    # ---- 警告 ----
    if report.warnings:
        lines.append("## 数据警告 / 降级说明")
        lines.append("")
        for warning in report.warnings:
            lines.append(f"- {warning}")
        lines.append("")

    # ---- 来源 ----
    lines.append("## 数据来源与已知局限")
    lines.append("")
    lines.append(f"- 数据来源：{common.source_names(report)}")
    for source in report.sources:
        if source.url:
            lines.append(f"  - {source.name}: <{source.url}>")
    lines.append("- 已知局限：")
    lines.append("  - Issue / PR 统计基于最近 100 条采样，绝对值可能偏低；PR 合并者仅抽查少量已合并 PR。")
    lines.append("  - 漏洞数据来自 OSV.dev（GHSA / CVE / PyPA 等公告）；依赖按「锁定版本或当前最新版本」启发式检查，不是完整 SBOM 审计。")
    lines.append("  - 运行时支持周期来自 endoflife.date，与厂商实际策略可能存在差异。")
    lines.append("  - 报告仅供决策参考，重要依赖建议人工复核或结合 SCA 工具。")
    lines.append("")
    return "\n".join(lines)


def _vuln_row(vuln: Vulnerability) -> str:
    aliases = [a for a in vuln.aliases if a != vuln.id][:2]
    name = vuln.cve or vuln.id
    alias_text = f"（{', '.join(aliases)}）" if aliases else ""
    return (
        f"| [{name}{alias_text}]({vuln.url}) | {score_to_grade_zh(vuln.severity)} | "
        f"{vuln.cvss_score if vuln.cvss_score is not None else '—'} | "
        f"{_md_escape((vuln.summary or '')[:120])} | {vuln.best_fix_version or '无'} | "
        f"{vuln.published.strftime('%Y-%m-%d') if vuln.published else '—'} |"
    )
