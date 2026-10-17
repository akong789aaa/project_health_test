"""终端报告渲染（ANSI 颜色 + CJK 宽度感知）。"""

from __future__ import annotations

import shutil
from typing import Optional

from ..models import ScanReport
from ..text import Style, Table, bar, box, pad, truncate, visible_width, wrap
from . import common


def _terminal_width() -> int:
    try:
        cols = shutil.get_terminal_size((100, 30)).columns
    except OSError:
        cols = 100
    return max(72, min(cols, 108))


def _wrap_with_prefix(
    text: str, width: int, *, first_prefix: str = "", prefix: str = "  ", style: Style
) -> list[str]:
    text = text.replace("\n", " ")
    budget = max(10, width - visible_width(prefix))
    lines = wrap(text, budget)
    out: list[str] = []
    for i, line in enumerate(lines or [""]):
        p = first_prefix if i == 0 else prefix
        out.append(p + line)
    return out


def render(report: ScanReport, *, style: Optional[Style] = None, width: Optional[int] = None) -> str:
    style = style or Style()
    width = width or _terminal_width()
    lines: list[str] = []

    # ------------------------------------------------------------------
    # 头部
    # ------------------------------------------------------------------
    inner = width - 2
    repo_line = common.repo_line(report)
    score = f"{report.score_int} / 100"
    verdict_colored = _verdict_text(report, style)
    header: list[str] = []
    header.append(f"{style.bold('目标')}    {common.short_target(report)}")
    header.append(f"{style.bold('仓库')}    {repo_line or style.dim('未找到 GitHub 仓库')}")
    gap = max(1, inner - 2 - visible_width(f"结论    {verdict_colored}") - visible_width(score))
    header.append(f"{style.bold('结论')}    {verdict_colored}{' ' * gap}{style.bold(score)}")
    header.append(f"{style.bold('置信度')}  {common.confidence_text(report)}")
    lines.extend(box(header, width=inner, title="开源项目健康度扫描器 · 报告", style=style))
    lines.append("")

    # ------------------------------------------------------------------
    # 维度评分
    # ------------------------------------------------------------------
    lines.append(style.bold("维度评分"))
    title_width = 12
    for dim in report.dimensions:
        if dim.available:
            bar_text = bar(dim.score, 14)
            colored_bar = (
                style.green(bar_text) if dim.score >= 75 else style.yellow(bar_text) if dim.score >= 50 else style.red(bar_text)
            )
            score_text = pad(f"{dim.score}/100", 7, "right")
            status = style.status_text(dim.status, common.STATUS_LABELS.get(dim.status, dim.status))
            summary = common.evidence_summary(dim, 1)
            fixed = 2 + title_width + 1 + 14 + 2 + 7 + 2 + 8
            summary_width = width - fixed - 2
            summary_part = ""
            if summary_width >= 12:
                summary_part = "  " + style.dim(truncate(summary, summary_width))
            lines.append(
                f"  {pad(dim.title, title_width)} {colored_bar} {score_text}  {status}{summary_part}"
            )
        else:
            note = dim.notes[0] if dim.notes else "数据缺失"
            lines.append(
                f"  {pad(dim.title, title_width)} {style.gray('░' * 14)} {pad('—', 7, 'right')}  "
                f"{style.status_text('unknown', '未知')}  {style.dim(truncate(note, max(10, width - 40)))}"
            )
    lines.append("")

    # ------------------------------------------------------------------
    # 关键指标
    # ------------------------------------------------------------------
    lines.append(style.bold("关键指标"))
    for dim in report.dimensions:
        if not dim.available:
            continue
        rows = common.metric_rows(dim)
        if not rows:
            continue
        suffix = " / 100"
        head = f"  {style.bold(dim.title)}  {dim.score}{suffix}"
        lines.append(head)
        chunk: list[str] = []
        current = "     "
        for label, value in rows:
            piece = f"{label} {style.bold(value)}"
            candidate = current + piece + " · "
            if visible_width(candidate) > width - 2 and current.strip():
                chunk.append(current.rstrip(" ·"))
                current = "     " + piece + " · "
            else:
                current = candidate
        if current.strip():
            chunk.append(current.rstrip(" ·"))
        lines.extend(chunk)
    lines.append("")

    # ------------------------------------------------------------------
    # 风险与发现
    # ------------------------------------------------------------------
    findings = common.top_findings(report)
    lines.append(style.bold("风险与发现"))
    if not findings:
        lines.append(f"  {style.green('✔')} 未发现明显风险信号")
    else:
        for status, text, _points in findings:
            icon = style.icon(status)
            wrapped = _wrap_with_prefix(text, width - 4, first_prefix=f"  {icon} ", prefix="    ", style=style)
            lines.extend(wrapped)
    for positive in common.positives(report, 2):
        lines.append(f"  {style.green('✔')} {style.dim(positive)}")
    lines.append("")

    # ------------------------------------------------------------------
    # 漏洞明细
    # ------------------------------------------------------------------
    security = report.security
    if security is not None and security.vulns_current:
        lines.append(style.bold(f"漏洞明细（影响当前版本，共 {len(security.vulns_current)} 条）"))
        table = Table(
            ["编号", "严重度", "CVSS", "摘要", "修复版本"],
            aligns=["left", "left", "right", "left", "left"],
        )
        for vuln in security.vulns_current[:12]:
            table.add(
                vuln.cve or vuln.id,
                common.score_to_grade_zh(vuln.severity),
                f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "—",
                truncate(vuln.summary or vuln.id, 46),
                _fix_label(vuln.best_fix_version),
            )
        for row in table.render(style, max_width=width - 2):
            lines.append("  " + row)
        if len(security.vulns_current) > 12:
            lines.append(style.dim(f"  …… 另有 {len(security.vulns_current) - 12} 条，详见 --format md/json 报告"))
        lines.append("")

    # ------------------------------------------------------------------
    # 依赖风险
    # ------------------------------------------------------------------
    risky = [r for r in report.dep_risks if getattr(r, "vulns", None)]
    if risky:
        lines.append(style.bold(f"依赖风险（{len(risky)} 个直接依赖存在漏洞）"))
        for risk in risky[:8]:
            worst = sorted(risk.vulns, key=lambda v: (-v.severity_rank, -(v.cvss_score or 0)))[0]
            fix = f" → 升级到 {worst.best_fix_version}" if worst.best_fix_version else "（暂无修复版本）"
            text = (
                f"{risk.name}@{risk.checked_version}：{worst.cve or worst.id}"
                f"（{common.score_to_grade_zh(worst.severity)}）{fix}"
            )
            lines.append(f"  {style.icon('warn')} {truncate(text, width - 4)}")
        lines.append("")

    # ------------------------------------------------------------------
    # 建议
    # ------------------------------------------------------------------
    lines.append(style.bold("行动建议"))
    for index, rec in enumerate(report.recommendations, 1):
        wrapped = _wrap_with_prefix(
            rec, width - 5, first_prefix=f"  {index}. ", prefix="     ", style=style
        )
        lines.extend(wrapped)
    lines.append("")

    # ------------------------------------------------------------------
    # 数据说明
    # ------------------------------------------------------------------
    lines.append(style.bold("数据说明"))
    window = report.extra.get("window_days", 90)
    info = [
        f"数据来源：{common.source_names(report)}",
        f"统计窗口：近 {window} 天 / 采集时间：{report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}"
        + f" / 耗时 {report.duration_seconds:.1f}s",
    ]
    remaining = report.extra.get("github_remaining")
    if remaining is not None:
        limit = report.extra.get("github_limit")
        info.append(
            f"GitHub 配额剩余：{remaining}"
            + (f" / {limit}" if limit else "")
            + ("（未配置 GITHUB_TOKEN，60 次/小时）" if limit and limit <= 60 else "")
        )
    if report.offline:
        info.append("模式：离线快照回放（数据为录制时状态）")
    commits = report.repo.commits if report.repo is not None else None
    if commits is not None and commits.baseline_commits_per_week is not None:
        info.append(
            "节奏基线：历史约 "
            f"{commits.baseline_commits_per_week:.1f} 次提交/周，近 90 天约 "
            f"{commits.recent_commits_per_week or 0:.1f} 次/周（项目自身 52 周基线）"
        )
    for line in info:
        wrapped = _wrap_with_prefix(line, width - 4, first_prefix="  · ", prefix="    ", style=style)
        lines.extend(wrapped)

    limitations = [
        "Issue / PR 统计基于最近 100 条采样，绝对值可能偏低；PR 合并者仅抽查少量已合并 PR。",
        "漏洞数据来自 OSV.dev；依赖按「锁定版本或当前最新版本」启发式检查，不是完整 SBOM 审计。",
        "运行时支持周期来自 endoflife.date，与厂商实际策略可能存在差异。",
        "活跃度与发布节奏已结合项目自身历史基线判定；极早期项目（<6 个月）基线样本不足。",
    ]
    lines.append(style.dim("  已知局限："))
    for item in limitations:
        for wrapped in wrap(item, width - 6):
            lines.append(style.dim("    · " + wrapped))

    # 置信度说明
    if report.confidence_reasons:
        lines.append(style.dim("  置信度说明："))
        for reason in report.confidence_reasons[:6]:
            for wrapped in wrap(reason, width - 6):
                lines.append(style.dim("    - " + wrapped))

    lines.append("")
    lines.append(style.dim(f"由 {report.tool_version} 生成 · 报告仅供决策参考，重要依赖请人工复核"))
    return "\n".join(lines)


def _fix_label(version: Optional[str]) -> str:
    if not version:
        return "无"
    # 有些修复版本是 commit SHA（没有正式发布版本），终端里缩短显示
    if len(version) == 40 and all(c in "0123456789abcdef" for c in version.lower()):
        return version[:10] + "…"
    return version


def _verdict_text(report: ScanReport, style: Style) -> str:
    icon = common.VERDICT_ICONS.get(report.verdict_level, "🟡")
    text = f"{icon} {report.grade} 级 · {report.verdict}"
    if report.verdict_level == "good":
        return style.green(text)
    if report.verdict_level == "caution":
        return style.yellow(text)
    return style.red(text)
