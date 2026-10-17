"""报告渲染的公共辅助：指标标签、状态文案、格式化。"""

from __future__ import annotations

from typing import Any, Optional

from ..models import Dimension, ScanReport
from ..cvss import score_to_grade_zh

DIMENSION_LABELS: dict[str, dict[str, str]] = {
    "issues": {"sampled": "采样 Issue 数", "created_window": "窗口内新建 Issue"},
    "prs": {"sampled": "采样 PR 数", "created_window": "窗口内新建 PR"},
    "maintenance": {"sampled": "采样提交数"},
}

METRIC_LABELS: dict[str, str] = {
    # maintenance
    "commits_window": "窗口内提交",
    "human_commits": "真人提交",
    "bot_commits": "机器人提交",
    "substantive_human_commits": "功能/修复提交",
    "chore_human_commits": "CI/依赖类提交",
    "unique_human_authors": "真人贡献者",
    "top_author_share": "最大贡献者占比",
    "last_commit_age_days": "最近提交（天前）",
    "active_weeks": "近 13 周活跃周数",
    "releases_window": "窗口内发布",
    "releases_365d": "近一年发布",
    "releases_prev_90d": "前 90 天发布",
    "release_trend": "发布节奏（相对前 90 天）",
    "last_release_age_days": "最近发布（天前）",
    "stars": "Stars",
    "stars_recent_90d": "近 90 天新增 Star",
    "star_velocity_recent_month": "近期 Star（个/月）",
    "star_velocity_lifetime_month": "历史 Star（个/月）",
    "archived": "已归档",
    # issues
    "sampled": "采样数量",
    "created_window": "窗口内新建 PR",
    "opened_window": "新开 Issue",
    "maintainer_replied": "维护者回复 Issue",
    "human_replied": "真人回复 Issue",
    "closed_by_maintainer": "维护者关闭 Issue",
    "closed_window": "窗口内关闭 Issue",
    "human_reply_ratio": "新 Issue 真人回复率",
    "bot_comment_share": "机器人评论占比",
    "median_first_human_response_hours": "首次真人响应",
    "median_maintainer_response_hours": "首次维护者响应",
    "maintainer_reply_ratio": "新 Issue 维护者回复率",
    "unanswered_open": "无人回复的开放 Issue",
    "unanswered_open_ratio": "开放 Issue 无人回复占比",
    "open_count": "开放 Issue 数",
    # prs
    "merged_window": "窗口内合并 PR",
    "human_created": "真人新建 PR",
    "bot_created": "机器人新建 PR",
    "closed_unmerged_window": "关闭未合并 PR",
    "open_window": "新开未合并 PR",
    "stale_open": "超 90 天未合并 PR",
    "bot_pr_share": "机器人 PR 占比",
    "merge_rate": "PR 合并率",
    "bot_merge_share": "机器人合并占比",
    "merged_samples": "抽查已合并 PR",
    "median_merge_hours": "PR 合并耗时",
    "human_median_merge_hours": "真人 PR 合并耗时",
    "sampled_prs_with_review_comments": "抽查有评审评论的 PR",
    # framework
    "runtime": "运行时",
    "declared": "声明支持",
    "latest_runtime": "最新运行时",
    "gap": "落后版本数",
    "max_tfm": "最新目标框架",
    "engine_floor_major": "engines 最低主版本",
    # security
    "unfixed_count": "未修复漏洞",
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "history_count": "历史公告",
    "fixed_count": "已修复公告",
    "max_severity": "最高严重度",
    # dependencies
    "deps_total": "运行时依赖",
    "deps_checked": "已检查依赖",
    "deps_failed": "无法解析依赖",
    "deps_with_vulns": "有漏洞的依赖",
    "dep_critical_high": "依赖严重/高危漏洞",
    "dep_medium": "依赖中危漏洞",
}

DIMENSION_KEY_METRICS: dict[str, list[str]] = {
    "maintenance": [
        "commits_window",
        "human_commits",
        "bot_commits",
        "substantive_human_commits",
        "chore_human_commits",
        "unique_human_authors",
        "top_author_share",
        "last_commit_age_days",
        "releases_365d",
        "last_release_age_days",
        "stars",
    ],
    "issues": [
        "sampled",
        "opened_window",
        "maintainer_replied",
        "closed_by_maintainer",
        "human_replied",
        "human_reply_ratio",
        "median_first_human_response_hours",
        "bot_comment_share",
        "unanswered_open",
    ],
    "prs": [
        "created_window",
        "human_created",
        "bot_created",
        "merged_window",
        "open_window",
        "stale_open",
        "bot_pr_share",
        "merge_rate",
        "bot_merge_share",
        "median_merge_hours",
        "human_median_merge_hours",
        "sampled_prs_with_review_comments",
    ],
    "framework": [
        "runtime",
        "declared",
        "latest_runtime",
        "gap",
        "max_tfm",
        "engine_floor_major",
    ],
    "security": ["unfixed_count", "critical", "high", "medium", "low", "history_count", "fixed_count"],
    "dependencies": ["deps_total", "deps_checked", "deps_with_vulns", "dep_critical_high", "dep_medium"],
}

STATUS_LABELS = {
    "good": "良好",
    "warn": "注意",
    "bad": "风险",
    "unknown": "未知",
}

VERDICT_ICONS = {"good": "🟢", "caution": "🟡", "bad": "🔴"}
CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低"}
CONFIDENCE_ICONS = {"high": "●●●", "medium": "●●○", "low": "●○○"}

_PERCENT_KEYS = ("share", "ratio", "rate")
_HOUR_KEYS = ("_hours",)
_DAYS_KEYS = ("_days",)
_SEVERITY_KEYS = ("max_severity",)


def format_metric(key: str, value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (list, tuple)):
        if not value:
            return "—"
        return "、".join(str(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items()) or "—"
    if any(token in key for token in _PERCENT_KEYS) and isinstance(value, (int, float)):
        return f"{float(value) * 100:.0f}%"
    if any(token in key for token in _HOUR_KEYS) and isinstance(value, (int, float)):
        hours = float(value)
        if hours < 1:
            return "<1 小时"
        if hours < 48:
            return f"{hours:.1f} 小时"
        return f"{hours / 24:.1f} 天"
    if any(token in key for token in _DAYS_KEYS) and isinstance(value, (int, float)):
        return f"{float(value):.0f} 天"
    if any(token in key for token in _SEVERITY_KEYS):
        return score_to_grade_zh(str(value)) if value not in ("NONE", "UNKNOWN") else "无"
    if isinstance(value, float):
        return f"{value:.1f}"
    if isinstance(value, int) and abs(value) >= 10000:
        return f"{value:,}"
    return str(value)


def metric_rows(dim: Dimension) -> list[tuple[str, str]]:
    """返回某维度用于展示的 (标签, 值) 列表。"""
    keys = DIMENSION_KEY_METRICS.get(dim.key, list(dim.metrics.keys()))
    rows: list[tuple[str, str]] = []
    overrides = DIMENSION_LABELS.get(dim.key, {})
    for key in keys:
        if key not in dim.metrics:
            continue
        label = overrides.get(key) or METRIC_LABELS.get(key, key)
        rows.append((label, format_metric(key, dim.metrics[key])))
    return rows


def evidence_summary(dim: Dimension, limit: int = 2) -> str:
    if not dim.available:
        return dim.notes[0] if dim.notes else "数据缺失"
    if not dim.evidence:
        return "—"
    return "；".join(dim.evidence[:limit])


def top_findings(report: ScanReport, per_dimension: int = 1, limit: int = 8) -> list[tuple[str, str, int]]:
    """收集各维度扣分项：返回 (状态, 文案, 扣分)。"""
    findings: list[tuple[str, str, int]] = []
    for flag in report.hard_flags:
        findings.append(("bad", f"一票否决：{flag.reason}", 100))
    for dim in report.dimensions:
        if not dim.available:
            continue
        for deduction in dim.deductions[:per_dimension]:
            status = "bad" if deduction.points >= 20 else "warn"
            findings.append((status, f"[{dim.title}] {deduction.reason}", deduction.points))
    findings.sort(key=lambda item: -item[2])
    return findings[:limit]


def positives(report: ScanReport, limit: int = 4) -> list[str]:
    out: list[str] = []
    for dim in report.dimensions:
        if dim.available and dim.score >= 80:
            out.append(f"{dim.title} {dim.score} 分：{evidence_summary(dim, 1)}")
        if len(out) >= limit:
            break
    return out


def source_names(report: ScanReport) -> str:
    names: list[str] = []
    for source in report.sources:
        if source.name not in names:
            names.append(source.name)
    return " · ".join(names) if names else "—"


def short_target(report: ScanReport) -> str:
    target = report.target
    package = report.package
    if package is not None:
        name = package.name
        version = package.version
        return f"{target.ecosystem}:{name} @ {version}"
    return target.display()


def repo_line(report: ScanReport) -> Optional[str]:
    if report.repo is None:
        return None
    repo = report.repo
    from ..util import fmt_human_int

    parts = [repo.slug, f"★ {fmt_human_int(repo.stars)}"]
    if repo.archived:
        parts.append("已归档")
    if repo.is_fork:
        parts.append("fork")
    if repo.license_spdx:
        parts.append(repo.license_spdx)
    return " · ".join(parts)


def score_text(report: ScanReport) -> str:
    return f"{VERDICT_ICONS.get(report.verdict_level, '🟡')} {report.grade} 级 · {report.verdict}"


def confidence_text(report: ScanReport) -> str:
    parts = [f"{CONFIDENCE_LABELS.get(report.confidence, report.confidence)}"]
    if report.confidence_reasons:
        parts.append(report.confidence_reasons[0])
    return " — ".join(parts)
