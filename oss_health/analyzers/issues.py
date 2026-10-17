"""Issue 响应分析：近 90 天有没有真人 / 维护者回 Issue、响应有多快、Issue 是否在被处理。

评分采用「**取最优信号**」的思路：只要出现任一强有力的处理信号（维护者回复量足够、
问题被维护者关闭、开放问题无人理会的比例很低），就说明项目是在处理 Issue 的。
这样大仓库和每日爆量的小社区项目都不会被「回复率低」误伤。
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from ..config import MIN_EFFECTIVE_MAINTAINER_REPLIES, WEIGHTS
from ..models import Dimension, RepoSignals
from ..util import fmt_hours, fmt_pct


def analyze(
    repo: Optional[RepoSignals],
    now: datetime,
    *,
    governance: bool = False,
) -> Dimension:
    dim = Dimension(
        key="issues",
        title="Issue 响应",
        weight=WEIGHTS["issues"],
        score=100,
        metrics={},
        evidence=[],
    )
    if repo is None or repo.issues is None:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("缺少 GitHub 仓库数据，无法评估 Issue 响应")
        return dim

    issues = repo.issues
    if issues.issues_disabled:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("仓库关闭了 Issues 功能，无法通过 Issue 判断响应能力")
        return dim

    window = issues.window_days
    metrics = dim.metrics
    metrics.update(
        {
            "sampled": issues.sampled,
            "opened_window": issues.opened_window,
            "maintainer_replied": issues.maintainer_replied_count,
            "human_replied": issues.human_replied_count,
            "closed_by_maintainer": issues.closed_by_maintainer_window,
            "closed_window": issues.closed_window,
            "bot_comment_share": issues.bot_comment_share,
            "median_first_human_response_hours": issues.median_first_human_response_hours,
            "median_maintainer_response_hours": issues.median_maintainer_response_hours,
            "unanswered_open": issues.unanswered_open_count,
            "open_count": issues.open_count,
            "bug_labeled": issues.bug_labeled_count,
            "long_open_bugs": issues.long_open_bugs,
        }
    )

    if issues.sampled == 0:
        dim.score = 72 if not governance else 60
        dim.evidence.append(f"近 {window} 天没有 Issue 活动，无法观测响应速度")
        if repo.archived:
            dim.add(30, "仓库已归档，Issue 不会再被官方处理")
        dim.status = "warn"
        return dim

    # ---------------- 证据 ----------------
    dim.evidence.append(
        f"近 {window} 天有更新的 Issue 采样 {issues.sampled} 条"
        + ("（已达 100 条上限）" if issues.sample_truncated else "")
        + f"，其中新开 {issues.opened_window} 条"
    )
    dim.evidence.append(
        f"获得维护者回复 {issues.maintainer_replied_count} 条、真人回复 {issues.human_replied_count} 条、"
        f"维护者关闭 {issues.closed_by_maintainer_window} 条"
    )
    if issues.median_first_human_response_hours is not None:
        dim.evidence.append(f"首次真人响应中位数：{fmt_hours(issues.median_first_human_response_hours)}")
    if issues.median_maintainer_response_hours is not None:
        dim.evidence.append(f"首次维护者响应中位数：{fmt_hours(issues.median_maintainer_response_hours)}")
    if issues.human_comment_count + issues.bot_comment_count > 0:
        dim.evidence.append(
            f"窗口内评论 {issues.human_comment_count + issues.bot_comment_count} 条，"
            f"机器人占 {fmt_pct(issues.bot_comment_share * 100)}"
        )
    if issues.open_count:
        dim.evidence.append(
            f"当前开放 Issue {issues.open_count} 条，其中窗口内无人回复 {issues.unanswered_open_count} 条"
        )

    # ---------------- 信号 ----------------
    replied = issues.maintainer_replied_count
    closed_by_maint = issues.closed_by_maintainer_window
    open_total = issues.open_count
    unanswered_ratio = (issues.unanswered_open_count / open_total) if open_total else 0.0
    human_reply_ratio = (issues.human_replied_count / issues.opened_window) if issues.opened_window else None
    maint_activity = issues.maintainer_activity or (not governance and replied >= MIN_EFFECTIVE_MAINTAINER_REPLIES)

    # 得分 = 100 - 排名第一的问题 - 排名第二的问题（两个独立信号各取最大值）
    penalties: list[tuple[int, str]] = []

    # 信号 A：维护者在回应吗？
    if replied == 0 and closed_by_maint == 0:
        penalties.append((40, f"近 {window} 天没有任何维护者回复或关闭 Issue"))
    elif replied + closed_by_maint < MIN_EFFECTIVE_MAINTAINER_REPLIES:
        penalties.append(
            (14, f"近 {window} 天维护者只处理了 {replied + closed_by_maint} 条 Issue，响应能力存疑")
        )

    # 信号 B：开放问题是不是被晾着？
    if open_total >= 5 and unanswered_ratio >= 0.85:
        penalties.append(
            (22, f"{fmt_pct(unanswered_ratio * 100)} 的开放 Issue 在窗口内无人回复（共 {open_total} 条开放）")
        )
    elif open_total >= 5 and unanswered_ratio >= 0.6:
        penalties.append((10, f"{fmt_pct(unanswered_ratio * 100)} 的开放 Issue 无人回复"))

    # 信号 C：新开 Issue 的响应率（仅当维护者整体不太活跃时才作为主要惩罚）
    if human_reply_ratio is not None and issues.opened_window >= 5:
        metrics["human_reply_ratio"] = human_reply_ratio
        if human_reply_ratio >= 0.5:
            dim.notes.append(f"窗口内新开 Issue 有 {fmt_pct(human_reply_ratio * 100)} 得到真人回复")
        elif human_reply_ratio < 0.15 and not maint_activity:
            penalties.append((20, f"新开 Issue 获得真人回复的比例仅 {fmt_pct(human_reply_ratio * 100)}"))
        elif human_reply_ratio < 0.15:
            dim.notes.append(
                f"新开 Issue 真人回复率 {fmt_pct(human_reply_ratio * 100)}（大仓库常见，已通过维护者回复量/关闭数交叉验证）"
            )

    # 信号 D：响应速度
    resp = issues.median_first_human_response_hours
    if resp is not None:
        if resp > 24 * 30:
            penalties.append((16, f"首次真人响应中位数超过 30 天（{fmt_hours(resp)}）"))
        elif resp > 24 * 14:
            penalties.append((9, f"首次真人响应中位数超过 14 天（{fmt_hours(resp)}）"))
        elif resp > 24 * 7:
            penalties.append((4, f"首次真人响应中位数超过 7 天（{fmt_hours(resp)}）"))

    # 信号 E：评论里全是机器人
    if issues.bot_comment_share >= 0.7 and issues.human_comment_count + issues.bot_comment_count >= 5:
        penalties.append((10, f"Issue 评论中机器人占 {fmt_pct(issues.bot_comment_share * 100)}，真人参与度低"))
    elif issues.bot_comment_share >= 0.5:
        penalties.append((4, f"Issue 评论中机器人占 {fmt_pct(issues.bot_comment_share * 100)}"))

    penalties.sort(key=lambda item: -item[0])
    applied = penalties[:2]
    for points, reason in applied:
        dim.add(points, reason)

    # 只有机器人回复过
    if issues.human_replied_count == 0 and issues.bot_comment_count > 0:
        dim.add(10, "近 90 天只有机器人回复 Issue，没有真人参与")

    # 信号 F：关键 bug 长期不修（带 bug/崩溃/安全标签、开放超过半年且无人回复）
    if issues.long_open_bugs:
        points = 16 if issues.long_open_bugs >= 3 else 10
        dim.add(
            points,
            f"有 {issues.long_open_bugs} 个带 bug/崩溃等标签的 Issue 开放超过半年且无人回复",
        )

    if repo.archived:
        dim.add(30, "仓库已归档，Issue 不再有人维护")

    # 正面证据
    if maint_activity and replied >= MIN_EFFECTIVE_MAINTAINER_REPLIES:
        dim.notes.append(f"近 {window} 天维护者处理了 {replied} 条 Issue，响应能力正常")
    if not governance and replied > 0:
        metrics["governance"] = True

    if issues.sample_truncated:
        dim.notes.append("Issue 命中 100 条采样上限，统计为下限")
    dim.clamp()
    dim.status = dim.score_status()
    return dim
