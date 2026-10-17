"""PR 健康度分析：真人是否还在参与、合并是不是机器人在做、PR 是否被处理。

与 Issue 类似，采用「取最优信号」避免误伤：

* 机器人负责合并 dependabot 的 bump 在成熟项目里是**最佳实践**，不扣分；
* 真正的风险是「所有 PR（含人类 PR）都由机器人合并」或「PR 被晾着没人处理」。
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from ..config import WEIGHTS
from ..models import Dimension, RepoSignals
from ..util import fmt_hours, fmt_pct


def analyze(repo: Optional[RepoSignals], now: datetime) -> Dimension:
    dim = Dimension(
        key="prs",
        title="PR 健康度",
        weight=WEIGHTS["prs"],
        score=100,
        metrics={},
        evidence=[],
    )
    if repo is None or repo.prs is None:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("缺少 GitHub 仓库数据，无法评估 PR 健康度")
        return dim

    prs = repo.prs
    window = prs.window_days
    total_created = prs.bot_pr_count + prs.human_pr_count
    closed_total = prs.merged_window + prs.closed_unmerged_window
    metrics = dim.metrics
    metrics.update(
        {
            "sampled": prs.sampled,
            "created_window": prs.created_window,
            "human_created": prs.human_created_window,
            "bot_created": prs.bot_pr_count,
            "merged_window": prs.merged_window,
            "closed_unmerged_window": prs.closed_unmerged_window,
            "open_window": prs.open_window,
            "stale_open": prs.stale_open_count,
            "bot_pr_share": prs.bot_pr_share,
            "merge_rate": prs.merge_rate,
            "bot_merge_share": prs.bot_merge_share,
            "merged_samples": prs.merged_samples,
            "median_merge_hours": prs.median_merge_hours,
            "human_median_merge_hours": prs.human_median_merge_hours,
            "governance": True,
        }
    )

    if prs.sampled == 0:
        dim.score = 74
        dim.evidence.append(f"近 {window} 天没有 PR 活动，无法观测协作情况")
        if repo.archived:
            dim.add(25, "仓库已归档，不再接受 PR")
        dim.status = "warn"
        return dim

    # ---------------- 证据 ----------------
    dim.evidence.append(
        f"近 {window} 天新开 PR {prs.created_window} 条"
        f"（真人 {prs.human_created_window} / 机器人 {prs.bot_pr_count}）"
    )
    if closed_total:
        dim.evidence.append(
            f"窗口内合并 {prs.merged_window} 条、由真人关闭未合并 {prs.human_closed_unmerged_window} 条、"
            f"关闭未合并合计 {prs.closed_unmerged_window} 条"
        )
    if prs.median_merge_hours is not None:
        dim.evidence.append(f"合并耗时中位数：{fmt_hours(prs.median_merge_hours)}")
    if prs.open_window:
        dim.evidence.append(f"窗口内新开且仍未合并的 PR：{prs.open_window} 条")
    if total_created:
        dim.evidence.append(f"机器人提交的 PR 占 {fmt_pct(prs.bot_pr_share * 100)}")
    if prs.merged_samples:
        dim.evidence.append(
            f"抽查 {prs.merged_samples} 个已合并 PR：机器人合并 {prs.bot_merged_samples} 个、"
            f"真人合并 {prs.human_merged_samples} 个"
        )
        reviewed = [d for d in prs.sample_details if d.get("review_comments", 0) > 0]
        metrics["sampled_prs_with_review_comments"] = len(reviewed)
        if reviewed:
            dim.evidence.append(f"抽查中 {len(reviewed)} 个 PR 有代码评审评论")
    else:
        dim.notes.append("未能抽查 PR 合并者（配额或数据不足）")

    # ---------------- 信号：处理情况（取最优） ----------------
    handled = (
        prs.merged_window
        + prs.human_closed_unmerged_window
        + (prs.human_merged_samples if prs.merged_samples else 0)
    )
    if handled == 0 and prs.human_created_window > 0:
        dim.add(30, "近 90 天有真人 PR，但没有任何一条被合并或由真人关闭")
    elif handled == 0 and prs.created_window > 0:
        dim.add(18, "近 90 天的 PR 全部没有处理（既未合并也未被关闭）")
    elif prs.human_created_window > 0 and prs.human_merged_samples == 0 and prs.merged_window == 0:
        dim.add(15, "近 90 天真人的 PR 没有得到合并")

    if prs.stale_open_count >= 30:
        dim.add(12, f"有 {prs.stale_open_count} 个超过 90 天未合并的 PR 积压")
    elif prs.stale_open_count >= 10:
        dim.add(6, f"有 {prs.stale_open_count} 个超过 90 天未合并的 PR 积压")

    # 合并率：只在样本够、且不是「没合并」已经扣过分的场景下使用
    if prs.merge_rate is not None and closed_total >= 5 and handled > 0:
        if prs.merge_rate < 0.1:
            dim.add(10, f"窗口内 PR 合并率仅 {fmt_pct(prs.merge_rate * 100)}")
        elif prs.merge_rate < 0.3:
            dim.add(5, f"窗口内 PR 合并率偏低（{fmt_pct(prs.merge_rate * 100)}）")

    # ---------------- 信号：机器人与评审 ----------------
    bot_share = prs.bot_merge_share
    if prs.merged_samples and prs.merged_samples >= 2:
        if bot_share is not None and bot_share >= 0.8:
            # 区分：全是 bot 的依赖 PR（成熟 CI 实践） vs 连人类 PR 也被 bot 合并
            if prs.merged_samples >= 3 and prs.human_pr_count == 0:
                dim.add(12, "抽查的合并 PR 几乎全部由机器人执行，真人协作信号很弱")
            elif prs.merged_samples >= 3:
                dim.add(6, "抽查的合并 PR 中机器人占比 ≥80%，人工评审把关不足")
                dim.notes.append("注意：若这些只是依赖升级 PR，机器人合并属于正常的自动化实践")
        elif bot_share is not None and bot_share >= 0.6:
            dim.add(3, f"抽查的合并 PR 中 {fmt_pct(bot_share * 100)} 由机器人合并")
    # 人类 PR 被机器人合并 = 真有问题
    human_authored_bot_merged = [
        d for d in prs.sample_details
        if d.get("merged_by_is_bot") and d.get("author") and not _is_bot_name(d.get("author", ""))
    ]
    if human_authored_bot_merged:
        dim.add(10, f"抽查中有 {len(human_authored_bot_merged)} 个人类 PR 被机器人合并")

    if total_created >= 3:
        if prs.human_created_window == 0 and prs.bot_pr_count >= 3:
            dim.add(12, "近 90 天的 PR 全部由机器人提交，没有真人贡献")
        elif prs.bot_pr_share >= 0.9:
            dim.add(6, f"机器人提交的 PR 占 {fmt_pct(prs.bot_pr_share * 100)}，真人贡献很少")
        dim.notes.append(
            f"真人 PR {prs.human_created_window} 条 / 机器人 PR {prs.bot_pr_count} 条"
        )

    if prs.median_merge_hours is not None and prs.median_merge_hours > 24 * 30:
        dim.add(5, f"PR 合并耗时中位数超过 30 天（{fmt_hours(prs.median_merge_hours)}）")
    if prs.human_median_merge_hours is not None:
        dim.evidence.append(
            f"真人提交的 PR 合并耗时中位数：{fmt_hours(prs.human_median_merge_hours)}"
        )
        if prs.human_median_merge_hours > 24 * 45:
            dim.add(8, f"真人 PR 平均要 {fmt_hours(prs.human_median_merge_hours)} 才被合并")
        elif prs.human_median_merge_hours > 24 * 14:
            dim.add(4, f"真人 PR 合并偏慢（中位数 {fmt_hours(prs.human_median_merge_hours)}）")

    # 只有当人类 PR 也普遍没有评审时才算问题（依赖机器人 PR 没有评审是正常的）
    human_merged_details = [
        d for d in prs.sample_details if d.get("author") and not _is_bot_name(d.get("author", ""))
    ]
    if (
        human_merged_details
        and len(human_merged_details) >= 2
        and not metrics.get("sampled_prs_with_review_comments")
    ):
        dim.add(4, f"抽查的 {len(human_merged_details)} 个人类合并 PR 都没有代码评审评论")
    elif prs.sample_details and not metrics.get("sampled_prs_with_review_comments"):
        dim.notes.append("抽查的合并 PR 均为机器人依赖更新，没有评审评论属正常")

    if prs.auto_merge_prs > 0:
        dim.notes.append(f"窗口内有 {prs.auto_merge_prs} 个 PR 启用了 auto-merge")
    if prs.sample_truncated:
        dim.notes.append("PR 采样达到 100 条上限，统计为下限")
    if repo.archived:
        dim.add(25, "仓库已归档，不再处理 PR")
    if repo.disabled:
        dim.add(25, "仓库已被禁用")

    dim.clamp()
    dim.status = dim.score_status()
    return dim


def _is_bot_name(name: str) -> bool:
    from ..heuristics import is_bot_login  # 局部导入，避免循环依赖

    return is_bot_login(name)
