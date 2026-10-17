"""维护活跃度分析：真人提交、运维 vs 功能提交、bus factor、发布节奏、归档状态。"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from ..config import (
    ACTIVITY_DECLINE_BAD_RATIO,
    ACTIVITY_DECLINE_WARN_RATIO,
    WEIGHTS,
)
from ..models import Dimension, PackageInfo, ReleaseSignals, RepoSignals
from ..util import fmt_ago, fmt_date, fmt_human_int, fmt_pct


def _staleness_penalty(age: int) -> tuple[int, str]:
    if age > 540:
        return 50, f"已经 {age} 天没有提交"
    if age > 365:
        return 38, f"已经 {age} 天没有提交"
    if age > 180:
        return 28, f"已经 {age} 天没有提交"
    if age > 90:
        return 16, f"最近一次提交在 {age} 天前"
    if age > 30:
        return 5, f"最近一次提交在 {age} 天前"
    return 0, ""


def _sparse_commit_penalty(count: int, window_days: int, baseline: Optional[float]) -> int:
    """提交稀疏度扣分，结合项目历史节奏：低频项目在窗口内提交少是正常的。"""
    if count == 0:
        if baseline is None:
            return 22
        expected = baseline * window_days / 7.0
        if expected >= 6:
            return 22
        if expected >= 2:
            return 12
        return 4
    if count <= 2:
        if baseline is not None and baseline * window_days / 7.0 <= 2:
            return 0
        return 12
    if count < 10:
        return 4
    return 0


def _release_stats(
    repo: Optional[RepoSignals], package: Optional[PackageInfo], now: datetime
) -> Optional[dict]:
    if repo is not None and repo.releases is not None and repo.releases.total_fetched:
        rel: ReleaseSignals = repo.releases
        return {
            "last_age_days": rel.last_release_age_days,
            "last_at": rel.last_release_at,
            "releases_365d": rel.releases_365d,
            "releases_window": rel.releases_window,
            "source": "github",
        }
    if package is not None and package.release_dates:
        dates = package.release_dates
        last = dates[-1]
        return {
            "last_age_days": max(0, int((now - last).total_seconds() // 86400)),
            "last_at": last,
            "releases_365d": len([d for d in dates if (now - d).total_seconds() <= 365 * 86400]),
            "releases_window": len([d for d in dates if (now - d).total_seconds() <= 90 * 86400]),
            "source": "package",
        }
    return None


def analyze(
    repo: Optional[RepoSignals],
    package: Optional[PackageInfo],
    now: datetime,
) -> Dimension:
    dim = Dimension(
        key="maintenance",
        title="维护活跃度",
        weight=WEIGHTS["maintenance"],
        score=100,
        metrics={},
        evidence=[],
    )
    if repo is None and package is None:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("缺少仓库与包元数据，无法评估维护活跃度")
        return dim

    if repo is None:
        return _analyze_package_only(dim, package, now)

    commits = repo.commits
    evidence = dim.evidence
    metrics = dim.metrics

    if repo.archived:
        dim.add(35, "仓库已归档（archived），官方停止维护")
    if repo.disabled:
        dim.add(45, "仓库已被 GitHub 禁用")
    if package is not None and package.deprecated:
        dim.add(30, "包已被标记为废弃（deprecated）")

    substantive_ratio: Optional[float] = None
    if commits is not None:
        human = commits.human_count
        chore = commits.chore_human_count
        substantive = commits.substantive_human_count
        if human:
            substantive_ratio = substantive / human
        metrics.update(
            {
                "commits_window": commits.count_window,
                "human_commits": human,
                "bot_commits": commits.bot_count,
                "substantive_human_commits": substantive,
                "chore_human_commits": chore,
                "unique_human_authors": commits.unique_human_authors,
                "top_author_share": commits.top_author_share,
                "last_commit_age_days": commits.last_commit_age_days,
                "active_weeks": commits.active_weeks,
                "baseline_commits_per_week": commits.baseline_commits_per_week,
                "recent_commits_per_week": commits.recent_commits_per_week,
                "activity_trend": commits.activity_trend,
            }
        )
        count_label = "≥" if not commits.count_is_exact and commits.count_window >= 100 else ""
        evidence.append(
            f"近 {commits.window_days} 天提交 {count_label}{commits.count_window} 次"
            f"（真人 {human} / 机器人 {commits.bot_count}）"
        )
        if human:
            evidence.append(
                f"真人提交中功能/修复类 {substantive} 次、CI/依赖类 {chore} 次；"
                f"真人贡献者 {commits.unique_human_authors} 人，最大贡献者占 {fmt_pct(commits.top_author_share * 100)}"
            )
        evidence.append(
            f"最近提交：{fmt_date(commits.last_commit_at)}"
            + (f"（{fmt_ago(commits.last_commit_at, now)}）" if commits.last_commit_at else "")
        )
        if commits.weekly_counts:
            evidence.append(f"近 13 周中有 {commits.active_weeks} 周存在提交")

        baseline = commits.baseline_commits_per_week
        age = commits.last_commit_age_days
        if age is None:
            dim.add(25, "无法获取最近的提交时间")
        else:
            points, reason = _staleness_penalty(age)
            if points and baseline is not None and baseline > 0.05:
                # 相对「项目自身节奏」放宽：低频但稳定（如每年几次）的项目不该被判为停摆
                expected_gap = 7.0 / baseline
                allowed = max(expected_gap * 3.0, 45.0)
                ratio = age / allowed
                if ratio <= 1.0:
                    dim.notes.append(
                        f"最近提交在 {age} 天前，但该项目历史节奏约每 {expected_gap:.0f} 天一次提交，"
                        "属于低频但稳定，不视为停摆"
                    )
                    points = 0
                elif ratio <= 2.0:
                    points = int(points * 0.5)
            if points:
                dim.add(points, reason)

        sparse_points = _sparse_commit_penalty(commits.count_window, commits.window_days, baseline)
        if sparse_points:
            if commits.count_window == 0:
                dim.add(sparse_points, f"近 {commits.window_days} 天没有任何提交")
            elif commits.count_window <= 2:
                dim.add(sparse_points, f"近 {commits.window_days} 天只有 {commits.count_window} 次提交")
            else:
                dim.add(sparse_points, f"近 {commits.window_days} 天提交较少（{commits.count_window} 次）")

        # 活跃度断崖：最近 13 周 vs 之前 39 周（同一项目的自身基线）
        trend = commits.activity_trend
        if trend is not None and baseline is not None and baseline >= 0.5:
            if trend < ACTIVITY_DECLINE_BAD_RATIO:
                dim.add(
                    14,
                    f"提交节奏断崖：近 90 天为历史节奏的 {trend * 100:.0f}%"
                    f"（历史约 {baseline:.1f} 次/周）",
                )
            elif trend < ACTIVITY_DECLINE_WARN_RATIO:
                dim.add(
                    6,
                    f"提交节奏明显放缓：近 90 天为历史节奏的 {trend * 100:.0f}%"
                    f"（历史约 {baseline:.1f} 次/周）",
                )

        # 只有机器人 / 真人只在做运维
        if human == 0 and commits.bot_count > 0:
            dim.add(18, "近 90 天没有真人提交，只有机器人自动更新")
        elif human > 0 and substantive == 0 and chore > 0:
            dim.add(12, "近 90 天真人的提交全是 CI/依赖类维护，没有功能开发或缺陷修复")
            evidence.append("⚠ 真人提交全部是 CI / 依赖类维护，代码本身没有实质变化")
        if commits.bot_share > 0.8 and commits.bot_count >= 5:
            dim.add(6, f"提交中机器人占比 {fmt_pct(commits.bot_share * 100)}")
        if commits.unique_human_authors == 1 and human >= 3:
            dim.add(8, "近 90 天只有 1 位真人维护者（bus factor 风险）")
        if commits.top_author_share >= 0.9 and commits.unique_human_authors >= 2:
            dim.add(5, "单一贡献者占比过高（≥90%）")
        if commits.weekly_counts:
            if commits.active_weeks <= 2:
                dim.add(10, "近 13 周只有 ≤2 周有提交")
            elif commits.active_weeks <= 5:
                dim.add(4, "近 13 周只有 ≤5 周有提交")
    else:
        dim.add(25, "无法获取提交数据")

    # 发布节奏
    stats = _release_stats(repo, package, now)
    if stats:
        metrics.update(
            {
                "releases_window": stats["releases_window"],
                "releases_365d": stats["releases_365d"],
                "last_release_age_days": stats["last_age_days"],
            }
        )
        last_at = stats["last_at"]
        label = "最近发布" if stats["source"] == "github" else "最近发布（包元数据）"
        evidence.append(
            f"{label}：{fmt_date(last_at)}"
            + (f"（{fmt_ago(last_at, now)}）" if last_at else "")
            + f"，近一年 {stats['releases_365d']} 次"
        )
        age = stats["last_age_days"]
        if age is not None:
            if age > 730:
                dim.add(18, f"超过 {age // 365} 年没有新版本发布")
            elif age > 365:
                dim.add(10, "超过 1 年没有新版本发布")
        if stats["releases_365d"] == 0 and stats["releases_window"] == 0:
            dim.add(5, "过去一年没有发布新版本")
        rel = repo.releases
        if rel is not None and rel.cadence_cliff and (rel.last_release_age_days or 0) <= 540:
            dim.add(
                10,
                f"发布节奏断崖：前一个 90 天发布 {rel.releases_prev_90d} 次，近 90 天仅 {rel.releases_window} 次",
            )
    else:
        evidence.append("没有可用的发布记录")

    # 社区温度：star 增长是否停滞（高 star/fork 但近期没有新增）
    if repo.star_growth_stalled:
        recent = repo.stars_recent_90d if repo.stars_recent_90d is not None else 0
        dim.add(
            8,
            f"社区热度停滞：{fmt_human_int(repo.stars)} star / {fmt_human_int(repo.forks)} fork，"
            f"但近 3 个月仅新增约 {recent} 个 star",
        )
        dim.evidence.append(
            f"star 增速：近期约 {repo.star_velocity_recent_month or 0:.1f} 个/月，"
            f"历史平均约 {repo.star_velocity_lifetime_month or 0:.1f} 个/月"
        )
    metrics["stars_recent_90d"] = repo.stars_recent_90d
    metrics["star_velocity_recent_month"] = repo.star_velocity_recent_month
    metrics["star_velocity_lifetime_month"] = repo.star_velocity_lifetime_month

    metrics["stars"] = repo.stars
    metrics["archived"] = repo.archived
    evidence.append(
        f"仓库 {fmt_human_int(repo.stars)} stars · {fmt_human_int(repo.forks)} forks"
        + (" · 已归档" if repo.archived else "")
    )

    # 运维碎片化的说明（不额外扣分，避免与「只有运维提交」重复扣分）
    if substantive_ratio is not None and 0 < substantive_ratio <= 0.3:
        dim.notes.append(
            f"真人提交中只有 {fmt_pct(substantive_ratio * 100)} 属于功能/修复，其余为 CI、依赖等运维改动"
        )
    dim.clamp()
    dim.status = dim.score_status()
    return dim


def _analyze_package_only(dim: Dimension, package: Optional[PackageInfo], now: datetime) -> Dimension:
    """没有 GitHub 数据时，仅根据发布记录做一个保守的局部评估。"""
    dim.notes.append("没有 GitHub 仓库数据，仅根据发布记录评估")
    stats = _release_stats(None, package, now)
    if not stats:
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("没有任何发布记录")
        return dim
    dim.score = 80
    metrics = dim.metrics
    metrics.update(
        {
            "releases_365d": stats["releases_365d"],
            "releases_window": stats["releases_window"],
            "last_release_age_days": stats["last_age_days"],
        }
    )
    dim.evidence.append(
        f"最近发布：{fmt_date(stats['last_at'])}（{fmt_ago(stats['last_at'], now)}），"
        f"近一年 {stats['releases_365d']} 次"
    )
    age = stats["last_age_days"]
    if age is not None:
        if age > 730:
            dim.add(45, f"最近一次发布在 {fmt_ago(stats['last_at'], now)}（超过 2 年）")
        elif age > 365:
            dim.add(30, f"最近一次发布在 {fmt_ago(stats['last_at'], now)}（超过 1 年）")
        elif age > 180:
            dim.add(12, f"最近一次发布在 {fmt_ago(stats['last_at'], now)}")
    if stats["releases_365d"] == 0:
        dim.add(10, "过去一年没有任何新版本发布")
    if package is not None and package.deprecated:
        dim.add(30, "包已被标记为废弃（deprecated）")
    if package is not None:
        dim.evidence.append(f"发布版本数 {package.release_count}，其中 {len(package.release_dates)} 个有发布时间记录")
    dim.clamp()
    dim.status = "warn" if dim.score >= 50 else "bad"
    return dim
