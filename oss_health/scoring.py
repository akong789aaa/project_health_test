"""评分模型：维度加权 + 一票否决封顶 + 等级 / 结论 / 置信度 / 行动建议。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .config import (
    DIMENSION_TITLES,
    GRADE_TABLE,
    HARD_CAPS,
    WEIGHTS,
)
from .cvss import score_to_grade_zh
from .models import (
    Dimension,
    HardFlag,
    PackageInfo,
    RepoSignals,
    SecuritySignals,
    Vulnerability,
)
from .util import fmt_days


@dataclass
class ScoreResult:
    raw_total: float = 0.0
    total_score: float = 0.0
    grade: str = "F"
    verdict: str = ""
    verdict_level: str = "bad"
    hard_flags: list[HardFlag] = field(default_factory=list)
    confidence: str = "low"
    confidence_reasons: list[str] = field(default_factory=list)


def grade_for(score: float) -> tuple[str, str, str]:
    for threshold, grade, verdict, level in GRADE_TABLE:
        if score >= threshold:
            return grade, verdict, level
    threshold, grade, verdict, level = GRADE_TABLE[-1]
    return grade, verdict, level


def compute(
    dimensions: list[Dimension],
    *,
    repo: Optional[RepoSignals],
    package: Optional[PackageInfo],
    security: Optional[SecuritySignals],
) -> ScoreResult:
    result = ScoreResult()
    available = [d for d in dimensions if d.available]
    if not available:
        raise ValueError("没有任何可用维度，无法评分")
    weight_sum = sum(d.weight for d in available)
    raw = sum(d.score * d.weight for d in available) / weight_sum if weight_sum else 0.0
    result.raw_total = round(raw, 1)

    flags = _hard_flags(repo, package, security, dimensions)
    result.hard_flags = flags
    total = result.raw_total
    for flag in flags:
        total = min(total, flag.cap)
    result.total_score = round(total, 1)

    result.grade, result.verdict, result.verdict_level = grade_for(result.total_score)
    result.confidence, result.confidence_reasons = _confidence(
        dimensions, available, repo, package, security
    )
    return result


def _hard_flags(
    repo: Optional[RepoSignals],
    package: Optional[PackageInfo],
    security: Optional[SecuritySignals],
    dimensions: Optional[list[Dimension]] = None,
) -> list[HardFlag]:
    flags: list[HardFlag] = []
    if repo is not None:
        if repo.archived:
            flags.append(
                HardFlag(
                    key="archived",
                    cap=HARD_CAPS["archived"],
                    reason="仓库已归档（archived），官方已停止维护",
                )
            )
        if repo.disabled:
            flags.append(
                HardFlag(
                    key="disabled",
                    cap=HARD_CAPS["disabled"],
                    reason="仓库已被 GitHub 禁用",
                )
            )
    if package is not None and package.deprecated:
        msg = package.deprecation_message or "维护者已将包标记为废弃（deprecated）"
        flags.append(HardFlag(key="deprecated", cap=HARD_CAPS["deprecated"], reason=msg))

    if security is not None and security.db_available:
        criticals = [v for v in security.vulns_current if v.severity == "CRITICAL"]
        if criticals:
            top = max(criticals, key=lambda v: v.cvss_score or 0)
            flags.append(
                HardFlag(
                    key="critical_cve",
                    cap=HARD_CAPS["critical_cve"],
                    reason=f"当前版本存在未修复的严重漏洞 {top.cve or top.id}"
                    + (f"（CVSS {top.cvss_score:.1f}）" if top.cvss_score else ""),
                )
            )

    if repo is not None and _no_human_activity(repo, dimensions):
        flags.append(
            HardFlag(
                key="no_human_maintainer",
                cap=HARD_CAPS["no_human_maintainer"],
                reason="近 90 天没有任何可观测的真人维护者活动（真人提交 / 维护者回复或关闭 Issue / 合并或关闭 PR）",
            )
        )
    return flags


def _no_human_activity(repo: RepoSignals, dimensions: Optional[list[Dimension]] = None) -> bool:
    """判断近 90 天是否完全看不到真人维护者的痕迹。

    「真人打开 Issue / 提交 PR」不算维护者活动（任何人都能开），
    必须是有真人维护者**回应 / 处理**过的证据。
    """
    data_present = False
    if repo.commits is not None and repo.commits.sample_size:
        data_present = True
        if repo.commits.human_count > 0:
            # 真人提交里是否有功能/修复（只有 CI/依赖类也算维护，因此这里都算）
            return False
    if repo.issues is not None and repo.issues.sampled:
        data_present = True
        if (
            repo.issues.maintainer_replied_count > 0
            or repo.issues.closed_by_maintainer_window > 0
        ):
            return False
    if repo.prs is not None and repo.prs.sampled:
        data_present = True
        if repo.prs.merged_window > 0 or repo.prs.human_closed_unmerged_window > 0:
            return False
    return data_present


def _confidence(
    dimensions: list[Dimension],
    available: list[Dimension],
    repo: Optional[RepoSignals],
    package: Optional[PackageInfo],
    security: Optional[SecuritySignals],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    missing = [d for d in dimensions if not d.available]
    for dim in missing:
        if dim.notes:
            reasons.append(f"{dim.title}：{dim.notes[0]}")

    level = "high"
    if package is None:
        level = "low"
        reasons.append("缺少包元数据：无法评估漏洞、依赖与运行时支持")
    if repo is None:
        if level == "high":
            level = "medium"
        reasons.append("缺少 GitHub 数据：维护活跃度、Issue、PR 维度覆盖有限")
    if security is None or not security.db_available:
        level = "low"
        reasons.append("漏洞数据库不可用，安全结论不完整")
    if len(missing) >= 3:
        level = "low"
    elif len(missing) >= 1 and level == "high":
        level = "medium"

    if repo is not None:
        if repo.warnings:
            level = "medium" if level == "high" else level
            reasons.append("GitHub 采集存在降级：" + repo.warnings[0])
        if repo.truncated:
            level = "medium" if level == "high" else level
            reasons.append("GitHub 请求被限流，部分数据缺失（建议配置 GITHUB_TOKEN）")
        if repo.issues is not None and repo.issues.sample_truncated:
            reasons.append("Issue 数据基于最近 100 条采样")
        if repo.prs is not None and repo.prs.sample_truncated:
            reasons.append("PR 数据基于最近 100 条采样")
        if repo.prs is not None and repo.prs.merged_samples:
            reasons.append(
                f"PR 合并者仅抽查 {repo.prs.merged_samples} 个已合并 PR"
            )
    if package is not None and security is not None and security.db_available:
        reasons.append("漏洞数据来自 OSV.dev（覆盖 GHSA / CVE / PyPA 等公告）")
    if level == "high":
        reasons.insert(0, "包元数据 + GitHub 活动 + 漏洞库均可用，数据覆盖完整")
    return level, reasons


# ---------------------------------------------------------------------------
# 行动建议
# ---------------------------------------------------------------------------


def _top_vulns(vulns: list[Vulnerability], limit: int = 3) -> list[Vulnerability]:
    return sorted(vulns, key=lambda v: (-v.severity_rank, -(v.cvss_score or 0)))[:limit]


def build_recommendations(
    dimensions: list[Dimension],
    *,
    repo: Optional[RepoSignals],
    package: Optional[PackageInfo],
    security: Optional[SecuritySignals],
    framework,
    dep_risks: list,
    result: ScoreResult,
) -> list[str]:
    recs: list[str] = []
    dim_by_key = {d.key: d for d in dimensions}

    # 1) 漏洞
    if security is not None and security.vulns_current:
        for vuln in _top_vulns(security.vulns_current):
            name = vuln.cve or vuln.id
            if vuln.best_fix_version:
                recs.append(
                    f"升级到 {package.name} {vuln.best_fix_version} 可修复 {name}"
                    f"（{score_to_grade_zh(vuln.severity)}，CVSS {vuln.cvss_score or '—'}）"
                )
            else:
                recs.append(
                    f"{name}（{score_to_grade_zh(vuln.severity)}）目前没有修复版本："
                    "隔离使用、加缓解措施，或评估替代包"
                )
        if len(recs) >= 3:
            recs.append("完整漏洞列表见报告「漏洞明细」一节，建议纳入依赖安全扫描（如 Dependabot / Renovate）")
    elif security is not None and security.history_count and not security.vulns_current:
        recs.append("当前版本没有已知未修复漏洞；保持版本更新，并订阅安全公告")

    # 2) 归档 / 废弃 / yank
    archived = repo is not None and repo.archived
    if archived:
        recs.append("项目已归档：新项目不要引入，存量项目建议制定迁移计划（或 fork 自行维护）")
    dep_flag = next((f for f in result.hard_flags if f.key == "deprecated"), None)
    if dep_flag is not None:
        recs.append(f"包已被标记废弃：{dep_flag.reason}；请迁移到仍在维护的替代包")
    if package is not None and package.yanked:
        recs.append(f"当前版本 {package.version} 已被 yank：尽快升级到最新可用版本 {package.latest_version}")

    # 3) Issue 响应
    issue_dim = dim_by_key.get("issues")
    if issue_dim is not None and issue_dim.available and issue_dim.score < 50:
        recs.append(
            "近 90 天维护者对 Issue 几乎无响应：遇到问题大概率只能自助，"
            "建议评估是否有商业支持或活跃的社区替代"
        )

    # 4) PR / 机器人合并
    if repo is not None and repo.prs is not None:
        prs = repo.prs
        human_bot_merged = [
            d for d in prs.sample_details
            if d.get("merged_by_is_bot") and d.get("author") and not _is_bot_login(d.get("author", ""), None)
        ]
        if human_bot_merged:
            recs.append(
                f"抽查发现 {len(human_bot_merged)} 个人类 PR 直接由机器人合并："
                "不要把自动合并等同于人工评审，升级前自行审查变更记录"
            )
        elif prs.merged_samples >= 2 and (prs.bot_merge_share or 0) >= 0.8:
            dim = dim_by_key.get("prs")
            if dim is not None and dim.score < 75:
                recs.append(
                    "抽查的合并 PR 以机器人为主：若这些只是依赖升级 PR 属正常自动化，"
                    "若涉及功能变更则建议人工复核 diff"
                )
        if prs.human_created_window == 0 and prs.bot_pr_count >= 3:
            recs.append("近期 PR 全部来自机器人，没有真人贡献，注意项目是否进入低维护期")

    # 5) 运行时 / 框架
    if framework is not None and framework.status in ("lagging", "eol"):
        detail = "；".join(framework.evidence[:2])
        recs.append(
            f"目标运行时落后（{framework.runtime or '未知运行时'}）：{detail}。"
            "建议升级 target framework / requires_python 下限，或评估是否被新版本运行时官方支持"
        )
    elif framework is not None and framework.status == "current" and framework.gap == 0:
        recs.append(f"运行时支持跟上了官方节奏（{framework.runtime} {framework.latest_supported}）")

    # 6) 依赖风险
    risky = [r for r in dep_risks if r.vulns]
    high_risky = [
        r for r in risky if any(v.severity in ("CRITICAL", "HIGH") for v in r.vulns)
    ]
    for risk in high_risky[:3]:
        worst = _top_vulns(risk.vulns, 1)[0]
        recs.append(
            f"直接依赖 {risk.name}@{risk.checked_version} 存在 "
            f"{score_to_grade_zh(worst.severity)}漏洞（{worst.cve or worst.id}），"
            "请升级/替换该依赖或等待上游修复"
        )

    # 7) 活死人信号：发布断崖 / 社区温度 / 长期未修的 bug
    if repo is not None and repo.releases is not None and repo.releases.cadence_cliff:
        rel = repo.releases
        recs.append(
            f"发布节奏断崖：前一个 90 天发布 {rel.releases_prev_90d} 次，近 90 天仅 {rel.releases_window} 次；"
            "确认是停止发版，还是改为 tag / CI 发布"
        )
    if repo is not None and repo.star_growth_stalled:
        recs.append(
            f"社区热度停滞：{repo.stars} star / {repo.forks} fork，但近 3 个月几乎无新增 star，"
            "关注项目是否进入「活死人」状态"
        )
    issue_dim = dim_by_key.get("issues")
    if issue_dim is not None and issue_dim.metrics.get("long_open_bugs"):
        recs.append(
            f"存在 {issue_dim.metrics['long_open_bugs']} 个超过半年无人回复的 bug Issue："
            "关键缺陷可能长期不修，建议逐一核查自己依赖的场景"
        )

    # 8) 整体结论
    if result.total_score >= 80:
        recs.append("整体判断：可以正常使用；建议锁定主版本并持续跟踪 Release / 安全公告")
    elif result.total_score >= 65:
        recs.append("整体判断：可以使用，但引入前建议验证关键路径，并跟踪维护状态变化")
    elif result.total_score >= 50:
        recs.append("整体判断：谨慎使用；建议锁定精确版本、补测试、准备替代方案")
    else:
        recs.append("整体判断：不建议在新项目中引入；存量使用需尽快制定迁移或自维护计划")
    return recs[:8]


def _is_bot_login(login: str, user_type) -> bool:
    from .heuristics import is_bot_login

    return is_bot_login(login, user_type)


def confidence_label(level: str) -> str:
    return {"high": "高", "medium": "中", "low": "低"}.get(level, level)
