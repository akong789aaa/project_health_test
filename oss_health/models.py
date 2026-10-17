"""数据模型：所有数据源统一成这些结构，分析器与渲染器只依赖它们。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

ECOSYSTEMS = ("pypi", "npm", "nuget", "github")


# ---------------------------------------------------------------------------
# 扫描目标
# ---------------------------------------------------------------------------


@dataclass
class Target:
    """扫描目标。ecosystem 为 pypi/npm/nuget 时 name 是包名；github 时是 owner/repo。"""

    ecosystem: str
    name: str
    version: Optional[str] = None        # 指定版本（默认最新版）
    repo_override: Optional[str] = None  # owner/repo，覆盖包元数据里的仓库地址
    raw_input: str = ""

    @property
    def is_package(self) -> bool:
        return self.ecosystem in ("pypi", "npm", "nuget")

    @property
    def repo_slug(self) -> Optional[str]:
        if self.repo_override:
            return self.repo_override
        return self.name if self.ecosystem == "github" else None

    def display(self) -> str:
        if self.ecosystem == "github":
            return f"github:{self.name}"
        if self.version:
            return f"{self.ecosystem}:{self.name}@{self.version}"
        return f"{self.ecosystem}:{self.name}"


# ---------------------------------------------------------------------------
# 包元数据
# ---------------------------------------------------------------------------


@dataclass
class Dependency:
    name: str
    spec: str = ""          # 版本约束原样，如 ">=1.26,<3" / "^4.0.0" / "[13.0.1, )"
    kind: str = "runtime"   # runtime / extra
    ecosystem: str = ""     # pypi / npm / nuget


@dataclass
class PackageInfo:
    ecosystem: str
    name: str
    version: str
    latest_version: str
    published_at: Optional[datetime] = None
    release_count: int = 0
    summary: str = ""
    homepage: str = ""
    repo_url: str = ""
    license: str = ""
    deprecated: bool = False
    deprecation_message: str = ""
    requires_python: str = ""
    python_versions: list[str] = field(default_factory=list)  # ["3.10", "3.11", ...]
    node_engines: str = ""                                     # ">= 18"
    node_versions: list[int] = field(default_factory=list)     # [18, 20, ...]
    target_frameworks: list[str] = field(default_factory=list) # ["netstandard2.0", ...]
    dependencies: list[Dependency] = field(default_factory=list)
    release_dates: list[datetime] = field(default_factory=list)  # 升序
    yanked: bool = False
    source: str = ""        # 元数据来源 URL
    extra: dict[str, Any] = field(default_factory=dict)

    def age_days(self, now: datetime) -> Optional[int]:
        if not self.published_at:
            return None
        return max(0, int((now - self.published_at).total_seconds() // 86400))


# ---------------------------------------------------------------------------
# GitHub 仓库信号
# ---------------------------------------------------------------------------


@dataclass
class CommitSignals:
    window_days: int = 90
    count_window: int = 0          # 窗口内提交总数（可能来自 stats，精确）
    sample_size: int = 0           # 实际取到的提交样本数
    human_count: int = 0
    bot_count: int = 0
    unique_human_authors: int = 0
    top_author_share: float = 0.0  # 最大贡献者占比（bus factor 代理指标）
    last_commit_at: Optional[datetime] = None
    last_commit_age_days: Optional[int] = None
    weekly_counts: list[int] = field(default_factory=list)  # 最近 13 周
    active_weeks: int = 0
    count_is_exact: bool = False
    chore_human_count: int = 0     # 真人提交中的 CI / 依赖 / 构建类维护提交
    substantive_human_count: int = 0  # 真人提交中的功能 / 修复类提交
    # 项目自身节奏基线（GitHub /stats/participation 的 52 周数据）
    baseline_weekly: list[int] = field(default_factory=list)   # 最近 52 周每周提交数（升序）
    baseline_commits_per_week: Optional[float] = None          # 之前 39 周的周均提交（历史节奏）
    recent_commits_per_week: Optional[float] = None            # 最近 13 周的周均提交
    activity_trend: Optional[float] = None                     # 最近 13 周 / 之前 39 周（1.0=持平）
    warnings: list[str] = field(default_factory=list)

    @property
    def bot_share(self) -> float:
        total = self.human_count + self.bot_count
        return self.bot_count / total if total else 0.0


@dataclass
class IssueSignals:
    window_days: int = 90
    sampled: int = 0                    # 窗口内更新过的 issue 采样数
    created_window: int = 0            # 其中窗口内新建的
    closed_window: int = 0
    maintainer_replied_count: int = 0  # 窗口内获得维护者回复的 issue 数
    human_replied_count: int = 0       # 窗口内获得真人（非机器人、非作者）回复的
    bot_comment_share: float = 0.0
    human_comment_count: int = 0
    bot_comment_count: int = 0
    median_first_human_response_hours: Optional[float] = None
    median_maintainer_response_hours: Optional[float] = None
    unanswered_open_count: int = 0     # 采样里开放且无人回复
    open_count: int = 0
    maintainer_activity: bool = False  # 窗口内是否有任何真人维护者发言/提交
    opened_window: int = 0             # 窗口内新开（created）的 Issue 数
    closed_by_maintainer_window: int = 0  # 窗口内由维护者关闭的 Issue 数
    bug_labeled_count: int = 0         # 采样中带 bug/崩溃/回归等标签的 Issue 数
    long_open_bugs: int = 0            # 开放超过半年、带 bug 标签且无人回复的 Issue 数
    sample_truncated: bool = False
    issues_disabled: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def maintainer_reply_ratio(self) -> Optional[float]:
        """窗口内新建 issue 中得到维护者回复的比例。"""
        if not self.created_window:
            return None
        return min(1.0, self.maintainer_replied_count / max(1, self.created_window))


@dataclass
class PullSignals:
    window_days: int = 90
    sampled: int = 0
    created_window: int = 0
    human_created_window: int = 0      # 窗口内真人新开的 PR
    merged_window: int = 0
    closed_unmerged_window: int = 0
    human_closed_unmerged_window: int = 0  # 窗口内被真人（维护者）关闭、未合并的 PR
    open_window: int = 0
    stale_open_count: int = 0          # 创建早于窗口仍未合并
    bot_pr_count: int = 0
    human_pr_count: int = 0
    auto_merge_prs: int = 0            # 开启 auto-merge 的 PR 数
    median_merge_hours: Optional[float] = None
    human_median_merge_hours: Optional[float] = None  # 真人提交的 PR 从创建到合并的中位数
    merged_samples: int = 0            # 抽查了合并者的已合并 PR 数
    bot_merged_samples: int = 0
    human_merged_samples: int = 0
    detail_truncated: bool = False
    sample_truncated: bool = False
    bot_pr_share: float = 0.0
    merge_rate: Optional[float] = None
    bot_merge_share: Optional[float] = None
    sample_details: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ReleaseSignals:
    last_release_at: Optional[datetime] = None
    last_release_age_days: Optional[int] = None
    releases_window: int = 0
    releases_365d: int = 0
    releases_prev_90d: int = 0            # 前一个 90 天窗口内的发布数
    release_trend: Optional[float] = None  # 近 90 天 / 前 90 天发布数（断崖判定）
    cadence_cliff: bool = False           # 发布节奏是否断崖
    total_fetched: int = 0
    prerelease_only: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class RepoSignals:
    owner: str
    name: str
    url: str = ""
    archived: bool = False
    disabled: bool = False
    is_fork: bool = False
    stars: int = 0
    forks: int = 0
    open_issues_and_prs: int = 0
    pushed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    default_branch: str = "main"
    license_spdx: str = ""
    topics: list[str] = field(default_factory=list)
    commits: Optional[CommitSignals] = None
    issues: Optional[IssueSignals] = None
    prs: Optional[PullSignals] = None
    releases: Optional[ReleaseSignals] = None
    # 社区温度：star 增长趋势（对最新 100 个 star 采样）
    stars_recent_90d: Optional[int] = None     # 最新 100 个 star 中 90 天内新增数
    stars_recent_capped: bool = False          # 100 个都在 90 天内（实际更多）
    star_velocity_recent_month: Optional[float] = None   # 近 3 个月 star/月
    star_velocity_lifetime_month: Optional[float] = None # 历史平均 star/月
    star_growth_stalled: bool = False          # 高 star/fork 但近期 star 增长停滞
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False
    fetched_at: Optional[datetime] = None

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


# ---------------------------------------------------------------------------
# 运行时 / target framework 评估
# ---------------------------------------------------------------------------


@dataclass
class FrameworkAssessment:
    runtime: str = ""             # Python / Node.js / .NET / 未知
    status: str = "unknown"       # current / lagging / eol / unknown
    score: int = 55
    declared: list[str] = field(default_factory=list)
    latest_supported: str = ""
    eol_declared: list[str] = field(default_factory=list)
    supported_cycles: list[str] = field(default_factory=list)
    gap: Optional[int] = None     # 落后当前最新运行时几个版本
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 安全
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1, "NONE": 0}


@dataclass
class Vulnerability:
    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    severity: str = "UNKNOWN"     # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    affects_current: bool = True
    fixed_versions: list[str] = field(default_factory=list)
    url: str = ""
    ecosystem: str = ""

    @property
    def cve(self) -> Optional[str]:
        for a in self.aliases:
            if a.upper().startswith("CVE-"):
                return a
        if self.id.upper().startswith("CVE-"):
            return self.id
        return None

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 1)

    @property
    def best_fix_version(self) -> Optional[str]:
        if not self.fixed_versions:
            return None
        return self.fixed_versions[0]


@dataclass
class DependencyRisk:
    name: str
    ecosystem: str = ""
    spec: str = ""
    checked_version: str = ""
    vulns: list[Vulnerability] = field(default_factory=list)
    error: str = ""

    @property
    def max_severity(self) -> str:
        if not self.vulns:
            return "NONE"
        order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}
        return max((v.severity for v in self.vulns), key=lambda s: order.get(s, 1))


@dataclass
class SecuritySignals:
    ecosystem: str
    package: str
    version: str
    vulns_current: list[Vulnerability] = field(default_factory=list)  # 影响当前版本（未修复）
    history_count: int = 0                                             # 历史公告总数（含已修复）
    fixed_count: int = 0                                               # 已在新版本修复
    deps_checked: int = 0
    deps_total: int = 0
    dep_risks: list[DependencyRisk] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    db_available: bool = True

    # ---- 统计辅助 ----
    def count(self, severity: str) -> int:
        return sum(1 for v in self.vulns_current if v.severity == severity)

    @property
    def critical_high(self) -> list[Vulnerability]:
        return [v for v in self.vulns_current if v.severity in ("CRITICAL", "HIGH")]

    @property
    def max_severity(self) -> str:
        if not self.vulns_current:
            return "NONE"
        rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}
        return max((v.severity for v in self.vulns_current), key=lambda s: rank.get(s, 1))

    @property
    def dep_vulns(self) -> list[tuple[DependencyRisk, Vulnerability]]:
        out: list[tuple[DependencyRisk, Vulnerability]] = []
        for risk in self.dep_risks:
            for v in risk.vulns:
                out.append((risk, v))
        return out

    def dep_count(self, severities: tuple[str, ...]) -> int:
        return sum(1 for _, v in self.dep_vulns if v.severity in severities)


# ---------------------------------------------------------------------------
# 评分维度 / 最终报告
# ---------------------------------------------------------------------------


@dataclass
class Deduction:
    points: int
    reason: str


@dataclass
class Dimension:
    key: str
    title: str
    weight: float
    score: int
    status: str = "unknown"    # good / warn / bad / unknown
    available: bool = True     # False 表示数据缺失，不参与加权
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    deductions: list[Deduction] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.deductions.append(Deduction(max(0, int(points)), reason))
        self.score = max(0, self.score - max(0, int(points)))

    def clamp(self, low: int = 0, high: int = 100) -> None:
        self.score = max(low, min(high, int(self.score)))

    def score_status(self, good: int = 75, warn: int = 50) -> str:
        if not self.available:
            return "unknown"
        if self.score >= good:
            return "good"
        if self.score >= warn:
            return "warn"
        return "bad"


@dataclass
class HardFlag:
    key: str
    cap: float
    reason: str


@dataclass
class SourceRecord:
    name: str
    url: str = ""
    retrieved_at: Optional[datetime] = None
    ok: bool = True
    note: str = ""


@dataclass
class ScanReport:
    input: str
    target: Target
    generated_at: datetime
    package: Optional[PackageInfo] = None
    repo: Optional[RepoSignals] = None
    framework: Optional[FrameworkAssessment] = None
    security: Optional[SecuritySignals] = None
    dep_risks: list[Any] = field(default_factory=list)
    dimensions: list[Dimension] = field(default_factory=list)
    raw_total: float = 0.0
    total_score: float = 0.0
    grade: str = "F"
    verdict: str = ""
    verdict_level: str = "bad"
    confidence: str = "low"
    confidence_reasons: list[str] = field(default_factory=list)
    hard_flags: list[HardFlag] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sources: list[SourceRecord] = field(default_factory=list)
    tool_version: str = ""
    offline: bool = False
    duration_seconds: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    def dimension(self, key: str) -> Optional[Dimension]:
        for d in self.dimensions:
            if d.key == key:
                return d
        return None

    @property
    def score_int(self) -> int:
        return int(round(self.total_score))
