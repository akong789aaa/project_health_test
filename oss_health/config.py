"""全局配置：维度权重、评分档位、阈值、机器人识别规则."""

from __future__ import annotations

TOOL_NAME = "oss-health"
TOOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# 维度权重（合计 100）。当某个维度缺少数据时，其余维度按权重重新归一。
# ---------------------------------------------------------------------------
WEIGHTS: dict[str, float] = {
    "maintenance": 20.0,   # 维护活跃度
    "issues": 22.0,        # Issue 响应
    "prs": 13.0,           # PR 健康
    "framework": 13.0,     # 运行时 / target framework
    "security": 20.0,      # 自身未修复漏洞
    "dependencies": 12.0,  # 直接依赖漏洞风险
}

DIMENSION_TITLES: dict[str, str] = {
    "maintenance": "维护活跃度",
    "issues": "Issue 响应",
    "prs": "PR 健康度",
    "framework": "运行时 / 框架",
    "security": "自身漏洞",
    "dependencies": "依赖安全",
}

# 评分档位 (最低分, 等级, 结论, 级别)
GRADE_TABLE: list[tuple[float, str, str, str]] = [
    (80.0, "A", "可以放心使用", "good"),
    (65.0, "B", "基本可用，注意跟踪", "good"),
    (50.0, "C", "谨慎使用，建议锁定版本", "caution"),
    (35.0, "D", "高风险，建议准备替代方案", "bad"),
    (0.0, "F", "不建议新项目使用，尽快迁移", "bad"),
]

# 一票否决 / 硬性封顶：触发后总分不会高于 cap
HARD_CAPS: dict[str, float] = {
    "archived": 35.0,          # 仓库已归档
    "deprecated": 35.0,        # 包已被标记废弃 / 弃用
    "critical_cve": 40.0,      # 当前版本存在未修复的严重漏洞
    "no_human_maintainer": 45.0,  # 近 90 天没有任何真人维护者活动
    "disabled": 25.0,          # 仓库被禁用
}

# ---------------------------------------------------------------------------
# 机器人识别
# ---------------------------------------------------------------------------
# GitHub API 会给出 user.type == "Bot"，但一部分自动化账号是 User 类型，需要额外规则。
BOT_LOGIN_SUFFIXES = ("[bot]", "-bot", "_bot")
BOT_LOGIN_EXACT = {
    "dependabot",
    "dependabot-preview",
    "renovate",
    "renovate-bot",
    "github-actions",
    "github-actions[bot]",
    "pre-commit-ci",
    "pre-commit-ci[bot]",
    "codecov",
    "codecov[bot]",
    "mergify",
    "mergify[bot]",
    "sourcery-ai",
    "sourcery-ai[bot]",
    "imgbot",
    "imgbot[bot]",
    "allcontributors",
    "allcontributors[bot]",
    "greenkeeper",
    "greenkeeper[bot]",
    "depfu",
    "depfu[bot]",
    "snyk-bot",
    "snyk-bot[bot]",
    "whitesource-bolt",
}
BOT_NAME_HINTS = (
    "bot",
    "automation",
    "autobot",
    "ci-bot",
    "release-please",
    "github-actions",
    "dependabot",
    "renovate",
)
# GitHub 网页端合并时出现的 committer，既不是机器人也不是真人作者，做身份判断时忽略
BOT_NAME_ALLOW = {"web-flow"}

MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}

# ---------------------------------------------------------------------------
# 阈值（天 / 小时 / 比例）
# ---------------------------------------------------------------------------
DEFAULT_WINDOW_DAYS = 90
DEFAULT_CACHE_TTL_HOURS = 6.0
DEFAULT_PR_DETAIL = 5
DEFAULT_DEP_CHECK = 10
STALE_COMMIT_DAYS = 180
STALE_RELEASE_DAYS = 365
SLOW_RESPONSE_HOURS = 24 * 14
# 大仓库每天几十条 Issue，维护者不可能每条都回；低于这个「有效回复量」视为响应不足
MIN_EFFECTIVE_MAINTAINER_REPLIES = 3
# ---- 社区温度 / 发布节奏（「活死人」判定） ----
BUG_LABEL_MARKERS = (
    "bug",
    "crash",
    "regression",
    "defect",
    "security",
    "critical",
    "broken",
    "data loss",
)
LONG_OPEN_BUG_DAYS = 180           # 带 bug 标签开放超过这个天数视为「长期未修」
STAR_STALL_MIN_STARS = 300         # star 太少时不做「增长停滞」判断
STAR_STALL_MIN_FORKS = 50          # fork 数多但 star 停滞的判定门槛
STAR_STALL_RECENT_MONTHS = 3.0     # 近 N 个月 star 增速
RELEASE_CLIFF_MIN_PREV = 2         # 前 90 天至少发布过几次才判断「断崖」
ACTIVITY_DECLINE_WARN_RATIO = 0.5  # 提交节奏较历史基线下降超过一半 → 提示下滑
ACTIVITY_DECLINE_BAD_RATIO = 0.25  # 下降到 1/4 以下 → 断崖
CHORE_COMMIT_MARKERS = (
    "bump",
    "chore(deps)",
    "dependabot",
    "renovate",
    "lock-issues",
    "pre-commit",
    "ci:",
    "[ci skip]",
    "update lockfile",
    "update pre-commit",
)

# 运行时支持周期数据源（endoflife.date）。产品名 -> 展示名
EOL_PRODUCTS = {
    "python": "Python",
    "nodejs": "Node.js",
    "dotnet": ".NET",
}
# 生态 -> 运行时产品
ECOSYSTEM_RUNTIME = {
    "pypi": "python",
    "npm": "nodejs",
    "nuget": "dotnet",
}
# 生态在 OSV 中的名称
OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "nuget": "NuGet",
}

USER_AGENT = f"{TOOL_NAME}/{TOOL_VERSION} (+https://github.com/oss-health/oss-health)"
