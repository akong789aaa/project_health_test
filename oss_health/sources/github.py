"""GitHub REST API 数据源：提交、Issue、评论、PR、Release。

在**无 Token**（60 次/小时）的约束下做了采样与降级：

* 提交列表每页 100 条，若被截断则用 ``/stats/participation`` 拿精确的 13 周提交数（+1 次请求）；
* Issue / 评论 / PR 各取最近 100 条（按时间倒序），报告里会标注采样；
* PR 合并者只抽查少量已合并 PR（默认 5 个），探测「是不是机器人合的」；
* 任何一步遇到限流都会降级并记录 warning，而不是整份报告失败。
"""

from __future__ import annotations

import re
import time
import urllib.parse
from datetime import datetime, timedelta
from typing import Any, Optional

from ..config import (
    BUG_LABEL_MARKERS,
    CHORE_COMMIT_MARKERS,
    DEFAULT_PR_DETAIL,
    DEFAULT_WINDOW_DAYS,
    LONG_OPEN_BUG_DAYS,
    MAINTAINER_ASSOCIATIONS,
    RELEASE_CLIFF_MIN_PREV,
    STAR_STALL_MIN_FORKS,
    STAR_STALL_MIN_STARS,
    STAR_STALL_RECENT_MONTHS,
)
from ..heuristics import is_bot_user, is_maintainer
from ..http_client import HttpClient, HttpError, NotFound, RateLimited
from ..models import (
    CommitSignals,
    IssueSignals,
    PullSignals,
    ReleaseSignals,
    RepoSignals,
)
from ..util import (
    age_days,
    hours_between,
    median,
    parse_iso,
    parse_owner_repo,
    utcnow,
)

_ISSUE_NUM_RE = re.compile(r"/issues/(\d+)(?:$|[/?#])")


def _issue_number(url: str) -> Optional[int]:
    m = _ISSUE_NUM_RE.search(url or "")
    return int(m.group(1)) if m else None


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sample_evenly(items: list[Any], count: int) -> list[Any]:
    if count <= 0 or not items:
        return []
    if count >= len(items):
        return list(items)
    step = len(items) / float(count)
    picked: list[Any] = []
    for i in range(count):
        picked.append(items[min(len(items) - 1, int(i * step))])
    return picked


class GitHubSource:
    BASE = "https://api.github.com"

    def __init__(self, client: HttpClient):
        self.client = client
        self.budget_exhausted = False

    # ------------------------------------------------------------------
    # 对外入口
    # ------------------------------------------------------------------

    def fetch(
        self,
        slug: str,
        *,
        window_days: int = DEFAULT_WINDOW_DAYS,
        pr_detail: int = DEFAULT_PR_DETAIL,
        now: Optional[datetime] = None,
    ) -> RepoSignals:
        owner, name = parse_owner_repo(slug)
        now = now or utcnow()
        cutoff = now - timedelta(days=window_days)
        meta = self._api(f"/repos/{owner}/{name}")
        repo = RepoSignals(
            owner=str(meta.get("owner", {}).get("login") or owner),
            name=str(meta.get("name") or name),
            url=str(meta.get("html_url") or f"https://github.com/{owner}/{name}"),
            archived=bool(meta.get("archived")),
            disabled=bool(meta.get("disabled")),
            is_fork=bool(meta.get("fork")),
            stars=int(meta.get("stargazers_count") or 0),
            forks=int(meta.get("forks_count") or 0),
            open_issues_and_prs=int(meta.get("open_issues_count") or 0),
            pushed_at=parse_iso(meta.get("pushed_at")),
            created_at=parse_iso(meta.get("created_at")),
            default_branch=str(meta.get("default_branch") or "main"),
            topics=[str(t) for t in (meta.get("topics") or [])],
            fetched_at=now,
        )
        license_obj = meta.get("license") or {}
        if isinstance(license_obj, dict):
            repo.license_spdx = str(license_obj.get("spdx_id") or license_obj.get("name") or "")
        if repo.archived:
            repo.warnings.append("仓库处于归档（archived）状态，官方已停止维护")
        if repo.disabled:
            repo.warnings.append("仓库已被 GitHub 禁用")
        if repo.is_fork:
            repo.warnings.append("这是一个 fork 仓库，上游可能另有其源")

        has_issues = bool(meta.get("has_issues", True))

        # 1) 提交
        commits: list[dict[str, Any]] = []
        try:
            commits = self._api(
                f"/repos/{owner}/{name}/commits",
                {"since": _iso(cutoff), "per_page": 100},
            )
            if not isinstance(commits, list):
                commits = []
        except RateLimited as exc:
            repo.warnings.append(f"提交数据缺失：{exc}")
            self.budget_exhausted = True
        except HttpError as exc:
            repo.warnings.append(f"提交数据缺失：{exc}")

        # 项目自身节奏基线：/stats/participation 提供 52 周提交数（1 次请求）
        participation: Optional[dict[str, Any]] = None
        if not self.budget_exhausted:
            participation = self._participation(owner, name, repo)
        repo.commits = self._analyze_commits(commits, participation, window_days, now)

        # 社区温度：对最新 100 个 star 采样，估算近期 star 增速（1 次请求）
        if not self.budget_exhausted:
            self._star_activity(owner, name, repo, now)

        # 2) Issue + 评论
        raw_issues: list[dict[str, Any]] = []
        raw_comments: list[dict[str, Any]] = []
        if has_issues and not self.budget_exhausted:
            try:
                issues_resp = self._api(
                    f"/repos/{owner}/{name}/issues",
                    {
                        "state": "all",
                        "since": _iso(cutoff),
                        "sort": "updated",
                        "direction": "desc",
                        "per_page": 100,
                    },
                )
                raw_issues = [i for i in issues_resp if "pull_request" not in i] if isinstance(issues_resp, list) else []
            except RateLimited as exc:
                repo.warnings.append(f"Issue 数据缺失：{exc}")
                self.budget_exhausted = True
            except HttpError as exc:
                repo.warnings.append(f"Issue 数据缺失：{exc}")
            try:
                comments_resp = self._api(
                    f"/repos/{owner}/{name}/issues/comments",
                    {
                        "since": _iso(cutoff),
                        "sort": "updated",
                        "direction": "desc",
                        "per_page": 100,
                    },
                )
                raw_comments = comments_resp if isinstance(comments_resp, list) else []
            except RateLimited as exc:
                repo.warnings.append(f"Issue 评论数据缺失：{exc}")
                self.budget_exhausted = True
            except HttpError as exc:
                repo.warnings.append(f"Issue 评论数据缺失：{exc}")
        elif not has_issues:
            repo.warnings.append("仓库关闭了 Issues 功能")
        repo.issues = self._analyze_issues(
            raw_issues,
            raw_comments,
            cutoff=cutoff,
            now=now,
            window_days=window_days,
            issues_disabled=not has_issues,
        )

        # 3) PR
        raw_pulls: list[dict[str, Any]] = []
        if not self.budget_exhausted:
            try:
                pulls_resp = self._api(
                    f"/repos/{owner}/{name}/pulls",
                    {"state": "all", "sort": "created", "direction": "desc", "per_page": 100},
                )
                raw_pulls = pulls_resp if isinstance(pulls_resp, list) else []
            except RateLimited as exc:
                repo.warnings.append(f"PR 数据缺失：{exc}")
                self.budget_exhausted = True
            except HttpError as exc:
                repo.warnings.append(f"PR 数据缺失：{exc}")
        details = self._fetch_pr_details(owner, name, raw_pulls, cutoff, pr_detail, repo)
        repo.prs = self._analyze_pulls(raw_pulls, details, cutoff, now, window_days, pr_detail)

        # 4) Release
        releases: list[dict[str, Any]] = []
        if not self.budget_exhausted:
            try:
                releases_resp = self._api(f"/repos/{owner}/{name}/releases", {"per_page": 50})
                releases = releases_resp if isinstance(releases_resp, list) else []
            except RateLimited as exc:
                repo.warnings.append(f"Release 数据缺失：{exc}")
                self.budget_exhausted = True
            except HttpError as exc:
                repo.warnings.append(f"Release 数据缺失：{exc}")
        repo.releases = self._analyze_releases(releases, cutoff, now)

        # 5) 汇总降级信息
        if self.budget_exhausted:
            repo.truncated = True
        return repo

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def _api(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        url = f"{self.BASE}{path}"
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            url += "?" + urllib.parse.urlencode(filtered)
        return self.client.get_json(url)

    def _participation(self, owner: str, name: str, repo: RepoSignals) -> Optional[dict[str, Any]]:
        url = f"{self.BASE}/repos/{owner}/{name}/stats/participation"
        try:
            response = self.client.request("GET", url)
            if response.status == 202:  # GitHub 正在后台计算统计，稍等重试一次
                time.sleep(2.0)
                response = self.client.request("GET", url)
            if response.status == 200:
                data = response.json()
                return data if isinstance(data, dict) else None
        except RateLimited as exc:
            repo.warnings.append(f"提交统计缺失：{exc}")
            self.budget_exhausted = True
        except (HttpError, ValueError):
            pass
        return None

    def _star_activity(self, owner: str, name: str, repo: RepoSignals, now: datetime) -> None:
        """估算近期 star 增速，判断「fork 多但 star 增长停滞」。

        GitHub 的 stargazers 接口现在要求认证，所以无 Token 时改用
        ``/repos/{owner}/{name}/events``：统计最近 90 天公开事件里的 WatchEvent（star）
        与 ForkEvent，用事件时间跨度折算月增速。有 Token 时优先用 stargazers（更准）。
        """
        recent: Optional[int] = None
        covered_days: Optional[int] = None

        if self.client.github_token:
            recent, covered_days = self._stars_from_stargazers(owner, name, now, repo)
        if recent is None:
            recent, covered_days = self._stars_from_events(owner, name, now, repo)
        if recent is None:
            return

        repo.stars_recent_90d = recent
        if repo.created_at:
            months = max(1.0, (now - repo.created_at).days / 30.4)
            if months >= 6:
                repo.star_velocity_lifetime_month = round(repo.stars / months, 2)

        # 事件可能只覆盖最近一部分时间，折算成「每月」再比较
        if covered_days and covered_days > 0:
            repo.star_velocity_recent_month = round(recent / covered_days * 30.4, 2)
        else:
            repo.star_velocity_recent_month = round(recent / STAR_STALL_RECENT_MONTHS, 2)

        lifetime = repo.star_velocity_lifetime_month
        if (
            lifetime is not None
            and repo.stars >= STAR_STALL_MIN_STARS
            and repo.forks >= STAR_STALL_MIN_FORKS
            and repo.star_velocity_recent_month is not None
            and not repo.archived
        ):
            if repo.star_velocity_recent_month < max(1.0, lifetime * 0.1):
                repo.star_growth_stalled = True

    def _stars_from_stargazers(
        self, owner: str, name: str, now: datetime, repo: RepoSignals
    ) -> tuple[Optional[int], Optional[int]]:
        """有 Token 时用 star 时间戳精确统计（最新 100 个 star）。"""
        url = f"{self.BASE}/repos/{owner}/{name}/stargazers?per_page=100"
        try:
            response = self.client.request(
                "GET", url, headers={"Accept": "application/vnd.github.star+json"}
            )
            data = response.json()
        except RateLimited as exc:
            repo.warnings.append(f"star 增长数据缺失：{exc}")
            self.budget_exhausted = True
            return None, None
        except (HttpError, ValueError):
            return None, None
        if not isinstance(data, list):
            return None, None
        recent_cut = now - timedelta(days=90)
        recent = 0
        for item in data:
            if not isinstance(item, dict):
                continue
            starred = parse_iso(item.get("starred_at"))
            if starred and starred >= recent_cut:
                recent += 1
        if len(data) >= 100:
            repo.stars_recent_capped = recent == len(data)
        return recent, 90

    def _stars_from_events(
        self, owner: str, name: str, now: datetime, repo: RepoSignals
    ) -> tuple[Optional[int], Optional[int]]:
        """无 Token 时用公开事件流估算 star / fork 增长（只读最近 100 条事件）。"""
        url = f"{self.BASE}/repos/{owner}/{name}/events?per_page=100"
        try:
            response = self.client.request("GET", url)
            data = response.json()
        except RateLimited as exc:
            repo.warnings.append(f"社区事件数据缺失：{exc}")
            self.budget_exhausted = True
            return None, None
        except (HttpError, ValueError):
            return None, None
        if not isinstance(data, list):
            return None, None
        stars = 0
        times: list[datetime] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            created = parse_iso(item.get("created_at"))
            if created:
                times.append(created)
            if item.get("type") == "WatchEvent":
                stars += 1
        if not times:
            # 90 天内没有任何公开事件：对高 star 项目来说就是「死寂」
            return 0, 90
        covered = (now - min(times)).days
        if len(data) >= 100 and covered < 30:
            # 事件太多、只覆盖了不到一个月，说明项目很活跃，无需担心停滞
            repo.stars_recent_capped = True
            return stars, max(covered, 1)
        return stars, max(covered, 1)

    # ------------------------------------------------------------------
    # 提交分析
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze_commits(
        commits: list[dict[str, Any]],
        participation: Optional[dict[str, Any]],
        window_days: int,
        now: datetime,
    ) -> CommitSignals:
        from ..heuristics import commit_identity  # 局部导入避免循环

        sig = CommitSignals(window_days=window_days, sample_size=len(commits))
        authors: dict[str, int] = {}
        latest: Optional[datetime] = None
        human = bot = 0
        for commit in commits:
            identity, is_bot = commit_identity(commit)
            if is_bot:
                bot += 1
            else:
                human += 1
                authors[identity] = authors.get(identity, 0) + 1
                message = str((commit.get("commit") or {}).get("message") or "").lower()
                if any(marker in message for marker in CHORE_COMMIT_MARKERS):
                    sig.chore_human_count += 1
                else:
                    sig.substantive_human_count += 1
            commit_obj = commit.get("commit") or {}
            dt = parse_iso((commit_obj.get("committer") or {}).get("date")) or parse_iso(
                (commit_obj.get("author") or {}).get("date")
            )
            if dt and (latest is None or dt > latest):
                latest = dt
        sig.human_count = human
        sig.bot_count = bot
        sig.unique_human_authors = len(authors)
        human_total = sum(authors.values())
        sig.top_author_share = (max(authors.values()) / human_total) if human_total else 0.0
        sig.last_commit_at = latest
        sig.last_commit_age_days = age_days(latest, now)

        if participation and isinstance(participation.get("all"), list):
            weekly_all = [int(x) for x in participation["all"]]
            sig.baseline_weekly = weekly_all[-52:]
            last13 = sig.baseline_weekly[-13:]
            prev39 = sig.baseline_weekly[:-13]
            sig.weekly_counts = last13
            sig.active_weeks = sum(1 for x in last13 if x > 0)
            sig.count_window = sum(last13)
            sig.count_is_exact = True
            if prev39:
                base = sum(prev39) / float(len(prev39))
                recent = sum(last13) / float(len(last13))
                sig.baseline_commits_per_week = round(base, 2)
                sig.recent_commits_per_week = round(recent, 2)
                sig.activity_trend = round(recent / base, 3) if base > 0 else None
        else:
            sig.count_window = len(commits)
            sig.count_is_exact = len(commits) < 100
            if len(commits) >= 100:
                sig.warnings.append("提交数超过单页上限，实际数量更多（未获取提交统计）")
        return sig

    # ------------------------------------------------------------------
    # Issue 分析
    # ------------------------------------------------------------------

    def _analyze_issues(
        self,
        issues: list[dict[str, Any]],
        comments: list[dict[str, Any]],
        *,
        cutoff: datetime,
        now: datetime,
        window_days: int,
        issues_disabled: bool,
    ) -> IssueSignals:
        sig = IssueSignals(window_days=window_days, issues_disabled=issues_disabled)
        if issues_disabled:
            return sig

        comment_map: dict[int, list[dict[str, Any]]] = {}
        for comment in comments:
            number = _issue_number(str(comment.get("issue_url") or ""))
            if number is None:
                continue
            created = parse_iso(comment.get("created_at"))
            if created is None or created < cutoff:
                continue
            comment_map.setdefault(number, []).append(comment)

        sig.sampled = len(issues)
        sig.sample_truncated = len(issues) >= 100
        human_responses: list[float] = []
        maintainer_responses: list[float] = []

        for issue in issues:
            created = parse_iso(issue.get("created_at"))
            closed = parse_iso(issue.get("closed_at"))
            author = (issue.get("user") or {}).get("login") or ""
            number = int(issue.get("number") or 0)
            issue_comments = comment_map.get(number, [])

            if created and created >= cutoff:
                sig.created_window += 1
                sig.opened_window += 1
            if closed and closed >= cutoff:
                sig.closed_window += 1
                closed_by = (issue.get("closed_by") or {}).get("login") or ""
                if is_maintainer(issue.get("author_association")) or (
                    closed_by and not is_bot_user(issue.get("closed_by") or {})
                ):
                    sig.closed_by_maintainer_window += 1
            if str(issue.get("state")) == "open":
                sig.open_count += 1

            first_human: Optional[datetime] = None
            first_maintainer: Optional[datetime] = None
            has_human = False
            has_maintainer = False
            for comment in issue_comments:
                c_created = parse_iso(comment.get("created_at"))
                c_user = (comment.get("user") or {}).get("login") or ""
                if is_bot_user(comment.get("user")):
                    sig.bot_comment_count += 1
                    continue
                sig.human_comment_count += 1
                if c_user == author:
                    continue
                has_human = True
                if first_human is None or (c_created and c_created < first_human):
                    first_human = c_created
                if is_maintainer(comment.get("author_association")):
                    has_maintainer = True
                    if first_maintainer is None or (c_created and c_created < first_maintainer):
                        first_maintainer = c_created
            total_comments = sig.human_comment_count + sig.bot_comment_count
            if total_comments and sig.sampled == len(issues):
                pass  # 比例在循环外统一计算

            if has_human:
                sig.human_replied_count += 1
            if has_maintainer:
                sig.maintainer_replied_count += 1
            if str(issue.get("state")) == "open" and not has_human:
                sig.unanswered_open_count += 1

            labels = []
            for label in issue.get("labels") or []:
                if isinstance(label, dict):
                    labels.append(str(label.get("name") or "").lower())
                elif label:
                    labels.append(str(label).lower())
            is_bug = any(marker in label for label in labels for marker in BUG_LABEL_MARKERS)
            if is_bug:
                sig.bug_labeled_count += 1
                if (
                    str(issue.get("state")) == "open"
                    and created is not None
                    and (now - created).days >= LONG_OPEN_BUG_DAYS
                    and not has_human
                ):
                    sig.long_open_bugs += 1

            if created and created >= cutoff:
                h = hours_between(created, first_human)
                if h is not None:
                    human_responses.append(h)
                m = hours_between(created, first_maintainer)
                if m is not None:
                    maintainer_responses.append(m)

        total_comments = sig.human_comment_count + sig.bot_comment_count
        sig.bot_comment_share = (sig.bot_comment_count / total_comments) if total_comments else 0.0
        sig.median_first_human_response_hours = median(human_responses)
        sig.median_maintainer_response_hours = median(maintainer_responses)
        sig.maintainer_activity = sig.maintainer_replied_count > 0
        if sig.sample_truncated:
            sig.warnings.append("Issue 采样达到 100 条上限，统计为下限")
        if len(comments) >= 100:
            sig.warnings.append("Issue 评论采样达到 100 条上限，回复统计可能偏低")
        return sig

    # ------------------------------------------------------------------
    # PR 分析
    # ------------------------------------------------------------------

    def _fetch_pr_details(
        self,
        owner: str,
        name: str,
        pulls: list[dict[str, Any]],
        cutoff: datetime,
        pr_detail: int,
        repo: RepoSignals,
    ) -> list[dict[str, Any]]:
        if pr_detail <= 0 or not pulls or self.budget_exhausted:
            return []
        merged = [
            p
            for p in pulls
            if p.get("merged_at") and (parse_iso(p.get("merged_at")) or cutoff) >= cutoff
        ]
        selected = _sample_evenly(merged, min(pr_detail, len(merged)))
        remaining = self.client.github_remaining
        if remaining is not None and remaining < len(selected) + 2:
            repo.warnings.append(
                "GitHub 配额不足，跳过 PR 合并者抽查（设置 GITHUB_TOKEN 可提升配额）"
            )
            return []
        details: list[dict[str, Any]] = []
        for pr in selected:
            try:
                details.append(self._api(f"/repos/{owner}/{name}/pulls/{pr['number']}"))
            except RateLimited as exc:
                repo.warnings.append(f"PR 合并者抽查中止：{exc}")
                self.budget_exhausted = True
                break
            except HttpError:
                continue
        return details

    @staticmethod
    def _analyze_pulls(
        pulls: list[dict[str, Any]],
        details: list[dict[str, Any]],
        cutoff: datetime,
        now: datetime,
        window_days: int,
        requested_detail: int,
    ) -> PullSignals:
        sig = PullSignals(window_days=window_days)
        sig.sampled = len(pulls)
        sig.sample_truncated = len(pulls) >= 100
        merge_hours: list[float] = []
        human_merge_hours: list[float] = []

        for pr in pulls:
            created = parse_iso(pr.get("created_at"))
            merged_at = parse_iso(pr.get("merged_at"))
            closed_at = parse_iso(pr.get("closed_at"))
            created_in = bool(created and created >= cutoff)
            merged_in = bool(merged_at and merged_at >= cutoff)
            if created_in:
                sig.created_window += 1
                if is_bot_user(pr.get("user")):
                    sig.bot_pr_count += 1
                else:
                    sig.human_pr_count += 1
                    sig.human_created_window += 1
            if merged_in:
                sig.merged_window += 1
                h = hours_between(created, merged_at)
                if h is not None:
                    merge_hours.append(h)
                    if not is_bot_user(pr.get("user")):
                        human_merge_hours.append(h)
            elif closed_at and closed_at >= cutoff and pr.get("merged_at") is None:
                sig.closed_unmerged_window += 1
                if not is_bot_user(pr.get("user")):
                    sig.human_closed_unmerged_window += 1
            if str(pr.get("state")) == "open":
                if created_in:
                    sig.open_window += 1
                else:
                    sig.stale_open_count += 1
            if pr.get("auto_merge") is not None:
                sig.auto_merge_prs += 1

        total_authored = sig.bot_pr_count + sig.human_pr_count
        sig.bot_pr_share = (sig.bot_pr_count / total_authored) if total_authored else 0.0
        closed_total = sig.merged_window + sig.closed_unmerged_window
        sig.merge_rate = (sig.merged_window / closed_total) if closed_total else None
        sig.median_merge_hours = median(merge_hours)
        sig.human_median_merge_hours = median(human_merge_hours)

        for detail in details:
            if not isinstance(detail, dict):
                continue
            if detail.get("merged") is not True:
                continue
            sig.merged_samples += 1
            merged_by = detail.get("merged_by") or {}
            if is_bot_user(merged_by):
                sig.bot_merged_samples += 1
            else:
                sig.human_merged_samples += 1
            sig.sample_details.append(
                {
                    "number": detail.get("number"),
                    "title": str(detail.get("title") or "")[:80],
                    "author": (detail.get("user") or {}).get("login") or "",
                    "merged_by": (merged_by or {}).get("login") or "",
                    "merged_by_is_bot": is_bot_user(merged_by),
                    "review_comments": int(detail.get("review_comments") or 0),
                    "comments": int(detail.get("comments") or 0),
                    "commits": int(detail.get("commits") or 0),
                    "changed_files": int(detail.get("changed_files") or 0),
                }
            )
        if sig.merged_samples:
            sig.bot_merge_share = sig.bot_merged_samples / sig.merged_samples
        if requested_detail and not details and sig.merged_window:
            sig.detail_truncated = True
        if sig.sample_truncated:
            sig.warnings.append("PR 采样达到 100 条上限，统计为下限")
        return sig

    # ------------------------------------------------------------------
    # Release 分析
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze_releases(releases: list[dict[str, Any]], cutoff: datetime, now: datetime) -> ReleaseSignals:
        sig = ReleaseSignals()
        if not releases:
            sig.warnings.append("仓库没有 GitHub Release 记录（可能只用 tag 发布）")
            return sig
        dates: list[tuple[datetime, bool]] = []
        for release in releases:
            if release.get("draft"):
                continue
            dt = parse_iso(release.get("published_at"))
            if dt:
                dates.append((dt, bool(release.get("prerelease"))))
        sig.total_fetched = len(dates)
        if not dates:
            sig.warnings.append("仓库没有正式发布的 Release")
            return sig
        dates.sort()
        last_dt = dates[-1][0]
        sig.last_release_at = last_dt
        sig.last_release_age_days = age_days(last_dt, now)
        window = [(dt, pre) for dt, pre in dates if dt >= cutoff]
        sig.releases_window = len(window)
        sig.releases_365d = len([dt for dt, _ in dates if dt >= now - timedelta(days=365)])
        prev_cutoff = cutoff - timedelta(days=90)
        sig.releases_prev_90d = len([dt for dt, _ in dates if prev_cutoff <= dt < cutoff])
        if sig.releases_prev_90d >= RELEASE_CLIFF_MIN_PREV:
            sig.release_trend = round(len(window) / float(sig.releases_prev_90d), 3)
            sig.cadence_cliff = sig.release_trend == 0 or (
                sig.releases_prev_90d >= 4 and sig.release_trend <= 0.25
            )
        if window:
            sig.prerelease_only = all(pre for _, pre in window)
        return sig
