"""单元测试：版本比较 / CVSS / 机器人识别 / 评分封顶 / 文本排版。"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from oss_health import cvss, heuristics, versions
from oss_health.config import WEIGHTS
from oss_health.analyzers import maintenance as maintenance_analyzer
from oss_health.models import (
    CommitSignals,
    Dimension,
    IssueSignals,
    PackageInfo,
    PullSignals,
    ReleaseSignals,
    RepoSignals,
    SecuritySignals,
    Vulnerability,
)
from oss_health.scoring import compute, grade_for
from oss_health.text import Table, Style, bar, visible_width, wrap, truncate, pad

UTC = timezone.utc
NOW = datetime(2026, 10, 17, tzinfo=UTC)


class VersionTests(unittest.TestCase):
    def test_pypi_ordering(self):
        self.assertEqual(versions.compare_versions("2.0rc1", "2.0", "pypi"), -1)
        self.assertEqual(versions.compare_versions("1.0.post1", "1.0", "pypi"), 1)
        self.assertEqual(versions.compare_versions("1.0.0", "1.0", "pypi"), 0)
        self.assertEqual(versions.compare_versions("2.10.0", "2.9.9", "pypi"), 1)

    def test_npm_semver(self):
        self.assertEqual(versions.compare_versions("1.0.0-alpha", "1.0.0", "npm"), -1)
        self.assertEqual(versions.compare_versions("1.0.0-alpha", "1.0.0-alpha.1", "npm"), -1)
        self.assertEqual(versions.compare_versions("1.0.0-alpha.2", "1.0.0-alpha.10", "npm"), -1)
        self.assertEqual(versions.compare_versions("1.0.0", "1.0.0", "npm"), 0)

    def test_nuget(self):
        self.assertEqual(versions.compare_versions("14.0.1-beta2", "14.0.1", "nuget"), -1)
        self.assertEqual(versions.compare_versions("1.0.0.0", "1.0.0", "nuget"), 0)
        self.assertEqual(versions.compare_versions("13.0.2", "13.0.1", "nuget"), 1)

    def test_npm_range(self):
        self.assertTrue(versions.satisfies_npm_range("26.0.0", ">= 18"))
        self.assertFalse(versions.satisfies_npm_range("26.0.0", "^18.0.0"))
        self.assertFalse(versions.satisfies_npm_range("26.0.0", ">=18 <22"))
        self.assertTrue(versions.satisfies_npm_range("20.0.0", "^18 || ^20"))
        self.assertIsNone(versions.satisfies_npm_range("20.0.0", None))

    def test_in_range(self):
        self.assertTrue(versions.in_range("1.5.0", introduced="1.0.0", fixed="2.0.0"))
        self.assertFalse(versions.in_range("2.0.0", introduced="1.0.0", fixed="2.0.0"))
        self.assertTrue(versions.in_range("2.0.0", last_affected="2.0.0"))
        self.assertFalse(versions.in_range("0.9.0", introduced="1.0.0", fixed="2.0.0"))


class CvssTests(unittest.TestCase):
    def test_scores(self):
        self.assertEqual(cvss.parse_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), (9.8, "3.1"))
        self.assertEqual(cvss.parse_cvss("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), (7.5, "3.0"))
        self.assertEqual(cvss.parse_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"), (5.3, "3.1"))
        self.assertEqual(cvss.parse_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), (6.1, "3.1"))

    def test_severity(self):
        self.assertEqual(cvss.severity_from_score(9.8), "CRITICAL")
        self.assertEqual(cvss.severity_from_score(7.5), "HIGH")
        self.assertEqual(cvss.severity_from_score(5.3), "MEDIUM")
        self.assertEqual(cvss.severity_from_score(2.0), "LOW")
        self.assertEqual(cvss.normalize_severity("MODERATE"), "MEDIUM")
        self.assertIsNone(cvss.parse_cvss("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))


class HeuristicTests(unittest.TestCase):
    def test_bot_detection(self):
        self.assertTrue(heuristics.is_bot_login("dependabot[bot]", "Bot"))
        self.assertTrue(heuristics.is_bot_login("renovate-bot"))
        self.assertTrue(heuristics.is_bot_login("github-actions[bot]"))
        self.assertFalse(heuristics.is_bot_login("alice"))
        self.assertFalse(heuristics.is_bot_login("abbot"))  # 真人用户名

    def test_commit_identity(self):
        bot_commit = {
            "author": {"login": "dependabot[bot]", "type": "Bot"},
            "committer": {"login": "web-flow", "type": "User"},
            "commit": {"author": {"name": "dependabot[bot]", "email": "support@github.com"}},
        }
        human_squash = {
            "author": {"login": "alice", "type": "User"},
            "committer": {"login": "web-flow", "type": "User"},
            "commit": {"author": {"name": "Alice", "email": "alice@example.com"}},
        }
        self.assertTrue(heuristics.is_bot_commit_author(bot_commit))
        self.assertFalse(heuristics.is_bot_commit_author(human_squash))

    def test_maintainer(self):
        self.assertTrue(heuristics.is_maintainer("MEMBER"))
        self.assertTrue(heuristics.is_maintainer("OWNER"))
        self.assertFalse(heuristics.is_maintainer("CONTRIBUTOR"))
        self.assertFalse(heuristics.is_maintainer(None))


def _dims(score: int = 100) -> list[Dimension]:
    return [
        Dimension(key=key, title=key, weight=weight, score=score, available=True)
        for key, weight in WEIGHTS.items()
    ]


def _package(**kwargs) -> PackageInfo:
    base = dict(ecosystem="pypi", name="demo", version="1.0.0", latest_version="1.0.0")
    base.update(kwargs)
    return PackageInfo(**base)


def _repo(**kwargs) -> RepoSignals:
    base = dict(owner="acme", name="demo")
    base.update(kwargs)
    return RepoSignals(**base)


def _critical_security() -> SecuritySignals:
    vuln = Vulnerability(
        id="GHSA-demo",
        aliases=["CVE-2026-0001"],
        severity="CRITICAL",
        cvss_score=9.8,
        affects_current=True,
        fixed_versions=["1.0.1"],
    )
    return SecuritySignals(
        ecosystem="pypi",
        package="demo",
        version="1.0.0",
        vulns_current=[vuln],
        history_count=1,
    )


class ScoringTests(unittest.TestCase):
    def test_plain_score(self):
        result = compute(_dims(100), repo=_repo(), package=_package(), security=None)
        self.assertEqual(result.total_score, 100.0)
        self.assertEqual(result.grade, "A")
        self.assertEqual(result.raw_total, 100.0)
        self.assertEqual(result.hard_flags, [])

    def test_archived_cap(self):
        result = compute(_dims(95), repo=_repo(archived=True), package=_package(), security=None)
        self.assertEqual(result.total_score, 35.0)
        self.assertEqual(result.grade, "D")
        self.assertIn("archived", [f.key for f in result.hard_flags])

    def test_critical_cve_cap(self):
        security = _critical_security()
        result = compute(_dims(100), repo=_repo(), package=_package(), security=security)
        self.assertEqual(result.total_score, 40.0)
        self.assertEqual(result.grade, "D")
        self.assertIn("critical_cve", [f.key for f in result.hard_flags])

    def test_deprecated_cap(self):
        package = _package(deprecated=True, deprecation_message="use demo2 instead")
        result = compute(_dims(90), repo=_repo(), package=package, security=None)
        self.assertEqual(result.total_score, 35.0)
        flag = next(f for f in result.hard_flags if f.key == "deprecated")
        self.assertIn("demo2", flag.reason)

    def test_no_human_activity_cap(self):
        repo = _repo(
            commits=CommitSignals(window_days=90, count_window=10, sample_size=10, human_count=0, bot_count=10),
        )
        result = compute(_dims(80), repo=repo, package=_package(), security=None)
        self.assertEqual(result.total_score, 45.0)
        self.assertIn("no_human_maintainer", [f.key for f in result.hard_flags])

    def test_grade_table(self):
        self.assertEqual(grade_for(85)[0], "A")
        self.assertEqual(grade_for(70)[0], "B")
        self.assertEqual(grade_for(55)[0], "C")
        self.assertEqual(grade_for(40)[0], "D")
        self.assertEqual(grade_for(10)[0], "F")

    def test_confidence(self):
        high = compute(_dims(90), repo=_repo(), package=_package(), security=_critical_security())
        self.assertEqual(high.confidence, "high")
        low = compute([d for d in _dims(90) if d.key in ("maintenance", "issues", "prs")],
                      repo=_repo(), package=None, security=None)
        self.assertEqual(low.confidence, "low")


class BaselineMaintenanceTests(unittest.TestCase):
    """「慢但稳」不应被判为停摆；真正断崖才扣分。"""

    def _repo(self, **kwargs) -> RepoSignals:
        commits = CommitSignals(
            window_days=90,
            count_window=kwargs.pop("count_window", 2),
            sample_size=6,
            human_count=2,
            bot_count=0,
            unique_human_authors=1,
            top_author_share=1.0,
            substantive_human_count=2,
            chore_human_count=0,
            last_commit_at=NOW,
            last_commit_age_days=kwargs.pop("age", 120),
        )
        data = dict(owner="acme", name="demo", stars=800, forks=80, commits=commits)
        data.update(kwargs)
        return RepoSignals(**data)

    def test_slow_but_steady_not_penalized(self):
        commits = CommitSignals(
            window_days=90,
            count_window=1,
            sample_size=3,
            human_count=3,
            unique_human_authors=1,
            substantive_human_count=3,
            last_commit_age_days=200,
            baseline_weekly=[0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0] * 4,
            baseline_commits_per_week=0.1,
            recent_commits_per_week=0.08,
        )
        repo = RepoSignals(owner="acme", name="demo", stars=300, forks=40, commits=commits)
        dim = maintenance_analyzer.analyze(repo, None, NOW)
        self.assertGreaterEqual(dim.score, 90)
        self.assertTrue(any("低频但稳定" in note for note in dim.notes))

    def test_stalled_project_penalized(self):
        commits = CommitSignals(
            window_days=90,
            count_window=0,
            sample_size=0,
            human_count=0,
            last_commit_age_days=400,
            baseline_commits_per_week=2.0,
            recent_commits_per_week=0.0,
            activity_trend=0.0,
        )
        repo = RepoSignals(owner="acme", name="demo", stars=5000, forks=800, commits=commits)
        dim = maintenance_analyzer.analyze(repo, None, NOW)
        self.assertLess(dim.score, 55)
        reasons = " ".join(d.reason for d in dim.deductions)
        self.assertIn("没有提交", reasons)
        self.assertIn("断崖", reasons)

    def test_release_cliff(self):
        commits = CommitSignals(
            window_days=90,
            count_window=12,
            sample_size=11,
            human_count=11,
            unique_human_authors=2,
            substantive_human_count=11,
            last_commit_age_days=3,
            baseline_commits_per_week=1.5,
            recent_commits_per_week=0.9,
            activity_trend=0.6,
        )
        releases = ReleaseSignals(
            last_release_at=NOW,
            last_release_age_days=100,
            releases_window=0,
            releases_prev_90d=5,
            releases_365d=7,
            cadence_cliff=True,
            release_trend=0.0,
            total_fetched=8,
        )
        repo = RepoSignals(owner="acme", name="demo", commits=commits, releases=releases)
        dim = maintenance_analyzer.analyze(repo, None, NOW)
        self.assertTrue(any("发布节奏断崖" in d.reason for d in dim.deductions))

    def test_star_growth_stalled(self):
        commits = CommitSignals(
            window_days=90,
            count_window=12,
            sample_size=11,
            human_count=11,
            unique_human_authors=2,
            substantive_human_count=11,
            last_commit_age_days=3,
            baseline_commits_per_week=1.5,
            recent_commits_per_week=1.2,
            activity_trend=0.8,
        )
        repo = RepoSignals(
            owner="acme",
            name="demo",
            stars=12000,
            forks=1500,
            commits=commits,
            stars_recent_90d=0,
            star_velocity_recent_month=0.0,
            star_velocity_lifetime_month=30.0,
            star_growth_stalled=True,
        )
        dim = maintenance_analyzer.analyze(repo, None, NOW)
        self.assertTrue(any("社区热度停滞" in d.reason for d in dim.deductions))

    def test_issue_long_open_bugs(self):
        from oss_health.analyzers import issues as issues_analyzer

        issues = IssueSignals(
            window_days=90,
            sampled=30,
            opened_window=10,
            maintainer_replied_count=4,
            human_replied_count=8,
            closed_by_maintainer_window=4,
            open_count=10,
            unanswered_open_count=2,
            bug_labeled_count=4,
            long_open_bugs=2,
        )
        repo = RepoSignals(owner="acme", name="demo", issues=issues)
        dim = issues_analyzer.analyze(repo, NOW)
        self.assertTrue(any("bug" in d.reason for d in dim.deductions))
        self.assertLess(dim.score, 100)

    def test_pr_human_latency(self):
        from oss_health.analyzers import pull_requests as pr_analyzer

        prs = PullSignals(
            window_days=90,
            sampled=20,
            created_window=5,
            human_created_window=5,
            merged_window=4,
            human_merged_samples=4,
            merged_samples=4,
            bot_merge_share=0.0,
            merge_rate=1.0,
            human_median_merge_hours=24 * 60,
        )
        repo = RepoSignals(owner="acme", name="demo", prs=prs)
        dim = pr_analyzer.analyze(repo, NOW)
        self.assertTrue(any("真人 PR" in d.reason for d in dim.deductions))


class TextTests(unittest.TestCase):
    def test_width(self):
        self.assertEqual(visible_width("abc"), 3)
        self.assertEqual(visible_width("中文"), 4)
        self.assertEqual(visible_width("\x1b[31mred\x1b[0m"), 3)

    def test_pad_truncate(self):
        self.assertEqual(pad("中文", 6), "中文  ")
        self.assertEqual(visible_width(pad("中文", 6)), 6)
        self.assertLessEqual(visible_width(truncate("这是一段很长的中文文本", 6)), 6)
        self.assertTrue(truncate("这是一段很长的中文文本", 6).endswith("…"))

    def test_wrap(self):
        lines = wrap("hello world this is a test", 10)
        self.assertTrue(all(visible_width(line) <= 10 for line in lines))
        cjk_lines = wrap("中文折行测试中文折行测试", 6)
        self.assertTrue(all(visible_width(line) <= 6 for line in cjk_lines))

    def test_bar(self):
        self.assertEqual(bar(50, 10), "█████░░░░░")

    def test_table(self):
        table = Table(["名称", "值"])
        table.add("中文", "1")
        lines = table.render(Style(enabled=False), max_width=40)
        self.assertEqual(len(lines), 3)
        self.assertIn("中文", lines[2])


if __name__ == "__main__":
    unittest.main()
