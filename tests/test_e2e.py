"""端到端测试：用假 API 跑通「采集 -> 分析 -> 评分 -> 四种报告」。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from oss_health.http_client import HttpClient
from oss_health.report import render_console, render_html, render_json, render_markdown
from oss_health.scanner import ScanOptions, Scanner, _split_package_version
from oss_health.text import Style

try:  # 兼容 python -m unittest discover 与 pytest 两种运行方式
    from .fake_api import NOW, FakeAPI
except ImportError:  # pragma: no cover
    from fake_api import NOW, FakeAPI


def run_scan(target: str = "pypi:acme-widget", *, api: FakeAPI | None = None, **option_kwargs):
    api = api or FakeAPI()
    client = HttpClient(transport=api)
    options = ScanOptions(now_override=NOW, **option_kwargs)
    report = Scanner(client, options).scan(target)
    return report, api


class EndToEndPypiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report, cls.api = run_scan(pr_detail=2, dep_check=10)

    def test_target_and_package(self):
        self.assertEqual(self.report.target.ecosystem, "pypi")
        package = self.report.package
        self.assertIsNotNone(package)
        self.assertEqual(package.name, "acme-widget")
        self.assertEqual(package.version, "1.1.0")
        self.assertEqual(package.repo_url, "https://github.com/acme/widget")

    def test_repo_signals(self):
        repo = self.report.repo
        self.assertIsNotNone(repo)
        self.assertEqual(repo.slug, "acme/widget")
        self.assertEqual(repo.stars, 1234)
        self.assertFalse(repo.archived)
        commits = repo.commits
        self.assertEqual(commits.human_count, 8)
        self.assertEqual(commits.bot_count, 2)
        self.assertEqual(commits.unique_human_authors, 4)
        self.assertGreaterEqual(commits.last_commit_age_days, 0)
        # 52 周基线：历史约 1.5 次/周，近 90 天约 0.9 次/周
        self.assertIsNotNone(commits.baseline_commits_per_week)
        self.assertAlmostEqual(commits.baseline_commits_per_week, 1.62, delta=0.05)
        self.assertAlmostEqual(commits.recent_commits_per_week, 0.92, delta=0.05)
        self.assertIsNotNone(commits.activity_trend)
        self.assertFalse(repo.star_growth_stalled)

    def test_issue_signals(self):
        issues = self.report.repo.issues
        self.assertEqual(issues.created_window, 2)
        self.assertEqual(issues.maintainer_replied_count, 2)
        self.assertEqual(issues.human_replied_count, 2)
        self.assertEqual(issues.bot_comment_count, 1)
        self.assertAlmostEqual(issues.median_first_human_response_hours or 0, 2.0, delta=0.5)
        self.assertEqual(issues.unanswered_open_count, 1)

    def test_pr_signals(self):
        prs = self.report.repo.prs
        self.assertEqual(prs.created_window, 4)
        self.assertEqual(prs.merged_window, 3)
        self.assertEqual(prs.bot_pr_count, 2)
        self.assertEqual(prs.human_pr_count, 2)
        self.assertEqual(prs.stale_open_count, 1)
        self.assertEqual(prs.merged_samples, 2)
        self.assertEqual(prs.bot_merged_samples, 2)
        self.assertEqual(prs.bot_merge_share, 1.0)

    def test_framework(self):
        framework = self.report.framework
        self.assertEqual(framework.runtime, "Python")
        self.assertEqual(framework.gap, 3)
        self.assertIn(framework.status, ("lagging", "eol"))
        self.assertIn("3.9", framework.eol_declared)

    def test_security(self):
        security = self.report.security
        self.assertEqual(len(security.vulns_current), 1)
        vuln = security.vulns_current[0]
        self.assertEqual(vuln.cve, "CVE-2026-0001")
        self.assertEqual(vuln.severity, "HIGH")
        self.assertAlmostEqual(vuln.cvss_score, 7.5, places=1)
        self.assertEqual(vuln.best_fix_version, "1.2.0")
        self.assertEqual(security.history_count, 2)
        self.assertEqual(security.fixed_count, 1)

    def test_dependencies(self):
        dep_dim = self.report.dimension("dependencies")
        self.assertTrue(dep_dim.available)
        self.assertEqual(dep_dim.metrics["deps_total"], 2)
        self.assertEqual(dep_dim.metrics["deps_checked"], 2)
        self.assertEqual(dep_dim.metrics["deps_with_vulns"], 0)

    def test_dimensions_and_score(self):
        dims = {d.key: d for d in self.report.dimensions}
        self.assertEqual(set(dims), {"maintenance", "issues", "prs", "framework", "security", "dependencies"})
        self.assertTrue(all(d.available for d in dims.values()))
        self.assertGreater(self.report.total_score, 50)
        self.assertLess(self.report.total_score, 95)
        self.assertEqual(self.report.grade, "A")
        # 高危漏洞不应触发「严重漏洞」一票否决
        self.assertNotIn("critical_cve", [f.key for f in self.report.hard_flags])
        self.assertEqual(self.report.confidence, "high")
        self.assertGreater(len(self.report.recommendations), 2)

    def test_reports_render(self):
        console = render_console(self.report, style=Style(enabled=False), width=100)
        self.assertIn("维度评分", console)
        self.assertIn("行动建议", console)
        self.assertIn("漏洞明细", console)
        self.assertNotIn("\x1b[", console)

        colored = render_console(self.report, style=Style(enabled=True), width=100)
        self.assertIn("\x1b[", colored)

        markdown = render_markdown(self.report)
        self.assertIn("# 开源项目健康度报告", markdown)
        self.assertIn("CVE-2026-0001", markdown)
        self.assertIn("## 行动建议", markdown)

        html = render_html(self.report)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("CVE-2026-0001", html)

        payload = json.loads(render_json(self.report))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["grade"], self.report.grade)
        self.assertEqual(payload["security"]["vulns_current"][0]["aliases"], ["CVE-2026-0001"])

    def test_github_only_scan(self):
        report, _ = run_scan("github:acme/widget")
        self.assertIsNone(report.package)
        self.assertIsNotNone(report.repo)
        dims = {d.key: d for d in report.dimensions}
        self.assertTrue(dims["maintenance"].available)
        self.assertTrue(dims["issues"].available)
        self.assertFalse(dims["security"].available)
        self.assertFalse(dims["framework"].available)
        self.assertFalse(dims["dependencies"].available)
        self.assertIn(report.confidence, ("medium", "low"))
        self.assertGreater(report.total_score, 0)

    def test_star_velocity(self):
        repo = self.report.repo
        self.assertIsNotNone(repo.stars_recent_90d)
        self.assertGreater(repo.star_velocity_recent_month or 0, 0)
        self.assertIsNotNone(repo.star_velocity_lifetime_month)
        self.assertFalse(repo.star_growth_stalled)
    def test_release_signals(self):
        rel = self.report.repo.releases
        self.assertEqual(rel.releases_prev_90d, 0)
        self.assertFalse(rel.cadence_cliff)

    def test_auto_ecosystem_detection(self):
        report, api = run_scan("acme-widget")
        self.assertEqual(report.target.ecosystem, "pypi")
        self.assertEqual(report.package.name, "acme-widget")

    def test_unknown_package(self):
        from oss_health.http_client import NotFound

        with self.assertRaises(NotFound):
            run_scan("pypi:definitely-does-not-exist")


class VariantTests(unittest.TestCase):
    def test_version_pinned_scan(self):
        report, _ = run_scan("pypi:acme-widget@1.0.0", pr_detail=0)
        self.assertEqual(report.package.version, "1.0.0")
        self.assertEqual(report.target.version, "1.0.0")

    def test_vulnerable_dependency(self):
        api = FakeAPI(vulnerable_dep=True)
        report, _ = run_scan(api=api, pr_detail=0)
        dep_dim = report.dimension("dependencies")
        self.assertEqual(dep_dim.metrics["deps_with_vulns"], 1)
        self.assertGreaterEqual(dep_dim.metrics["dep_critical_high"], 1)
        risky = [r for r in report.dep_risks if r.vulns]
        self.assertEqual(risky[0].name, "urllib3")
        self.assertEqual(risky[0].checked_version, "1.26.0")
        self.assertEqual(risky[0].vulns[0].cve, "CVE-2025-1234")

    def test_stalled_stars(self):
        report, _ = run_scan(api=FakeAPI(stalled_stars=True), pr_detail=0)
        repo = report.repo
        self.assertTrue(repo.star_growth_stalled)
        self.assertEqual(repo.stars_recent_90d, 0)
        reasons = " ".join(d.reason for d in report.dimension("maintenance").deductions)
        self.assertIn("社区热度停滞", reasons)
        self.assertTrue(any("社区热度停滞" in r for r in report.recommendations))

    def test_long_open_bugs(self):
        api = FakeAPI(dead_community=True)
        report, _ = run_scan(api=api, pr_detail=0)
        issues = report.repo.issues
        self.assertEqual(issues.bug_labeled_count, 1)
        self.assertEqual(issues.long_open_bugs, 1)
        self.assertLess(report.dimension("issues").score, 90)

    def test_zero_pr_detail(self):
        report, _ = run_scan(pr_detail=0)
        prs = report.repo.prs
        self.assertEqual(prs.merged_samples, 0)
        self.assertIsNone(prs.bot_merge_share)


class TargetParsingTests(unittest.TestCase):
    def test_split_package_version(self):
        self.assertEqual(_split_package_version("requests@2.31.0", "pypi"), ("requests", "2.31.0"))
        self.assertEqual(_split_package_version("requests==2.31.0", "pypi"), ("requests", "2.31.0"))
        self.assertEqual(_split_package_version("@scope/pkg@1.2.3", "npm"), ("@scope/pkg", "1.2.3"))
        self.assertEqual(_split_package_version("@scope/pkg", "npm"), ("@scope/pkg", None))
        self.assertEqual(_split_package_version("express", "npm"), ("express", None))

    def test_normalize_argv(self):
        from oss_health.cli import _normalize_argv

        self.assertEqual(_normalize_argv(["pypi:requests"]), ["scan", "pypi:requests"])
        self.assertEqual(_normalize_argv(["--format", "md", "pypi:requests"]), ["scan", "--format", "md", "pypi:requests"])
        self.assertEqual(_normalize_argv(["demo"]), ["demo"])
        self.assertEqual(_normalize_argv([]), ["--help"])

    def test_offline_fallback_ignores_since(self):
        tmp = tempfile.mkdtemp(dir=".")
        try:
            entry = {
                "v": 1,
                "url": "https://api.github.com/repos/a/b/commits?since=2026-07-01T00%3A00%3A00Z&per_page=100",
                "status": 200,
                "headers": {},
                "stored_at": "2026-10-17T00:00:00+00:00",
                "body": json.dumps({"ok": True}),
            }
            Path(tmp, "deadbeef.json").write_text(json.dumps(entry), encoding="utf-8")
            client = HttpClient(offline_dir=tmp)
            response = client.get("https://api.github.com/repos/a/b/commits?since=2026-10-17T00%3A00%3A00Z&per_page=100")
            self.assertEqual(response.json(), {"ok": True})
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
