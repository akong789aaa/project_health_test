"""测试用的假 API 层：完整模拟 PyPI / GitHub / OSV / endoflife.date 响应。

通过注入 ``HttpClient(transport=FakeAPI())``，可以在不联网、不消耗 GitHub 配额的情况下
跑通整个扫描链路。
"""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

from oss_health.http_client import Response

UTC = timezone.utc
NOW = datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(days: float = 0, hours: float = 0) -> datetime:
    return NOW - timedelta(days=days, hours=hours)


def _json_response(url: str, payload: Any, status: int = 200) -> Response:
    return Response(
        status=status,
        url=url,
        body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"content-type": "application/json"},
    )


def _user(login: str, user_type: str = "User") -> dict[str, Any]:
    return {"login": login, "type": user_type, "id": abs(hash(login)) % 100000}


def _commit(login: str, days: float, message: str, user_type: str = "User", name: str = "") -> dict[str, Any]:
    date = iso(ago(days=days))
    return {
        "sha": f"sha-{login}-{int(days * 100)}",
        "author": _user(login, user_type),
        "committer": _user(login, user_type),
        "commit": {
            "author": {"name": name or login, "email": f"{login}@example.com", "date": date},
            "committer": {"name": name or login, "email": f"{login}@example.com", "date": date},
            "message": message,
        },
    }


COMMITS = [
    _commit("alice", 2, "feat: add widget cache"),
    _commit("bob", 5, "fix: handle empty payload"),
    _commit("alice", 9, "docs: update README"),
    _commit("dependabot[bot]", 12, "chore(deps): bump urllib3 (#201)", "Bot", "dependabot[bot]"),
    _commit("alice", 18, "refactor: split parser"),
    _commit("carol", 26, "test: add regression tests"),
    _commit("bob", 33, "fix: retry on timeout"),
    _commit("dependabot[bot]", 41, "chore(deps): bump certifi (#199)", "Bot", "dependabot[bot]"),
    _commit("alice", 55, "feat: expose metrics endpoint"),
    _commit("dave", 70, "chore: drop py3.8"),
]

ISSUES = [
    {
        "number": 101,
        "state": "open",
        "title": "widget crashes on empty input",
        "created_at": iso(ago(days=3)),
        "updated_at": iso(ago(days=2, hours=22)),
        "closed_at": None,
        "comments": 1,
        "user": _user("reporter1"),
        "author_association": "NONE",
    },
    {
        "number": 102,
        "state": "open",
        "title": "question about configuration",
        "created_at": iso(ago(days=12)),
        "updated_at": iso(ago(days=11)),
        "closed_at": None,
        "comments": 1,
        "user": _user("reporter2"),
        "author_association": "NONE",
    },
    {
        "number": 90,
        "state": "closed",
        "title": "typo in docs",
        "created_at": iso(ago(days=120)),
        "updated_at": iso(ago(days=8)),
        "closed_at": iso(ago(days=8)),
        "comments": 1,
        "user": _user("reporter3"),
        "author_association": "NONE",
    },
]

ISSUE_COMMENTS = [
    {
        "issue_url": "https://api.github.com/repos/acme/widget/issues/101",
        "created_at": iso(ago(days=2, hours=22)),
        "user": _user("maintainer"),
        "author_association": "MEMBER",
        "body": "Thanks, fixed in main.",
    },
    {
        "issue_url": "https://api.github.com/repos/acme/widget/issues/102",
        "created_at": iso(ago(days=11)),
        "user": _user("dependabot[bot]", "Bot"),
        "author_association": "NONE",
        "body": "This issue is stale.",
    },
    {
        "issue_url": "https://api.github.com/repos/acme/widget/issues/90",
        "created_at": iso(ago(days=9)),
        "user": _user("maintainer"),
        "author_association": "OWNER",
        "body": "Good catch.",
    },
]

PULLS = [
    {
        "number": 204,
        "state": "open",
        "title": "feat: async support",
        "created_at": iso(ago(days=10)),
        "updated_at": iso(ago(days=9)),
        "closed_at": None,
        "merged_at": None,
        "user": _user("erin"),
        "auto_merge": None,
    },
    {
        "number": 201,
        "state": "closed",
        "title": "chore(deps): bump urllib3",
        "created_at": iso(ago(days=6)),
        "updated_at": iso(ago(days=5)),
        "closed_at": iso(ago(days=5)),
        "merged_at": iso(ago(days=5)),
        "user": _user("dependabot[bot]", "Bot"),
        "auto_merge": {"enabled_by": _user("maintainer")},
    },
    {
        "number": 202,
        "state": "closed",
        "title": "chore(deps): bump certifi",
        "created_at": iso(ago(days=21)),
        "updated_at": iso(ago(days=20)),
        "closed_at": iso(ago(days=20)),
        "merged_at": iso(ago(days=20)),
        "user": _user("dependabot[bot]", "Bot"),
        "auto_merge": None,
    },
    {
        "number": 203,
        "state": "closed",
        "title": "fix: parser edge case",
        "created_at": iso(ago(days=34)),
        "updated_at": iso(ago(days=30)),
        "closed_at": iso(ago(days=30)),
        "merged_at": iso(ago(days=30)),
        "user": _user("dave"),
        "auto_merge": None,
    },
    {
        "number": 180,
        "state": "open",
        "title": "old proposal",
        "created_at": iso(ago(days=220)),
        "updated_at": iso(ago(days=60)),
        "closed_at": None,
        "merged_at": None,
        "user": _user("frank"),
        "auto_merge": None,
    },
]

PR_DETAILS = {
    201: {
        "number": 201,
        "title": "chore(deps): bump urllib3",
        "merged": True,
        "merged_by": _user("github-actions[bot]", "Bot"),
        "user": _user("dependabot[bot]", "Bot"),
        "review_comments": 0,
        "comments": 0,
        "commits": 1,
        "changed_files": 2,
    },
    202: {
        "number": 202,
        "title": "chore(deps): bump certifi",
        "merged": True,
        "merged_by": _user("dependabot[bot]", "Bot"),
        "user": _user("dependabot[bot]", "Bot"),
        "review_comments": 0,
        "comments": 0,
        "commits": 1,
        "changed_files": 1,
    },
    203: {
        "number": 203,
        "title": "fix: parser edge case",
        "merged": True,
        "merged_by": _user("maintainer"),
        "user": _user("dave"),
        "review_comments": 2,
        "comments": 3,
        "commits": 2,
        "changed_files": 4,
    },
}

RELEASES = [
    {"tag_name": "v1.1.0", "published_at": iso(ago(days=45)), "prerelease": False, "draft": False},
    {"tag_name": "v1.0.0", "published_at": iso(ago(days=200)), "prerelease": False, "draft": False},
    {"tag_name": "v1.0.0-rc1", "published_at": iso(ago(days=230)), "prerelease": True, "draft": False},
]

GITHUB_REPO = {
    "name": "widget",
    "full_name": "acme/widget",
    "owner": _user("acme", "Organization"),
    "html_url": "https://github.com/acme/widget",
    "archived": False,
    "disabled": False,
    "fork": False,
    "stargazers_count": 1234,
    "forks_count": 87,
    "open_issues_count": 5,
    "pushed_at": iso(ago(days=2)),
    "created_at": "2019-01-01T00:00:00Z",
    "default_branch": "main",
    "has_issues": True,
    "topics": ["widgets"],
    "license": {"spdx_id": "MIT", "name": "MIT License"},
}


def _release_files(version: str, upload_days: float) -> list[dict[str, Any]]:
    return [
        {
            "filename": f"widget-{version}.tar.gz",
            "upload_time_iso_8601": iso(ago(days=upload_days)),
        }
    ]


PYPI_WIDGET = {
    "info": {
        "name": "acme-widget",
        "version": "1.1.0",
        "summary": "A tiny widget library for testing",
        "requires_python": ">=3.9",
        "requires_dist": ["urllib3>=1.26,<3", "certifi>=2023.5.7", 'pytest; extra == "test"'],
        "classifiers": [
            "Development Status :: 5 - Production/Stable",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
        ],
        "project_urls": {"Source": "https://github.com/acme/widget", "Docs": "https://acme.test/docs"},
        "home_page": None,
        "license": "MIT",
        "yanked": False,
    },
    "releases": {
        "1.0.0": _release_files("1.0.0", 200),
        "1.0.1": _release_files("1.0.1", 150),
        "1.1.0": _release_files("1.1.0", 45),
    },
    "urls": _release_files("1.1.0", 45),
}

PYPI_DEP_VERSIONS = {"urllib3": "2.2.1", "certifi": "2024.2.2", "pytest": "8.2.0"}

OSV_CURRENT_VULN = {
    "id": "GHSA-test-1234-abcd",
    "aliases": ["CVE-2026-0001"],
    "summary": "Widget parser allows denial of service via crafted input",
    "published": iso(ago(days=30)),
    "modified": iso(ago(days=20)),
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "database_specific": {"severity": "HIGH"},
    "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-test-1234-abcd"}],
    "affected": [
        {
            "package": {"name": "acme-widget", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}],
                }
            ],
            "versions": ["1.0.0", "1.0.1", "1.1.0"],
        }
    ],
}

LONG_OPEN_BUG_ISSUE = {
    "number": 80,
    "state": "open",
    "title": "crash when parsing nested payload",
    "created_at": iso(ago(days=400)),
    "updated_at": iso(ago(days=2)),
    "closed_at": None,
    "comments": 0,
    "user": _user("reporter4"),
    "author_association": "NONE",
    "labels": [{"name": "bug"}, {"name": "crash"}],
}

OSV_URLLIB3_VULN = {
    "id": "GHSA-urllib3-1234-zzzz",
    "aliases": ["CVE-2025-1234"],
    "summary": "urllib3 proxy header leak",
    "published": iso(ago(days=400)),
    "modified": iso(ago(days=250)),
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "database_specific": {"severity": "HIGH"},
    "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-urllib3-1234-zzzz"}],
    "affected": [
        {
            "package": {"name": "urllib3", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.1"}]}],
            "versions": ["1.26.0"],
        }
    ],
}

OSV_FIXED_VULN = {
    "id": "GHSA-old-9999-zzzz",
    "aliases": ["CVE-2025-9999"],
    "summary": "Widget 1.0.0 accepted unsigned payloads",
    "published": iso(ago(days=300)),
    "modified": iso(ago(days=250)),
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"}],
    "database_specific": {"severity": "MEDIUM"},
    "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-old-9999-zzzz"}],
    "affected": [
        {
            "package": {"name": "acme-widget", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.1"}],
                }
            ],
            "versions": ["1.0.0"],
        }
    ],
}

EOL_PYTHON = [
    {"cycle": "3.15", "releaseDate": "2026-10-09", "eol": "2031-10-31", "support": "2028-10-09", "latest": "3.15.0"},
    {"cycle": "3.14", "releaseDate": "2025-10-07", "eol": "2030-10-31", "support": "2027-10-01", "latest": "3.14.8"},
    {"cycle": "3.13", "releaseDate": "2024-10-07", "eol": "2029-10-31", "support": "2026-10-01", "latest": "3.13.16"},
    {"cycle": "3.12", "releaseDate": "2023-10-02", "eol": "2028-10-31", "support": "2025-04-02", "latest": "3.12.15"},
    {"cycle": "3.11", "releaseDate": "2022-10-24", "eol": "2027-10-31", "support": "2024-04-01", "latest": "3.11.17"},
    {"cycle": "3.10", "releaseDate": "2021-10-04", "eol": "2026-10-01", "support": "2023-04-05", "latest": "3.10.18"},
    {"cycle": "3.9", "releaseDate": "2020-10-05", "eol": "2025-10-31", "support": "2022-04-05", "latest": "3.9.23"},
]

EOL_NODE = [
    {"cycle": "26", "releaseDate": "2026-05-05", "eol": "2029-04-30", "support": "2027-10-27", "latest": "26.12.0"},
    {"cycle": "24", "releaseDate": "2025-05-06", "eol": "2028-04-30", "support": "2026-10-20", "latest": "24.22.0", "lts": "2025-10-28"},
    {"cycle": "22", "releaseDate": "2024-04-24", "eol": "2027-04-30", "support": "2025-10-21", "latest": "22.20.0", "lts": "2024-10-29"},
    {"cycle": "20", "releaseDate": "2023-04-18", "eol": "2026-04-30", "support": "2024-10-22", "latest": "20.19.0", "lts": "2023-10-24"},
    {"cycle": "18", "releaseDate": "2022-04-19", "eol": "2025-04-30", "support": "2023-10-18", "latest": "18.20.0", "lts": "2022-10-25"},
]


class FakeAPI:
    """可调用对象，签名与 HttpClient 的 transport 一致。"""

    def __init__(
        self,
        *,
        vulnerable_dep: bool = False,
        dead_community: bool = False,
        stalled_stars: bool = False,
    ):
        self.calls: list[tuple[str, str]] = []
        self.vulnerable_dep = vulnerable_dep
        self.dead_community = dead_community
        self.stalled_stars = stalled_stars

    def __call__(self, method: str, url: str, headers: dict[str, str], body: Any) -> Response:
        self.calls.append((method, url))
        parsed = urlsplit(url)
        path = parsed.path
        query = parse_qs(parsed.query)
        if method == "POST":
            payload = json.loads(body or b"{}")
            if path == "/v1/query":
                return self._osv_query(url, payload)
            if path == "/v1/querybatch":
                return self._osv_querybatch(url, payload)
            return _json_response(url, {"error": "unknown POST"})

        if path.startswith("/v1/vulns/"):
            vuln_id = path.rsplit("/", 1)[-1]
            for vuln in (OSV_CURRENT_VULN, OSV_FIXED_VULN, OSV_URLLIB3_VULN):
                if vuln["id"] == vuln_id:
                    return _json_response(url, vuln)
            return _json_response(url, {"error": "not found"}, status=404)

        if "api.github.com" in (parsed.hostname or ""):
            return self._github(url, path, query)

        if parsed.hostname == "pypi.org":
            return self._pypi(url, path)

        if parsed.hostname == "endoflife.date":
            if "/python" in path:
                return _json_response(url, EOL_PYTHON)
            if "/nodejs" in path:
                return _json_response(url, EOL_NODE)
            return _json_response(url, [])

        return _json_response(url, {"error": f"no fake for {url}"}, status=404)

    # ------------------------------------------------------------------

    def _github(self, url: str, path: str, query: dict[str, list[str]]) -> Response:
        repo_match = re.match(r"^/repos/acme/widget(/.*)?$", path)
        if not repo_match:
            return _json_response(url, {"message": "Not Found"}, status=404)
        suffix = repo_match.group(1) or ""
        if suffix == "":
            return _json_response(url, GITHUB_REPO)
        if suffix == "/commits":
            return _json_response(url, COMMITS)
        if suffix == "/stats/participation":
            recent = [1, 0, 2, 1, 0, 1, 2, 1, 0, 1, 0, 1, 2]          # 13 周：合计 12 次
            history = ([2, 1, 2, 1, 3, 1, 2, 2, 1, 2, 1, 1, 2] * 3)   # 39 周：合计 60 次
            weekly = history + recent
            return _json_response(url, {"all": weekly, "owner": weekly})
        if suffix == "/events":
            if self.stalled_stars:
                # 近 90 天只有推送事件、没有新增 star/fork：社区热度停滞
                items = [
                    {"type": "PushEvent", "created_at": iso(ago(days=2 + i * 2))}
                    for i in range(40)
                ]
            else:
                # 高活跃仓库：100 条事件只覆盖 6 天，其中 5 个 WatchEvent
                items = [
                    {
                        "type": "WatchEvent" if i < 5 else "PushEvent",
                        "created_at": iso(ago(days=i * 0.06)),
                    }
                    for i in range(100)
                ]
            return _json_response(url, items)
        if suffix == "/stargazers":
            # 最新 100 个 star：10 个在近 90 天内，其余更早
            items = []
            for i in range(100):
                days = 10 if i < 10 else 200 + i
                items.append({"starred_at": iso(ago(days=days)), "user": _user(f"stargazer{i}")})
            return _json_response(url, items)
        if suffix == "/issues":
            issues = list(ISSUES)
            if self.dead_community:
                issues = issues + [LONG_OPEN_BUG_ISSUE]
            return _json_response(url, issues)
        if suffix == "/issues/comments":
            return _json_response(url, ISSUE_COMMENTS)
        if suffix == "/pulls":
            return _json_response(url, PULLS)
        detail_match = re.match(r"^/pulls/(\d+)$", suffix)
        if detail_match:
            number = int(detail_match.group(1))
            detail = PR_DETAILS.get(number)
            if detail:
                return _json_response(url, detail)
            return _json_response(url, {"message": "Not Found"}, status=404)
        if suffix == "/releases":
            return _json_response(url, RELEASES)
        return _json_response(url, {"error": f"no fake for {path}"}, status=404)

    def _pypi(self, url: str, path: str) -> Response:
        parts = [p for p in path.split("/") if p]
        # /pypi/{name}/json 或 /pypi/{name}/{version}/json
        if len(parts) >= 3 and parts[0] == "pypi" and parts[-1] == "json":
            name = parts[1].lower()
            if name == "acme-widget":
                payload = copy.deepcopy(PYPI_WIDGET)
                if self.vulnerable_dep:
                    payload["info"]["requires_dist"] = ["urllib3==1.26.0", "certifi>=2023.5.7"]
                if len(parts) == 4:
                    requested = parts[2]
                    files = payload["releases"].get(requested)
                    if not files:
                        return _json_response(url, {"message": "Not Found"}, status=404)
                    payload["info"]["version"] = requested
                    payload["urls"] = files
                return _json_response(url, payload)
            version = PYPI_DEP_VERSIONS.get(name)
            if version:
                return _json_response(
                    url,
                    {
                        "info": {
                            "name": name,
                            "version": version,
                            "requires_python": ">=3.8",
                            "classifiers": ["Programming Language :: Python :: 3.12"],
                            "project_urls": {"Source": "https://github.com/acme/" + name},
                        },
                        "releases": {version: _release_files(version, 30)},
                        "urls": _release_files(version, 30),
                    },
                )
            return _json_response(url, {"message": "Not Found"}, status=404)
        return _json_response(url, {"message": "Not Found"}, status=404)

    def _osv_query(self, url: str, payload: dict[str, Any]) -> Response:
        package = payload.get("package") or {}
        version = payload.get("version")
        if package.get("name") != "acme-widget":
            return _json_response(url, {"vulns": []})
        if version is None:
            return _json_response(url, {"vulns": [OSV_CURRENT_VULN, OSV_FIXED_VULN]})
        if version in ("1.1.0", "1.0.0"):
            return _json_response(url, {"vulns": [OSV_CURRENT_VULN]})
        return _json_response(url, {"vulns": []})

    def _osv_querybatch(self, url: str, payload: dict[str, Any]) -> Response:
        results = []
        for query in payload.get("queries") or []:
            package = query.get("package") or {}
            name = str(package.get("name") or "")
            version = str(query.get("version") or "")
            if self.vulnerable_dep and name == "urllib3" and version in ("1.26.0", "1.26"):
                results.append({"vulns": [{"id": "GHSA-urllib3-1234-zzzz", "modified": iso(ago(days=250))}]})
            else:
                results.append({})
        return _json_response(url, {"results": results})
