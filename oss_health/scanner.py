"""扫描编排：目标解析 -> 数据采集 -> 维度分析 -> 评分 -> 报告数据。"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .analyzers import dependencies as deps_analyzer
from .analyzers import framework as framework_analyzer
from .analyzers import issues as issues_analyzer
from .analyzers import maintenance as maintenance_analyzer
from .analyzers import pull_requests as prs_analyzer
from .analyzers import security as security_analyzer
from .config import (
    DEFAULT_DEP_CHECK,
    DEFAULT_PR_DETAIL,
    DEFAULT_WINDOW_DAYS,
    TOOL_VERSION,
)
from .http_client import HttpClient, HttpError, NotFound, OfflineMiss, RateLimited
from .models import PackageInfo, ScanReport, SourceRecord, Target
from .scoring import build_recommendations, compute
from .sources.eol import EOLSource
from .sources.github import GitHubSource
from .sources.npm import NpmSource
from .sources.nuget import NuGetSource
from .sources.osv import OSVSource
from .sources.pypi import PyPISource
from .util import (
    parse_github_url,
    parse_repo_slug,
    utcnow,
)

EXPLICIT_RE = re.compile(r"^(pypi|npm|nuget|github)\s*:\s*(.+)$", re.IGNORECASE)
_VERSION_HINT = re.compile(r"^v?\d+(?:\.\d+)*(?:[.\-+][0-9A-Za-z.\-+]+)?$")
_PACKAGE_ECO_ORDER = ("pypi", "npm", "nuget")


@dataclass
class ScanOptions:
    window_days: int = DEFAULT_WINDOW_DAYS
    pr_detail: int = DEFAULT_PR_DETAIL
    dep_check: int = DEFAULT_DEP_CHECK
    ecosystem: str = "auto"          # auto / pypi / npm / nuget / github
    version: Optional[str] = None
    repo_override: Optional[str] = None
    now_override: Optional[datetime] = None
    verbose: bool = False
    offline: bool = False


@dataclass
class Resolved:
    target: Target
    package: Optional[PackageInfo]


def _split_package_version(text: str, ecosystem: str) -> tuple[str, Optional[str]]:
    text = text.strip()
    if "==" in text:
        name, _, version = text.partition("==")
        return name.strip(), version.strip() or None
    if ecosystem == "github":
        return text, None
    at = text.rfind("@")
    if at > 0:  # 注意 scoped npm 包以 @ 开头，不能用 index 0
        version = text[at + 1 :].strip()
        name = text[:at].strip()
        if version and _VERSION_HINT.match(version) and "/" not in version:
            return name, version
    return text, None


class Scanner:
    def __init__(self, client: HttpClient, options: Optional[ScanOptions] = None):
        self.client = client
        self.options = options or ScanOptions()
        self.now = self.options.now_override or utcnow()
        self.pypi = PyPISource(client)
        self.npm = NpmSource(client)
        self.nuget = NuGetSource(client)
        self.eol = EOLSource(client)
        self.osv = OSVSource(client)
        self.github = GitHubSource(client)

    # ------------------------------------------------------------------

    def _log(self, message: str) -> None:
        if self.options.verbose:
            import sys

            print(f"[scan] {message}", file=sys.stderr)

    def scan(self, raw_input: str) -> ScanReport:
        started = time.time()
        raw_input = (raw_input or "").strip()
        if not raw_input:
            raise ValueError("扫描目标不能为空")
        target = self._resolve_target(raw_input)
        self._log(f"目标: {target.display()}")

        package: Optional[PackageInfo] = None
        if target.ecosystem != "github":
            package, target = self._fetch_package(target)
            self._log(f"包元数据: {package.name} {package.version}")
        else:
            target = Target(
                ecosystem="github",
                name=parse_repo_slug(target.name) or target.name,
                raw_input=raw_input,
            )

        repo = None
        repo_slug = target.repo_slug
        if package is not None and not repo_slug:
            repo_slug = parse_github_url(package.repo_url)
        sources: list[SourceRecord] = []
        warnings: list[str] = []

        if package is not None:
            sources.append(
                SourceRecord(
                    name=f"{package.ecosystem} registry",
                    url=package.source,
                    retrieved_at=self.now,
                )
            )

        if repo_slug:
            from .util import parse_owner_repo

            owner, name = parse_owner_repo(repo_slug)
            self._log(f"采集 GitHub: {repo_slug}（窗口 {self.options.window_days} 天）")
            try:
                repo = self.github.fetch(
                    repo_slug,
                    window_days=self.options.window_days,
                    pr_detail=self.options.pr_detail,
                    now=self.now,
                )
                sources.append(
                    SourceRecord(
                        name="GitHub API",
                        url=f"https://github.com/{repo_slug}",
                        retrieved_at=self.now,
                    )
                )
                warnings.extend(repo.warnings)
            except NotFound:
                warnings.append(f"GitHub 仓库 {repo_slug} 不存在或不可访问，跳过仓库维度")
            except RateLimited as exc:
                warnings.append(f"GitHub 配额不足，跳过仓库维度：{exc}")
            except HttpError as exc:
                warnings.append(f"GitHub 采集失败，跳过仓库维度：{exc}")
        elif package is not None:
            warnings.append("包元数据中没有可识别的 GitHub 仓库地址，无法评估维护 / Issue / PR 维度")

        # ---- 维度分析 ----
        dim_maintenance = maintenance_analyzer.analyze(repo, package, self.now)
        # 「治理信号」开关：Issue/PR 维度是否也给出了有效证据（用于补充判断「真人维护」）
        governance = self._has_governance(dim_maintenance)
        dim_issues = issues_analyzer.analyze(repo, self.now, governance=governance)
        dim_prs = prs_analyzer.analyze(repo, self.now)

        self._log("检查运行时 / target framework ...")
        assessment, dim_framework = framework_analyzer.analyze(package, self.eol, self.now)
        sources.append(
            SourceRecord(name="endoflife.date", url="https://endoflife.date", retrieved_at=self.now)
        )
        warnings.extend(assessment.warnings)

        self._log("查询 OSV.dev 漏洞库 ...")
        security, dim_security = security_analyzer.analyze(package, self.osv, self.now)
        sources.append(
            SourceRecord(name="OSV.dev", url="https://osv.dev", retrieved_at=self.now)
        )
        if security is not None:
            warnings.extend(security.warnings)

        self._log("检查直接依赖 ...")
        resolver = deps_analyzer.DependencyResolver(
            package.ecosystem if package else "",
            pypi=self.pypi,
            npm=self.npm,
            nuget=self.nuget,
        )
        dep_risks, dim_deps = deps_analyzer.analyze(
            package, self.osv, resolver, self.now, limit=self.options.dep_check
        )
        if package is not None:
            warnings.extend(dim_deps.notes)

        dimensions = [
            dim_maintenance,
            dim_issues,
            dim_prs,
            dim_framework,
            dim_security,
            dim_deps,
        ]
        for dim in dimensions:
            self._log(f"  {dim.title}: {dim.score if dim.available else '无数据'}")

        result = compute(dimensions, repo=repo, package=package, security=security)
        recommendations = build_recommendations(
            dimensions,
            repo=repo,
            package=package,
            security=security,
            framework=assessment,
            dep_risks=dep_risks,
            result=result,
        )
        for flag in result.hard_flags:
            warnings.append(f"一票否决：{flag.reason}")

        report = ScanReport(
            input=raw_input,
            target=target,
            generated_at=self.now,
            package=package,
            repo=repo,
            framework=assessment,
            security=security,
            dep_risks=dep_risks,
            dimensions=dimensions,
            raw_total=result.raw_total,
            total_score=result.total_score,
            grade=result.grade,
            verdict=result.verdict,
            verdict_level=result.verdict_level,
            confidence=result.confidence,
            confidence_reasons=result.confidence_reasons,
            hard_flags=result.hard_flags,
            recommendations=recommendations,
            warnings=warnings,
            sources=sources,
            tool_version=TOOL_VERSION,
            offline=self.options.offline,
            duration_seconds=round(time.time() - started, 2),
        )
        report.extra["github_remaining"] = self.client.github_remaining
        report.extra["github_limit"] = self.client.github_limit
        report.extra["requests_made"] = self.client.request_count
        report.extra["cache_hits"] = self.client.cache_hits
        report.extra["offline_hits"] = self.client.offline_hits
        report.extra["window_days"] = self.options.window_days
        return report

    @staticmethod
    def _has_governance(dim_maintenance) -> bool:
        """提交维度里真人是否在做实质维护。"""
        if not dim_maintenance.available:
            return False
        human = dim_maintenance.metrics.get("human_commits") or 0
        substantive = dim_maintenance.metrics.get("substantive_human_commits")
        if substantive is None:
            return human > 0
        return human > 0 and substantive > 0

    # ------------------------------------------------------------------
    # 目标解析
    # ------------------------------------------------------------------

    def _resolve_target(self, raw: str) -> Target:
        explicit = EXPLICIT_RE.match(raw)
        if explicit:
            ecosystem = explicit.group(1).lower()
            rest = explicit.group(2).strip()
            if ecosystem == "github":
                slug = parse_repo_slug(rest) or parse_repo_slug(parse_github_url(rest) or "")
                if not slug:
                    raise ValueError(f"无法识别的 GitHub 仓库：{rest}（示例：github:psf/requests）")
                return Target(
                    ecosystem="github",
                    name=slug,
                    repo_override=self._repo_override(),
                    raw_input=raw,
                )
            name, version = _split_package_version(rest, ecosystem)
            if not name:
                raise ValueError(f"无法识别的包名：{rest}")
            return Target(
                ecosystem=ecosystem,
                name=name,
                version=self.options.version or version,
                repo_override=self._repo_override(),
                raw_input=raw,
            )

        # GitHub URL
        if raw.startswith(("http://", "https://", "git@")):
            slug = parse_repo_slug(raw)
            if not slug:
                raise ValueError("目前只支持 GitHub 仓库 URL（https://github.com/owner/repo）")
            return Target(ecosystem="github", name=slug, raw_input=raw)

        if raw.startswith("@"):
            # scoped npm 包
            name, version = _split_package_version(raw, "npm")
            return Target(
                ecosystem="npm" if self.options.ecosystem in ("auto", "npm") else self.options.ecosystem,
                name=name,
                version=self.options.version or version,
                raw_input=raw,
            )

        # owner/repo 形式
        if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", raw):
            return Target(ecosystem="github", name=raw, raw_input=raw)

        name, version = _split_package_version(raw, "pypi")
        ecosystem = self.options.ecosystem
        if ecosystem != "auto":
            return Target(
                ecosystem=ecosystem,
                name=name,
                version=self.options.version or version,
                raw_input=raw,
            )
        return Target(ecosystem="auto", name=name, version=self.options.version or version, raw_input=raw)

    def _repo_override(self) -> Optional[str]:
        if not self.options.repo_override:
            return None
        slug = parse_repo_slug(self.options.repo_override)
        if not slug:
            raise ValueError(f"--repo 需要 owner/repo 形式：{self.options.repo_override}")
        return slug

    # ------------------------------------------------------------------

    def _fetch_package(self, target: Target) -> tuple[PackageInfo, Target]:
        if target.ecosystem == "auto":
            last_error: Optional[Exception] = None
            for ecosystem in _PACKAGE_ECO_ORDER:
                try:
                    package = self._fetch_one(ecosystem, target.name, target.version)
                    return package, Target(
                        ecosystem=ecosystem,
                        name=package.name,
                        version=target.version,
                        repo_override=target.repo_override,
                        raw_input=target.raw_input,
                    )
                except NotFound as exc:
                    last_error = exc
                    continue
                except OfflineMiss:
                    raise OfflineMiss(
                        "离线快照中不包含该目标的自动探测响应，请显式指定生态，例如 pypi:requests"
                    )
            raise NotFound(
                f"在 PyPI / npm / NuGet 上都没有找到包「{target.name}」"
                f"（可用 --ecosystem 显式指定生态）。最后一个错误：{last_error}"
            )
        package = self._fetch_one(target.ecosystem, target.name, target.version)
        return package, target

    def _fetch_one(self, ecosystem: str, name: str, version: Optional[str]) -> PackageInfo:
        try:
            if ecosystem == "pypi":
                return self.pypi.resolve(name, version)
            if ecosystem == "npm":
                return self.npm.resolve(name, version)
            if ecosystem == "nuget":
                return self.nuget.resolve(name, version)
        except NotFound:
            raise
        raise ValueError(f"不支持的生态：{ecosystem}")
