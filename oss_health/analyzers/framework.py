"""运行时 / target framework 现代化分析。

判断包的「目标运行时」是否还在官方支持周期内：

* PyPI  -> Python 版本（classifiers + requires_python），对照 endoflife.date
* npm   -> engines.node，对照 Node.js 支持周期（含 semver range 判断）
* NuGet -> 目标框架 TFM 列表，对照 .NET 支持周期

数据缺失时该维度标记为不可用，不参与加权，并降低报告置信度。
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from ..config import WEIGHTS, ECOSYSTEM_RUNTIME, EOL_PRODUCTS
from ..models import Dimension, FrameworkAssessment, PackageInfo
from ..sources.eol import Cycle, EOLSource
from ..http_client import HttpError
from ..util import fmt_date
from ..versions import compare_versions, satisfies_npm_range

_PY_MIN_RE = re.compile(r"(?:>=|==|~=)\s*(\d+)\.(\d+)")
_PY_MAX_RE = re.compile(r"<\s*(\d+)\.(\d+)")
_NET_MODERN_RE = re.compile(r"^net(\d+)\.0")
_NET_LEGACY_RE = re.compile(r"^(net4\d{2}|net3\d{2}|portable|netplatform)")


def _fmt_cycles(cycles: list[str]) -> str:
    return "、".join(cycles) if cycles else "—"


def _new_assessment(runtime: str = "") -> FrameworkAssessment:
    return FrameworkAssessment(runtime=runtime)


def analyze(
    package: Optional[PackageInfo],
    eol: EOLSource,
    now: datetime,
) -> tuple[FrameworkAssessment, Dimension]:
    dim = Dimension(
        key="framework",
        title="运行时 / 框架",
        weight=WEIGHTS["framework"],
        score=100,
        metrics={},
        evidence=[],
    )
    if package is None:
        assessment = _new_assessment()
        assessment.evidence.append("没有包元数据，无法判断运行时支持情况")
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("缺少包元数据，无法评估运行时/框架现代化程度")
        return assessment, dim

    runtime = ECOSYSTEM_RUNTIME.get(package.ecosystem)
    if not runtime:
        assessment = _new_assessment()
        assessment.evidence.append(f"{package.ecosystem} 生态暂不支持运行时周期检查")
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("该生态暂不支持运行时支持周期检查")
        return assessment, dim

    display_runtime = EOL_PRODUCTS.get(runtime, runtime)
    try:
        cycles = eol.product(runtime)
    except (HttpError, ValueError) as exc:
        assessment = _new_assessment(display_runtime)
        assessment.warnings.append(f"无法获取 endoflife.date 数据：{exc}")
        assessment.evidence.append("官方支持周期数据获取失败，无法判断是否落后")
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("缺少官方运行时支持周期数据")
        return assessment, dim

    if not cycles:
        assessment = _new_assessment(display_runtime)
        dim.available = False
        dim.status = "unknown"
        dim.notes.append("官方支持周期数据为空")
        return assessment, dim

    latest_cycle = eol.latest_cycle(runtime)
    supported = [c for c in cycles if not c.is_eol(now)]
    supported_labels = [c.cycle for c in supported]
    eol_cycles = {c.cycle for c in cycles if c.is_eol(now)}

    if package.ecosystem == "pypi":
        assessment = _analyze_python(package, dim, cycles, latest_cycle, supported, eol_cycles, now)
    elif package.ecosystem == "npm":
        assessment = _analyze_node(package, dim, cycles, latest_cycle, supported, eol_cycles, now)
    else:
        assessment = _analyze_dotnet(package, dim, cycles, latest_cycle, supported, eol_cycles, now)

    assessment.runtime = display_runtime
    assessment.latest_supported = latest_cycle.cycle if latest_cycle else ""
    assessment.supported_cycles = supported_labels
    assessment.eol_declared = [v for v in assessment.declared if _cycle_of(v) in eol_cycles]
    if assessment.status == "unknown":
        dim.available = False
        dim.status = "unknown"
    else:
        dim.available = True
        penalty = sum(d.points for d in dim.deductions)
        dim.score = max(0, min(100, assessment.score - penalty))
        dim.status = _status_from_score(dim.score)
    dim.evidence.extend(assessment.evidence)
    dim.metrics.update(assessment.details)
    if assessment.gap is not None:
        dim.metrics["gap"] = assessment.gap
    return assessment, dim


def _cycle_of(value: str) -> str:
    value = str(value).strip()
    m = re.match(r"^(\d+(?:\.\d+)?)", value)
    return m.group(1) if m else value


def _status_from_score(score: int) -> str:
    if score >= 80:
        return "good"
    if score >= 50:
        return "warn"
    return "bad"


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def _analyze_python(
    package: PackageInfo,
    dim: Dimension,
    cycles: list[Cycle],
    latest_cycle: Optional[Cycle],
    supported: list[Cycle],
    eol_cycles: set[str],
    now: datetime,
) -> FrameworkAssessment:
    assessment = _new_assessment("Python")
    declared = list(package.python_versions)
    requires = package.requires_python or ""
    assessment.declared = declared or ([f"requires_python {requires}"] if requires else [])
    latest_label = latest_cycle.cycle if latest_cycle else ""

    def cycle_for(minor: str) -> Optional[Cycle]:
        for c in cycles:
            if c.cycle == minor:
                return c
        return None

    if declared:
        assessment.evidence.append(
            f"声明测试/支持的 Python 版本：{_fmt_cycles(declared)}（PyPI classifiers）"
        )
        max_declared = declared[-1]
        gap = 0
        for c in cycles:
            if compare_versions(c.cycle, max_declared, "generic") > 0:
                gap += 1
        assessment.gap = gap
        if gap == 0:
            assessment.score = 100
            assessment.evidence.append(f"已跟进当前最新 Python {latest_label}")
        elif gap == 1:
            assessment.score = 82
            assessment.evidence.append(f"比最新 Python {latest_label} 落后 1 个版本")
        elif gap == 2:
            assessment.score = 62
            assessment.evidence.append(f"比最新 Python {latest_label} 落后 2 个版本")
        elif gap == 3:
            assessment.score = 44
            assessment.evidence.append(f"比最新 Python {latest_label} 落后 3 个版本")
        else:
            assessment.score = 24
            assessment.evidence.append(f"比最新 Python {latest_label} 落后 {gap} 个版本")

        declared_eol = [v for v in declared if v in eol_cycles]
        if declared_eol:
            assessment.evidence.append(
                "以下声明支持的 Python 版本已结束官方支持："
                + "、".join(
                    f"{v}（EOL {fmt_date(cycle_for(v).eol) if cycle_for(v) else '?'}）"
                    for v in declared_eol
                )
            )
            if len(declared_eol) == len(declared):
                assessment.score = min(assessment.score, 25)
                dim.add(25, "只声明支持已经 EOL 的 Python 版本")
            else:
                dim.add(8, f"仍声明支持 {len(declared_eol)} 个已 EOL 的 Python 版本")
    elif requires:
        assessment.evidence.append(f"requires_python: {requires}")
        min_match = _PY_MIN_RE.search(requires)
        max_match = _PY_MAX_RE.search(requires)
        if min_match:
            min_label = f"{min_match.group(1)}.{min_match.group(2)}"
            assessment.declared = [f"≥{min_label}"]
            if max_match:
                max_label = f"{max_match.group(1)}.{max_match.group(2)}"
                assessment.declared.append(f"<{max_label}")
                if compare_versions(max_label, latest_label, "generic") <= 0:
                    assessment.score = 22
                    assessment.status = "eol"
                    assessment.evidence.append(
                        f"requires_python 上界 <{max_label}，无法安装到最新 Python {latest_label}"
                    )
                    dim.add(40, f"声明不支持 Python {latest_label} 及更新版本")
                    return assessment
            assessment.score = 74
            assessment.evidence.append("未提供 classifiers，只能从 requires_python 推断（按「基本可用」计）")
            if min_label in eol_cycles:
                dim.add(8, f"最低要求 Python {min_label} 已 EOL")
        else:
            assessment.score = 55
            assessment.evidence.append("requires_python 未给出可用信息")
    else:
        assessment.evidence.append("包没有声明 Python 版本支持信息")
        assessment.status = "unknown"
        return assessment

    assessment.details = {
        "runtime": "Python",
        "declared": assessment.declared,
        "latest_runtime": latest_label,
        "supported_cycles": assessment.supported_cycles,
        "eol_declared": sorted(set(assessment.eol_declared or [v for v in declared if v in eol_cycles])),
    }
    assessment.status = _assessment_status(assessment.score)
    return assessment


# ---------------------------------------------------------------------------
# Node.js
# ---------------------------------------------------------------------------


def _analyze_node(
    package: PackageInfo,
    dim: Dimension,
    cycles: list[Cycle],
    latest_cycle: Optional[Cycle],
    supported: list[Cycle],
    eol_cycles: set[str],
    now: datetime,
) -> FrameworkAssessment:
    assessment = _new_assessment("Node.js")
    engines = package.node_engines
    latest_label = latest_cycle.cycle if latest_cycle else ""
    assessment.supported_cycles = [c.cycle for c in supported]
    if not engines:
        assessment.evidence.append("package.json 没有声明 engines.node，无法判断支持的 Node 版本")
        assessment.status = "unknown"
        return assessment
    assessment.declared = [engines]
    assessment.evidence.append(f"engines.node: {engines}")

    def allowed(cycle: str) -> bool:
        return bool(satisfies_npm_range(f"{cycle}.0.0", engines))

    supported_allowed = [c.cycle for c in supported if allowed(c.cycle)]
    latest_allowed = bool(latest_cycle and allowed(latest_cycle.cycle))
    any_allowed = [c.cycle for c in cycles if allowed(c.cycle)]

    if latest_allowed:
        assessment.score = 95
        if len(supported_allowed) == len(supported):
            assessment.evidence.append(
                f"可用于当前受支持的所有 Node 版本（{_fmt_cycles(assessment.supported_cycles)}）"
            )
        else:
            assessment.evidence.append(
                f"可用于最新 Node {latest_label}，以及 {_fmt_cycles(supported_allowed)}"
            )
    elif supported_allowed:
        assessment.score = 78
        assessment.evidence.append(
            f"不支持最新的 Node {latest_label}，但支持仍在维护的 {_fmt_cycles(supported_allowed)}"
        )
        dim.add(6, f"engines 排除了最新 Node {latest_label}")
    elif any_allowed:
        assessment.score = 32
        assessment.status = "eol"
        assessment.evidence.append(
            f"engines.node 只允许已 EOL 的 Node 版本：{_fmt_cycles(any_allowed)}"
        )
        dim.add(35, f"只允许在已 EOL 的 Node 版本上运行（{_fmt_cycles(any_allowed)}）")
    else:
        assessment.score = 20
        assessment.status = "eol"
        assessment.evidence.append("无法解析 engines.node 范围，或它排除了所有已知 Node 版本")
        dim.add(40, "engines.node 无法匹配任何已知 Node 版本")

    floor = min(package.node_versions) if package.node_versions else None
    if floor is not None:
        assessment.details["engine_floor_major"] = floor
        gap = 0
        if latest_cycle:
            gap = max(0, int(latest_cycle.cycle) - floor)
        assessment.gap = gap
        if floor in {int(x) for x in eol_cycles if x.isdigit()}:
            assessment.evidence.append(f"engines 下限 Node {floor} 已结束支持（仅代表兼容，不影响新版本安装）")
            dim.add(4, f"仍允许早已 EOL 的 Node {floor}（兼容性下限过低）")

    assessment.details.update(
        {
            "runtime": "Node.js",
            "declared": [engines],
            "latest_runtime": latest_label,
            "supported_cycles": assessment.supported_cycles,
            "eol_declared": [v for v in any_allowed if v in eol_cycles],
        }
    )
    assessment.status = _assessment_status(assessment.score)
    return assessment


# ---------------------------------------------------------------------------
# .NET
# ---------------------------------------------------------------------------


def _analyze_dotnet(
    package: PackageInfo,
    dim: Dimension,
    cycles: list[Cycle],
    latest_cycle: Optional[Cycle],
    supported: list[Cycle],
    eol_cycles: set[str],
    now: datetime,
) -> FrameworkAssessment:
    assessment = _new_assessment(".NET")
    tfms = list(package.target_frameworks)
    supported_majors = {c.cycle for c in supported}
    latest_label = latest_cycle.cycle if latest_cycle else ""
    assessment.supported_cycles = sorted(supported_majors, key=lambda x: int(x) if x.isdigit() else 0)
    if not tfms:
        assessment.evidence.append("NuGet 元数据没有目标框架信息")
        assessment.status = "unknown"
        return assessment
    assessment.declared = tfms
    assessment.evidence.append(f"目标框架：{_fmt_cycles(tfms)}")

    modern: list[tuple[int, str]] = []
    for tfm in tfms:
        m = _NET_MODERN_RE.match(tfm)
        if m:
            modern.append((int(m.group(1)), tfm))
    netstandard = [t for t in tfms if t.startswith("netstandard")]
    legacy = [t for t in tfms if _NET_LEGACY_RE.match(t)]

    if modern:
        max_major, max_tfm = max(modern)
        assessment.details["max_tfm"] = max_tfm
        if not latest_cycle:
            assessment.status = "unknown"
            return assessment
        gap = int(latest_label) - max_major if latest_label.isdigit() else 0
        assessment.gap = max(0, gap)
        if max_major >= int(latest_label):
            assessment.score = 100
            assessment.evidence.append(f"已跟进最新 .NET {latest_label}（{max_tfm}）")
        elif str(max_major) in supported_majors:
            assessment.score = 88
            assessment.evidence.append(
                f"目标框架 {max_tfm} 仍在支持周期内，但未跟进最新 .NET {latest_label}"
            )
            dim.add(5, f"未跟进最新 .NET {latest_label}")
        else:
            if gap <= 1:
                assessment.score = 68
            elif gap <= 2:
                assessment.score = 48
            elif gap <= 3:
                assessment.score = 30
            else:
                assessment.score = 18
            assessment.evidence.append(
                f"最新目标框架 {max_tfm} 已 EOL，官方最新为 .NET {latest_label}"
            )
            dim.add(20, f"最新目标框架 {max_tfm} 已结束支持")
        cycle = next((c for c in cycles if c.cycle == str(max_major)), None)
        if cycle and cycle.eol and 0 <= (cycle.eol - now).days <= 180:
            assessment.evidence.append(
                f"注意：.NET {max_major} 将于 {fmt_date(cycle.eol)} 结束支持"
            )
            dim.add(6, f".NET {max_major} 即将 EOL（{fmt_date(cycle.eol)}）")
        if netstandard:
            assessment.evidence.append(
                f"同时提供 {_fmt_cycles(netstandard)} 兼容目标，可在受支持的 .NET 上使用"
            )
    elif netstandard:
        assessment.score = 68
        assessment.evidence.append(
            "只提供 netstandard 目标：可在现代 .NET 上运行，但没有针对新版 TFM 优化"
        )
        dim.add(8, "未提供现代 .NET TFM")
    elif legacy:
        assessment.score = 20
        assessment.status = "eol"
        assessment.evidence.append(f"只有传统 .NET Framework 目标：{_fmt_cycles(legacy)}")
        dim.add(40, "只支持已停止支持的 .NET Framework / PCL")
    else:
        assessment.score = 40
        assessment.evidence.append("无法识别目标框架类型")
        dim.add(20, "无法识别目标框架类型")

    assessment.details.update(
        {
            "runtime": ".NET",
            "declared": tfms,
            "latest_runtime": latest_label,
            "supported_cycles": assessment.supported_cycles,
            "eol_declared": [t for t in legacy],
        }
    )
    assessment.status = _assessment_status(assessment.score)
    return assessment


def _assessment_status(score: int) -> str:
    if score >= 80:
        return "current"
    if score >= 50:
        return "lagging"
    return "eol"
