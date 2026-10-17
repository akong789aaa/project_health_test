"""跨生态版本号比较（PyPI / npm / NuGet），纯标准库实现。

* PyPI: 优先使用 ``packaging``（若已安装，它是事实标准），否则用内置 PEP 440 子集实现。
* npm: SemVer 2.0。
* NuGet: 4 段数字版本 + 预发布标签。

只做「比较 / 是否落在范围内」这些扫描器真正需要的事，不实现完整解析器。
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

try:  # pragma: no cover - 环境相关
    from packaging.version import InvalidVersion as _PkgInvalidVersion
    from packaging.version import Version as _PkgVersion

    _HAS_PACKAGING = True
except Exception:  # pragma: no cover
    _HAS_PACKAGING = False
    _PkgVersion = None  # type: ignore[assignment]
    _PkgInvalidVersion = Exception  # type: ignore[assignment]


_LEADING_V = re.compile(r"^[vV]")
_NUM = re.compile(r"\d+")


def normalize(version: str) -> str:
    """去空白、去前导 v，保留其余信息。"""
    v = (version or "").strip()
    v = _LEADING_V.sub("", v)
    return v


def is_prerelease(version: str, ecosystem: str = "generic") -> bool:
    v = normalize(version).lower()
    if not v:
        return False
    if ecosystem == "pypi":
        return bool(re.search(r"(?:a|b|rc|alpha|beta|dev)[-.]?\d*$", v)) or ".dev" in v
    # npm / nuget: '-' 后是预发布标签
    return "-" in v


def _pad(parts: Iterable[int], n: int = 6) -> tuple[int, ...]:
    vals = list(parts)[:n]
    while len(vals) < n:
        vals.append(0)
    return tuple(vals)


# ---------------------------------------------------------------------------
# PEP 440（内置子集，仅在 packaging 不可用时使用）
# ---------------------------------------------------------------------------

_PEP440_RE = re.compile(
    r"""^
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?P<pre>[-_.]?(?P<pre_l>a|alpha|b|beta|c|rc|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?P<post>(?:[-_.]?post[-_.]?(?P<post_n>\d+)?))?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    $""",
    re.VERBOSE | re.IGNORECASE,
)

_PRE_RANK = {"a": 1, "alpha": 1, "b": 2, "beta": 2, "c": 3, "rc": 3, "pre": 3, "preview": 3}


def _fallback_pep440_key(version: str) -> tuple[int, tuple[int, ...], int, int]:
    v = normalize(version).lower()
    m = _PEP440_RE.match(v)
    if not m:
        # 完全无法解析：退化为通用数字比较，保证可比较
        nums = tuple(int(x) for x in _NUM.findall(v))
        return (0, _pad(nums), 4, 0)
    epoch = int(m.group("epoch") or 0)
    release = _pad(int(x) for x in m.group("release").split("."))
    pre_l = m.group("pre_l")
    dev_n = m.group("dev_n")
    post_n = m.group("post_n")
    pre_n = int(m.group("pre_n") or 0)
    has_post = m.group("post") is not None
    has_dev = m.group("dev") is not None
    if pre_l:
        phase, phase_n = _PRE_RANK.get(pre_l.lower(), 3), pre_n
        if has_dev:
            phase, phase_n = 0, int(dev_n or 0)  # 1.0rc1.dev2 < 1.0rc1
    elif has_dev:
        phase, phase_n = 0, int(dev_n or 0)
    elif has_post:
        phase, phase_n = 5, int(post_n or 0)
    else:
        phase, phase_n = 4, 0
    return (epoch, release, phase, phase_n)


def _pep440_key(version: str) -> Any:
    v = normalize(version)
    if _HAS_PACKAGING:
        try:
            return _PkgVersion(v)
        except _PkgInvalidVersion:
            pass
    return _fallback_pep440_key(v)


# ---------------------------------------------------------------------------
# SemVer（npm）
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"^(?P<core>\d+(?:\.\d+){0,2})(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_pre_key(pre: Optional[str]) -> tuple:
    if not pre:
        return ((2,),)  # 正式版 > 预发布
    parts = []
    for ident in pre.split("."):
        if ident.isdigit():
            parts.append((0, int(ident)))
        else:
            parts.append((1, ident.lower()))
    return tuple(parts)


def _semver_key(version: str) -> tuple:
    v = normalize(version)
    m = _SEMVER_RE.match(v)
    if not m:
        nums = tuple(int(x) for x in _NUM.findall(v))
        return (_pad(nums, 3), ((1,),))
    core = tuple(int(x) for x in m.group("core").split("."))
    return (_pad(core, 3), _semver_pre_key(m.group("pre")))


def _semver_cmp(a: str, b: str) -> int:
    ka, kb = _semver_key(a), _semver_key(b)
    if ka < kb:
        return -1
    if ka > kb:
        return 1
    return 0


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------

_NUGET_RE = re.compile(r"^(?P<core>\d+(?:\.\d+){0,3})(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _nuget_key(version: str) -> tuple:
    v = normalize(version)
    m = _NUGET_RE.match(v)
    if not m:
        nums = tuple(int(x) for x in _NUM.findall(v))
        return (_pad(nums, 4), ((1,),))
    core = tuple(int(x) for x in m.group("core").split("."))
    pre = m.group("pre")
    if not pre:
        pre_key: tuple = ((2,),)
    else:
        pre_key = tuple(
            (0, int(p)) if p.isdigit() else (1, p.lower()) for p in pre.split(".")
        )
    return (_pad(core, 4), pre_key)


# ---------------------------------------------------------------------------
# 公共 API
# ---------------------------------------------------------------------------


def compare_versions(a: str, b: str, ecosystem: str = "generic") -> int:
    """比较两个版本号：a<b 返回 -1，a==b 返回 0，a>b 返回 1。"""
    a2, b2 = normalize(a), normalize(b)
    if a2 == b2:
        return 0
    eco = (ecosystem or "generic").lower()
    try:
        if eco == "pypi":
            ka, kb = _pep440_key(a2), _pep440_key(b2)
            if isinstance(ka, tuple) and isinstance(kb, tuple):
                return (ka > kb) - (ka < kb)
            if ka < kb:  # type: ignore[operator]
                return -1
            if ka > kb:  # type: ignore[operator]
                return 1
            return 0
        if eco == "npm":
            return _semver_cmp(a2, b2)
        if eco == "nuget":
            ka, kb = _nuget_key(a2), _nuget_key(b2)
            return (ka > kb) - (ka < kb)
    except Exception:
        pass
    # generic：拆数字段比较
    na = tuple(int(x) for x in _NUM.findall(a2))
    nb = tuple(int(x) for x in _NUM.findall(b2))
    if na != nb:
        return (na > nb) - (na < nb)
    pa = is_prerelease(a2, eco)
    pb = is_prerelease(b2, eco)
    if pa != pb:
        return -1 if pa else 1
    return (a2 > b2) - (a2 < b2)


def equal_versions(a: str, b: str, ecosystem: str = "generic") -> bool:
    if normalize(a) == normalize(b):
        return True
    try:
        return compare_versions(a, b, ecosystem) == 0
    except Exception:
        return False


def latest_version(versions: Iterable[str], ecosystem: str = "generic") -> Optional[str]:
    best: Optional[str] = None
    for v in versions:
        if not v or not normalize(v):
            continue
        if best is None or compare_versions(v, best, ecosystem) > 0:
            best = v
    return best


def sort_versions(versions: Iterable[str], ecosystem: str = "generic") -> list[str]:
    import functools

    return sorted(versions, key=functools.cmp_to_key(lambda x, y: compare_versions(x, y, ecosystem)))


def in_range(
    version: str,
    *,
    introduced: Optional[str] = None,
    fixed: Optional[str] = None,
    last_affected: Optional[str] = None,
    ecosystem: str = "generic",
) -> bool:
    """判断版本是否落在 OSV 的 [introduced, fixed) 或 (introduced, last_affected] 区间。"""
    v = normalize(version)
    if introduced and introduced != "0":
        try:
            if compare_versions(v, introduced, ecosystem) < 0:
                return False
        except Exception:
            pass
    if fixed:
        try:
            if compare_versions(v, fixed, ecosystem) >= 0:
                return False
        except Exception:
            return False
    if last_affected:
        try:
            if compare_versions(v, last_affected, ecosystem) > 0:
                return False
        except Exception:
            return False
    return True


# ---------------------------------------------------------------------------
# npm engines 范围判断（SemVer range 的常用子集）
# ---------------------------------------------------------------------------

_NPM_CLAUSE_RE = re.compile(
    r"^(>=|<=|>|<|=|\^|~)?\s*v?(\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?|\*|x|X)$"
)


def _clause_holds(version: str, clause: str) -> Optional[bool]:
    clause = clause.strip()
    if not clause:
        return True
    if clause in ("*", "x", "X"):
        return True
    m = _NPM_CLAUSE_RE.match(clause)
    if not m:
        return None
    op = m.group(1) or "="
    bound = m.group(2)
    if bound in ("*", "x", "X"):
        return True
    # 按核心版本比较
    core = normalize(version)
    if op == ">=":
        return compare_versions(core, bound, "npm") >= 0
    if op == ">":
        return compare_versions(core, bound, "npm") > 0
    if op == "<=":
        return compare_versions(core, bound, "npm") <= 0
    if op == "<":
        return compare_versions(core, bound, "npm") < 0
    if op == "^":
        major, minor, patch = _core_parts(bound)
        if compare_versions(core, bound, "npm") < 0:
            return False
        if major > 0:
            return _major_of(core) == major
        if minor > 0:
            return _major_of(core) == 0 and _minor_of(core) == minor
        return (_major_of(core), _minor_of(core), _patch_of(core)) == (0, 0, patch)
    if op == "~":
        major, minor, _ = _core_parts(bound)
        if compare_versions(core, bound, "npm") < 0:
            return False
        return (_major_of(core), _minor_of(core)) == (major, minor)
    # 精确匹配
    return compare_versions(core, bound, "npm") == 0


def _core_parts(version: str) -> tuple[int, int, int]:
    m = _SEMVER_RE.match(normalize(version))
    if not m:
        return (0, 0, 0)
    parts = [int(x) for x in m.group("core").split(".")]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def _major_of(version: str) -> int:
    return _core_parts(version)[0]


def _minor_of(version: str) -> int:
    return _core_parts(version)[1]


def _patch_of(version: str) -> int:
    return _core_parts(version)[2]


def satisfies_npm_range(version: str, range_str: Optional[str]) -> Optional[bool]:
    """判断某个版本是否满足 npm engines 之类的 semver range。

    返回 None 表示无法解析该 range。
    """
    if not range_str or not str(range_str).strip():
        return None
    version = normalize(version)
    normalized_range = re.sub(r"(>=|<=|>|<|=|\^|~)\s+", r"\1", str(range_str))
    for alternative in normalized_range.split("||"):
        alternative = alternative.strip()
        if not alternative:
            continue
        held: Optional[bool] = True
        for clause in alternative.split():
            result = _clause_holds(version, clause)
            if result is None:
                held = None
                break
            if result is False:
                held = False
                break
        if held is True:
            return True
    return False
