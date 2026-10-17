"""CVSS v3.0 / v3.1 基础评分计算器（OSV 只给向量，不给分数）。

同时提供严重度标签归一化：OSV/GitHub 的 ``database_specific.severity``
与 CVSS 分数之间互相映射。
"""

from __future__ import annotations

import math
from typing import Optional

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_LABEL_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NONE": "NONE",
    "UNKNOWN": "UNKNOWN",
    "IMPORTANT": "HIGH",  # 某些发行版使用
    "MODERATE ": "MEDIUM",
}


def severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def normalize_severity(label: str) -> str:
    return _LABEL_ALIASES.get((label or "").strip().upper(), "UNKNOWN")


def severity_rank(severity: str) -> int:
    return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1, "NONE": 0}.get(
        (severity or "").upper(), 1
    )


def _roundup(value: float) -> float:
    """CVSS v3.1 规范里的 Roundup：向上取到 1 位小数。"""
    int_input = int(round(value * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _round_v30(value: float) -> float:
    """CVSS v3.0 用的是四舍五入到 1 位小数（half-up）。"""
    return math.floor(value * 10 + 0.5) / 10.0


def parse_cvss_v3(vector: str) -> Optional[tuple[float, str]]:
    """解析 CVSS v3.x 向量，返回 (基础分, 版本)。解析失败返回 None。"""
    if not vector:
        return None
    parts = vector.strip().split("/")
    version = "3.1"
    metrics: dict[str, str] = {}
    for token in parts:
        if token.startswith("CVSS:"):
            version = token.split(":", 1)[1]
            continue
        if ":" not in token:
            continue
        key, val = token.split(":", 1)
        metrics[key.strip().upper()] = val.strip().upper()
    if version not in ("3.0", "3.1"):
        return None
    try:
        scope_changed = metrics["S"] == "C"
        av = AV[metrics["AV"]]
        ac = AC[metrics["AC"]]
        pr = (PR_CHANGED if scope_changed else PR_UNCHANGED)[metrics["PR"]]
        ui = UI[metrics["UI"]]
        c = CIA[metrics["C"]]
        i = CIA[metrics["I"]]
        a = CIA[metrics["A"]]
    except KeyError:
        return None
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)
    score = _roundup(score) if version == "3.1" else _round_v30(score)
    return round(score, 1), version


def parse_cvss(vector: str) -> Optional[tuple[float, str]]:
    """通用入口：目前支持 CVSS v3.0/v3.1，v4.0 暂不计算分数（返回 None）。"""
    if not vector:
        return None
    head = vector.strip()[:9]
    if head.startswith("CVSS:4"):
        return None
    return parse_cvss_v3(vector)


def score_to_grade_zh(severity: str) -> str:
    return {
        "CRITICAL": "严重",
        "HIGH": "高危",
        "MEDIUM": "中危",
        "LOW": "低危",
        "UNKNOWN": "未知",
        "NONE": "无",
    }.get((severity or "").upper(), "未知")
