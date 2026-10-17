"""JSON 报告：完整结构化数据，便于接入 CI / 二次分析。"""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from datetime import datetime
from typing import Any

from ..models import ScanReport

SCHEMA_VERSION = 1


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: to_jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def to_dict(report: ScanReport) -> dict[str, Any]:
    data = to_jsonable(report)
    data["schema_version"] = SCHEMA_VERSION
    return data


def render(report: ScanReport, *, indent: int = 2) -> str:
    return json.dumps(to_dict(report), ensure_ascii=False, indent=indent)
