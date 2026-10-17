#!/usr/bin/env python3
"""录制离线 demo 快照。

用法::

    python3 scripts/record_demo.py                # 录制全部示例
    python3 scripts/record_demo.py --list         # 查看示例列表
    python3 scripts/record_demo.py --only requests
    python3 scripts/record_demo.py --only express --pr-detail 6

录制结果会写入 ``demo/snapshots/<name>/``（原始 HTTP 响应），同时生成
``demo/snapshots/<name>/manifest.json`` 以及 ``reports/<name>.md/.html/.json``。

注意：GitHub 未配置 Token 时只有 60 次/小时配额，一次录制大约消耗 10~12 次。
脚本会固定一个「当前时间」（--as-of），保证重试时 URL 一致、可复用缓存。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oss_health.config import TOOL_VERSION  # noqa: E402
from oss_health.http_client import HttpClient, default_cache_dir  # noqa: E402
from oss_health.report import render_html, render_json, render_markdown  # noqa: E402
from oss_health.scanner import ScanOptions, Scanner  # noqa: E402
from oss_health.util import isoformat_z, parse_iso, utcnow  # noqa: E402

DEMO_DIR = ROOT / "demo" / "snapshots"
REPORT_DIR = ROOT / "reports"

TARGETS: list[dict] = [
    {
        "name": "requests",
        "input": "pypi:requests",
        "description": "长期维护的 Python HTTP 库（健康样例）",
        "repo": None,
        "window_days": 90,
        "pr_detail": 4,
        "dep_check": 8,
    },
    {
        "name": "pycrypto",
        "input": "pypi:pycrypto",
        "description": "2014 年后停更、存在未修复 CVE 的加密库（高风险样例）",
        "repo": "dlitz/pycrypto",
        "window_days": 90,
        "pr_detail": 4,
        "dep_check": 8,
    },
    {
        "name": "express",
        "input": "npm:express",
        "description": "活跃维护的 Node.js Web 框架（npm 生态样例）",
        "repo": None,
        "window_days": 90,
        "pr_detail": 4,
        "dep_check": 8,
    },
    {
        "name": "newtonsoft-json",
        "input": "nuget:Newtonsoft.Json",
        "description": "高使用量的 .NET JSON 库（TFM 目标框架分析样例）",
        "repo": None,
        "window_days": 90,
        "pr_detail": 4,
        "dep_check": 5,
    },
]


def _select(names: list[str] | None) -> list[dict]:
    if not names:
        return list(TARGETS)
    selected = []
    for name in names:
        match = next((t for t in TARGETS if t["name"] == name), None)
        if match is None:
            raise SystemExit(f"未知示例：{name}，可用：{', '.join(t['name'] for t in TARGETS)}")
        selected.append(match)
    return selected


def record_one(target: dict, now: datetime, *, pr_detail: int | None, dry_run: bool) -> dict | None:
    name = target["name"]
    snap_dir = DEMO_DIR / name
    if dry_run:
        print(f"[dry-run] 将录制 {name}: {target['input']} -> {snap_dir}")
        return None
    snap_dir.mkdir(parents=True, exist_ok=True)
    client = HttpClient(
        cache_dir=default_cache_dir(),
        record_dir=snap_dir,
        timeout=30.0,
        retries=2,
        verbose=False,
    )
    options = ScanOptions(
        window_days=int(target.get("window_days", 90)),
        pr_detail=pr_detail if pr_detail is not None else int(target.get("pr_detail", 4)),
        dep_check=int(target.get("dep_check", 8)),
        repo_override=target.get("repo"),
        now_override=now,
        verbose=True,
    )
    print(f"\n=== 录制 {name}: {target['input']} (仓库={target.get('repo') or '自动'}) ===")
    report = Scanner(client, options).scan(target["input"])

    # 录制结束后做一次离线回放校验：确保 demo 在任何时候都能复现
    verify_client = HttpClient(offline_dir=snap_dir)
    verify_options = ScanOptions(
        window_days=options.window_days,
        pr_detail=options.pr_detail,
        dep_check=options.dep_check,
        now_override=now,
        offline=True,
    )
    replay = Scanner(verify_client, verify_options).scan(target["input"])
    if replay.score_int != report.score_int:
        print(
            f"    ! 离线回放分数不一致：实时 {report.score_int} vs 回放 {replay.score_int}",
            file=sys.stderr,
        )

    manifest = {
        "name": name,
        "input": target["input"],
        "description": target.get("description", ""),
        "repo_override": target.get("repo"),
        "recorded_at": isoformat_z(now),
        "recorded_by": f"oss-health/{TOOL_VERSION}",
        "window_days": options.window_days,
        "pr_detail": options.pr_detail,
        "dep_check": options.dep_check,
        "tool_version": TOOL_VERSION,
        "score": report.score_int,
        "grade": report.grade,
        "verdict": report.verdict,
        "confidence": report.confidence,
        "offline": False,
    }
    (snap_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / f"{name}.md").write_text(render_markdown(report), encoding="utf-8")
    (REPORT_DIR / f"{name}.html").write_text(render_html(report), encoding="utf-8")
    (REPORT_DIR / f"{name}.json").write_text(render_json(report), encoding="utf-8")

    print(
        f"--- {name}: {report.score_int}/100 {report.grade} 级 · {report.verdict}"
        f"（置信度 {report.confidence}）"
    )
    print(f"    GitHub 请求 {client.request_count} 次 / 缓存命中 {client.cache_hits} 次")
    for warning in report.warnings[:5]:
        print(f"    ! {warning}")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="录制 oss-health 离线 demo 快照")
    parser.add_argument("--only", action="append", help="只录制指定示例（可多次指定）")
    parser.add_argument("--list", action="store_true", help="列出示例")
    parser.add_argument("--as-of", default=None, help="固定「当前时间」（ISO），默认现在")
    parser.add_argument("--pr-detail", type=int, default=None, help="覆盖 PR 抽查数量")
    parser.add_argument("--force", action="store_true", help="即使快照已存在也重新录制")
    parser.add_argument("--dry-run", action="store_true", help="只打印计划")
    args = parser.parse_args(argv)

    if args.list:
        for target in TARGETS:
            exists = "已录制" if (DEMO_DIR / target["name"] / "manifest.json").exists() else "未录制"
            print(f"{target['name']:<18} {target['input']:<28} {exists}  {target['description']}")
        return 0

    now = parse_iso(args.as_of) if args.as_of else utcnow()
    if now is None:
        raise SystemExit(f"非法 --as-of：{args.as_of}")

    selected = _select(args.only)
    recorded = []
    for target in selected:
        manifest_path = DEMO_DIR / target["name"] / "manifest.json"
        if manifest_path.exists() and not args.force:
            print(f"跳过 {target['name']}（已存在快照，--force 可重新录制）")
            continue
        try:
            manifest = record_one(target, now, pr_detail=args.pr_detail, dry_run=args.dry_run)
        except Exception as exc:
            print(f"录制 {target['name']} 失败：{exc}", file=sys.stderr)
            print("提示：GitHub 配额 60 次/小时（无 Token），稍后重试会复用缓存。", file=sys.stderr)
            return 1
        if manifest:
            recorded.append(manifest)

    if recorded:
        print("\n录制完成：")
        for manifest in recorded:
            print(f"  {manifest['name']:<18} {manifest['score']:>3}/100 {manifest['grade']} 级  {manifest['input']}")
        print(f"\n快照目录：{DEMO_DIR}")
        print(f"报告目录：{REPORT_DIR}")
        print("回放验证：python3 -m oss_health demo <name>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
