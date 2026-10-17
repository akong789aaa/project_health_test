"""命令行入口。

用法::

    oss-health pypi:requests
    oss-health npm:express --format md -o report.md
    oss-health github:psf/requests --format html -o report.html
    oss-health demo --list
    oss-health demo requests
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .config import DEFAULT_CACHE_TTL_HOURS, DEFAULT_DEP_CHECK, DEFAULT_PR_DETAIL, DEFAULT_WINDOW_DAYS, TOOL_VERSION
from .http_client import HttpClient, HttpError, NotFound, OfflineMiss, RateLimited, default_cache_dir
from .report import render_console, render_html, render_json, render_markdown
from .scanner import ScanOptions, Scanner
from .text import Style, Table
from .util import parse_iso

DEMO_DIR_ENV = "OSS_HEALTH_DEMO_DIR"

EPILOG = """\
示例:
  oss-health pypi:requests                # 普通扫描（自动探测生态）
  oss-health requests                     # 依次在 PyPI / npm / NuGet 查找
  oss-health npm:express                  # 指定生态
  oss-health nuget:Newtonsoft.Json
  oss-health github:psf/requests          # 只扫仓库
  oss-health https://github.com/psf/requests
  oss-health pypi:pycrypto@2.6.1          # 指定历史版本
  oss-health pypi:requests --format md -o report.md
  oss-health --format html -o report.html github:expressjs/express
  oss-health demo --list                  # 查看内置离线示例
  oss-health demo requests                # 离线回放示例（不消耗网络）
"""

DEFAULT_FORMAT = "console"
FORMATS = ("console", "md", "json", "html")


def _add_common_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=FORMATS, default=DEFAULT_FORMAT, help="输出格式（默认 console）")
    parser.add_argument("-o", "--output", help="把报告写入文件")
    parser.add_argument("--no-color", action="store_true", help="禁用 ANSI 颜色")
    parser.add_argument("--width", type=int, default=None, help="终端报告宽度（默认自动）")


def _add_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="包名或仓库，如 pypi:requests / npm:express / github:psf/requests")
    parser.add_argument(
        "--ecosystem",
        choices=("auto", "pypi", "npm", "nuget", "github"),
        default="auto",
        help="强制指定生态（默认 auto 依次探测）",
    )
    parser.add_argument("--version", "-v", dest="package_version", help="指定包版本（默认最新版）")
    parser.add_argument("--repo", help="覆盖 GitHub 仓库，owner/repo")
    parser.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS, help="统计窗口（天，默认 90）")
    parser.add_argument("--pr-detail", type=int, default=DEFAULT_PR_DETAIL, help="抽查 PR 合并者的数量（默认 5）")
    parser.add_argument("--dep-check", type=int, default=DEFAULT_DEP_CHECK, help="检查的直接依赖数量（默认 10）")
    parser.add_argument("--github-token", default=None, help="GitHub Token（默认读 GITHUB_TOKEN / GH_TOKEN）")
    parser.add_argument("--offline", metavar="DIR", help="离线回放模式：只读取录制的快照目录")
    parser.add_argument("--record", metavar="DIR", help="把本次真实请求录制到快照目录")
    parser.add_argument("--cache-dir", default=None, help="缓存目录（默认 ~/.cache/oss-health 或工作区）")
    parser.add_argument("--no-cache", action="store_true", help="禁用响应缓存")
    parser.add_argument("--cache-ttl", type=float, default=DEFAULT_CACHE_TTL_HOURS, help="缓存有效期（小时）")
    parser.add_argument("--timeout", type=float, default=25.0, help="单请求超时（秒）")
    parser.add_argument("--retries", type=int, default=2, help="网络重试次数")
    parser.add_argument("--as-of", dest="as_of", default=None, help="把「当前时间」固定为指定 ISO 时间（复现窗口）")
    parser.add_argument("--verbose", action="store_true", help="输出采集过程日志（stderr）")


def _add_demo_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("name", nargs="?", default=None, help="示例名称（默认列出全部）")
    parser.add_argument("--list", action="store_true", help="列出内置示例")
    parser.add_argument("--demo-dir", default=None, help="自定义快照目录")
    parser.add_argument("--verbose", action="store_true", help="输出回放过程日志（stderr）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oss-health",
        description="开源项目健康度扫描器：综合判断一个包「还能不能用」",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="扫描包 / 仓库（默认命令）", formatter_class=argparse.RawDescriptionHelpFormatter)
    _add_scan_args(scan)
    _add_common_output_args(scan)

    demo = sub.add_parser("demo", help="离线回放内置示例快照")
    _add_demo_args(demo)
    _add_common_output_args(demo)

    list_demos = sub.add_parser("list-demos", help="列出内置离线示例")
    list_demos.add_argument("--demo-dir", default=None)
    return parser


def _normalize_argv(argv: list[str]) -> list[str]:
    """允许省略 scan 子命令：``oss-health pypi:requests``。"""
    known = {"scan", "demo", "list-demos", "-h", "--help", "-V", "--version"}
    if not argv:
        return ["--help"]
    if argv[0] in known:
        return argv
    return ["scan"] + argv


def _demo_snapshots_dir(explicit: Optional[str] = None) -> Path:
    import os

    candidates: list[Path] = []
    env = os.environ.get(DEMO_DIR_ENV)
    if explicit:
        candidates.append(Path(explicit).expanduser())
    elif env:
        candidates.append(Path(env).expanduser())
    candidates.append(Path(__file__).resolve().parent.parent / "demo" / "snapshots")
    candidates.append(Path.cwd() / "demo" / "snapshots")
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[0]


def _available_demos(demo_dir: Path) -> list[dict]:
    demos: list[dict] = []
    if not demo_dir.is_dir():
        return demos
    for manifest_path in sorted(demo_dir.glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        manifest.setdefault("name", manifest_path.parent.name)
        manifest["_dir"] = manifest_path.parent
        demos.append(manifest)
    return demos


def _render(report, fmt: str, *, color_enabled: bool, width: Optional[int]) -> str:
    if fmt == "console":
        return render_console(report, style=Style(enabled=color_enabled), width=width)
    if fmt == "md":
        return render_markdown(report)
    if fmt == "json":
        return render_json(report)
    if fmt == "html":
        return render_html(report)
    raise ValueError(f"未知输出格式：{fmt}")


def _write_output(text: str, output: Optional[str]) -> None:
    if not output:
        print(text)
        return
    path = Path(output).expanduser()
    if path.parent and str(path.parent) != ".":
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    print(f"报告已写入：{path}", file=sys.stderr)


def _build_client(args) -> HttpClient:
    record_dir = getattr(args, "record", None)
    cache_dir = None
    if not args.no_cache and not args.offline:
        cache_dir = args.cache_dir or default_cache_dir()
    return HttpClient(
        cache_dir=cache_dir,
        ttl_hours=args.cache_ttl,
        offline_dir=args.offline,
        record_dir=record_dir,
        timeout=args.timeout,
        retries=args.retries,
        github_token=getattr(args, "github_token", None),
        verbose=getattr(args, "verbose", False),
    )


def _cmd_scan(args) -> int:
    as_of = None
    if args.as_of:
        as_of = parse_iso(args.as_of)
        if as_of is None:
            raise ValueError(f"--as-of 不是合法的 ISO 时间：{args.as_of}")
    if args.offline and not Path(args.offline).is_dir():
        raise ValueError(f"--offline 目录不存在：{args.offline}")
    options = ScanOptions(
        window_days=args.window_days,
        pr_detail=args.pr_detail,
        dep_check=args.dep_check,
        ecosystem=args.ecosystem,
        version=args.package_version,
        repo_override=args.repo,
        now_override=as_of,
        verbose=args.verbose,
        offline=bool(args.offline),
    )
    client = _build_client(args)
    scanner = Scanner(client, options)
    report = scanner.scan(args.target)
    text = _render(report, args.format, color_enabled=not args.no_color, width=args.width)
    _write_output(text, args.output)
    return 0


def _cmd_demo(args) -> int:
    demo_dir = _demo_snapshots_dir(args.demo_dir)
    demos = _available_demos(demo_dir)
    if args.list or not demos:
        if not demos:
            print(f"没有找到内置示例快照（查找目录：{demo_dir}）", file=sys.stderr)
            print("可以运行 scripts/record_demo.py 重新录制。", file=sys.stderr)
            return 1
        style = Style(enabled=not args.no_color)
        print(style.bold(f"内置离线示例（{demo_dir}）："))
        table = Table(["名称", "目标", "说明", "录制时间", "评分"], aligns=["left", "left", "left", "left", "right"])
        for manifest in demos:
            table.add(
                manifest.get("name", ""),
                manifest.get("input", ""),
                manifest.get("description", ""),
                str(manifest.get("recorded_at", ""))[:16].replace("T", " "),
                str(manifest.get("score", "—")),
            )
        for line in table.render(style):
            print("  " + line)
        print()
        print(style.dim("用法：oss-health demo <名称> [--format console|md|json|html] [-o 文件]"))
        return 0

    if args.name:
        selected = [d for d in demos if d.get("name") == args.name]
        if not selected:
            names = "、".join(d.get("name", "") for d in demos)
            raise ValueError(f"没有名为 {args.name} 的示例。可用：{names}")
        demos = selected

    reports = []
    for manifest in demos:
        snap_dir = manifest["_dir"]
        recorded_at = parse_iso(manifest.get("recorded_at"))
        client = HttpClient(offline_dir=snap_dir, verbose=args.verbose)
        options = ScanOptions(
            window_days=int(manifest.get("window_days", DEFAULT_WINDOW_DAYS)),
            pr_detail=int(manifest.get("pr_detail", DEFAULT_PR_DETAIL)),
            dep_check=int(manifest.get("dep_check", DEFAULT_DEP_CHECK)),
            now_override=recorded_at,
            offline=True,
            verbose=args.verbose,
        )
        report = Scanner(client, options).scan(str(manifest.get("input")))
        reports.append(report)

    if args.format == "console" and len(reports) > 1:
        for i, report in enumerate(reports):
            if i:
                print("\n" + "─" * 80 + "\n")
            print(_render(report, "console", color_enabled=not args.no_color, width=args.width))
        return 0
    if args.output and len(reports) > 1:
        raise ValueError("输出到文件时一次只能回放一个示例")
    text = _render(reports[0], args.format, color_enabled=not args.no_color, width=args.width)
    _write_output(text, args.output)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        args = parser.parse_args(_normalize_argv(raw))
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "demo":
            return _cmd_demo(args)
        if args.command == "list-demos":
            demo_dir = _demo_snapshots_dir(args.demo_dir)
            demos = _available_demos(demo_dir)
            if not demos:
                print(f"没有找到内置示例快照（查找目录：{demo_dir}）")
                return 1
            for manifest in demos:
                print(f"{manifest.get('name')}\t{manifest.get('input')}\t{manifest.get('description', '')}")
            return 0
        parser.print_help()
        return 2
    except NotFound as exc:
        _error(str(exc), hint="检查包名拼写；PyPI 包名不区分大小写，npm 包名区分大小写。")
        return 2
    except RateLimited as exc:
        _error(str(exc), hint="等待配额重置，或设置 GITHUB_TOKEN / GH_TOKEN 环境变量后重试。")
        return 3
    except OfflineMiss as exc:
        _error(str(exc), hint="离线快照不完整，请用 --record 重新录制，或显式指定生态。")
        return 4
    except HttpError as exc:
        _error(f"网络请求失败：{exc}", hint="检查网络连接，或稍后重试；也可以使用 --offline 回放已录制数据。")
        return 4
    except ValueError as exc:
        _error(str(exc))
        return 2
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - 防御性兜底
        _error(f"未预期的错误：{type(exc).__name__}: {exc}", hint="加 --verbose 可查看采集过程。")
        return 1


def _error(message: str, hint: Optional[str] = None) -> None:
    style = Style()
    print(style.red(f"错误：{message}"), file=sys.stderr)
    if hint:
        print(style.dim(f"提示：{hint}"), file=sys.stderr)
