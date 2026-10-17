"""终端文本工具：CJK 宽度感知的排版、颜色、表格、评分条。"""

from __future__ import annotations

import os
import re
import sys
import unicodedata

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class Style:
    """ANSI 样式包装器。"""

    CODES = {
        "reset": "0",
        "bold": "1",
        "dim": "2",
        "italic": "3",
        "underline": "4",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
        "gray": "90",
        "bright_red": "91",
        "bright_green": "92",
        "bright_yellow": "93",
        "bright_blue": "94",
        "bright_magenta": "95",
        "bright_cyan": "96",
    }

    STATUS_ICONS = {"good": "✔", "warn": "▲", "bad": "✖", "unknown": "○"}
    STATUS_COLORS = {"good": "green", "warn": "yellow", "bad": "red", "unknown": "gray"}

    def __init__(self, enabled: bool | None = None):
        self.enabled = supports_color() if enabled is None else bool(enabled)

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\x1b[{self.CODES.get(code, code)}m{text}\x1b[0m"

    # 颜色
    def bold(self, t: str) -> str:
        return self._wrap("bold", t)

    def dim(self, t: str) -> str:
        return self._wrap("dim", t)

    def red(self, t: str) -> str:
        return self._wrap("red", t)

    def green(self, t: str) -> str:
        return self._wrap("green", t)

    def yellow(self, t: str) -> str:
        return self._wrap("yellow", t)

    def blue(self, t: str) -> str:
        return self._wrap("blue", t)

    def magenta(self, t: str) -> str:
        return self._wrap("magenta", t)

    def cyan(self, t: str) -> str:
        return self._wrap("cyan", t)

    def gray(self, t: str) -> str:
        return self._wrap("gray", t)

    def color(self, status: str, text: str) -> str:
        return self._wrap(self.STATUS_COLORS.get(status, "gray"), text)

    def icon(self, status: str) -> str:
        return self.color(status, self.STATUS_ICONS.get(status, "○"))

    def status_text(self, status: str, label: str) -> str:
        return f"{self.icon(status)} {self.color(status, label)}"

    def severity_color(self, severity: str, text: str) -> str:
        mapping = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "UNKNOWN": "gray",
            "NONE": "green",
        }
        return self._wrap(mapping.get(severity, "gray"), text)


# ---------------------------------------------------------------------------
# 宽度计算
# ---------------------------------------------------------------------------

_EAST_ASIAN_WIDE = (
    (0x1100, 0x115F),
    (0x2E80, 0x303E),
    (0x3041, 0x33FF),
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xA000, 0xA4CF),
    (0xA960, 0xA97F),
    (0xAC00, 0xD7A3),
    (0xF900, 0xFAFF),
    (0xFE10, 0xFE19),
    (0xFE30, 0xFE6F),
    (0xFF00, 0xFF60),
    (0xFFE0, 0xFFE6),
    (0x1F300, 0x1F64F),
    (0x1F900, 0x1F9FF),
    (0x1FA70, 0x1FAFF),
    (0x20000, 0x2FFFD),
    (0x30000, 0x3FFFD),
)
_ZERO_WIDTH = (
    (0x0300, 0x036F),
    (0x200B, 0x200F),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
)


def char_width(ch: str) -> int:
    code = ord(ch)
    if code < 32 or code == 0x7F:
        return 0
    for lo, hi in _ZERO_WIDTH:
        if lo <= code <= hi:
            return 0
    east = unicodedata.east_asian_width(ch)
    if east in ("W", "F"):
        return 2
    if east == "A":  # Ambiguous 按东亚语境宽度 2 处理更稳妥，但终端多为 1
        return 1
    for lo, hi in _EAST_ASIAN_WIDE:
        if lo <= code <= hi:
            return 2
    return 1


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def visible_width(text: str) -> int:
    return sum(char_width(ch) for ch in strip_ansi(text))


def pad(text: str, width: int, align: str = "left", fill: str = " ") -> str:
    """按可见宽度补齐/截断到指定宽度。"""
    text = truncate(text, width)
    gap = max(0, width - visible_width(text))
    if align == "right":
        return fill * gap + text
    if align == "center":
        left = gap // 2
        return fill * left + text + fill * (gap - left)
    return text + fill * gap


def truncate(text: str, width: int, ellipsis: str = "…") -> str:
    if width <= 0:
        return ""
    if visible_width(text) <= width:
        return text
    ell_w = char_width(ellipsis)
    budget = width - ell_w
    if budget <= 0:
        return ellipsis[:width]
    out: list[str] = []
    used = 0
    i = 0
    plain = strip_ansi(text)
    # 保留 ANSI 颜色：逐字符重建（颜色码不计宽）
    tokens = re.split(r"(\x1b\[[0-9;]*m)", text)
    for token in tokens:
        if ANSI_RE.fullmatch(token):
            out.append(token)
            continue
        for ch in token:
            w = char_width(ch)
            if used + w > budget:
                out.append(ellipsis)
                return "".join(out)
            out.append(ch)
            used += w
        i += 1
    return "".join(out)


def wrap(text: str, width: int) -> list[str]:
    """按可见宽度折行；对中文逐字折行，对英文尽量按空格断。"""
    if width <= 0:
        return [text]
    lines: list[str] = []
    for raw_line in text.splitlines() or [""]:
        line = ""
        used = 0
        last_space = -1
        for ch in raw_line:
            w = char_width(ch)
            if used + w > width:
                if last_space > 0 and visible_width(line[:last_space]) > width // 2:
                    lines.append(line[:last_space].rstrip())
                    line = line[last_space + 1 :] + ch
                    used = visible_width(line)
                else:
                    lines.append(line)
                    line = ch
                    used = w
                last_space = -1
                continue
            line += ch
            used += w
            if ch == " ":
                last_space = len(line) - 1
        lines.append(line.rstrip())
    return lines or [""]


# ---------------------------------------------------------------------------
# 评分条 / 图标
# ---------------------------------------------------------------------------


def bar(score: float, width: int = 14, full: str = "█", empty: str = "░") -> str:
    score = max(0.0, min(100.0, float(score)))
    filled = int(round(score / 100.0 * width))
    return full * filled + empty * (width - filled)


def score_icon(score: float) -> str:
    if score >= 80:
        return "🟢"
    if score >= 65:
        return "🟡"
    if score >= 50:
        return "🟠"
    return "🔴"


# ---------------------------------------------------------------------------
# 盒子 / 表格 / 键值
# ---------------------------------------------------------------------------

BOX = {
    "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯",
    "h": "─", "v": "│", "lt": "├", "rt": "┤",
}


def hrule(width: int, char: str = "─") -> str:
    return char * width


def box(content: list[str], width: int | None = None, title: str = "", style: Style | None = None) -> list[str]:
    """给内容行加圆角边框，返回带边框的行列表（样式会被保留）。"""
    style = style or Style(enabled=False)
    inner = width or (max((visible_width(line) for line in content), default=0) + 2)
    inner = max(inner, visible_width(title) + 4 if title else 0, 10)
    out: list[str] = []
    if title:
        title_part = f" {title} "
        remaining = inner - 2 - visible_width(title_part)
        out.append(
            f"{style.gray(BOX['tl'])}{style.gray(BOX['h']*2)}"
            f"{style.bold(title_part)}"
            f"{style.gray(BOX['h']*max(0, remaining))}{style.gray(BOX['tr'])}"
        )
    else:
        out.append(style.gray(BOX["tl"] + BOX["h"] * inner + BOX["tr"]))
    for line in content:
        out.append(f"{style.gray(BOX['v'])} {pad(line, inner - 2)} {style.gray(BOX['v'])}")
    out.append(style.gray(BOX["bl"] + BOX["h"] * inner + BOX["br"]))
    return out


class Table:
    """按可见宽度对齐的简易表格。"""

    def __init__(self, headers: list[str], aligns: list[str] | None = None, padding: int = 1):
        self.headers = headers
        self.rows: list[list[str]] = []
        self.aligns = aligns or ["left"] * len(headers)
        self.padding = padding

    def add(self, *cells: str) -> None:
        self.rows.append([str(c) for c in cells])

    def render(self, style: Style | None = None, max_width: int | None = None) -> list[str]:
        style = style or Style(enabled=False)
        ncols = len(self.headers)
        widths = [visible_width(h) for h in self.headers]
        for row in self.rows:
            for i in range(ncols):
                cell = row[i] if i < len(row) else ""
                widths[i] = max(widths[i], visible_width(cell))
        total = lambda: sum(widths) + (len(widths) - 1) * (2 * self.padding)  # noqa: E731
        if max_width and total() > max_width:
            excess = total() - max_width
            # 从最宽的列开始压缩
            while excess > 0:
                idx = max(range(ncols), key=lambda j: widths[j])
                if widths[idx] <= 8:
                    break
                cut = min(excess, widths[idx] - 8)
                widths[idx] -= cut
                excess -= cut
        lines = [" ".join([pad(style.bold(h), widths[i], self.aligns[i]) for i, h in enumerate(self.headers)])]
        sep = " ".join(style.gray("─" * widths[i]) for i in range(ncols))
        lines.append(sep)
        for row in self.rows:
            cells = []
            for i in range(ncols):
                cell = row[i] if i < len(row) else ""
                cells.append(pad(cell, widths[i], self.aligns[i]))
            lines.append(" ".join(cells))
        return lines


def kv_lines(pairs: list[tuple[str, str]], key_width: int = 0, sep: str = "  ") -> list[str]:
    width = key_width or max((visible_width(k) for k, _ in pairs), default=0)
    out = []
    for key, value in pairs:
        out.append(f"{pad(key, width)} {sep}{value}")
    return out
