"""报告渲染器集合。"""

from .console import render as render_console
from .html import render as render_html
from .json_report import render as render_json, to_dict
from .markdown import render as render_markdown

__all__ = ["render_console", "render_html", "render_json", "render_markdown", "to_dict"]
