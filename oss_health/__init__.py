"""oss-health: 开源项目健康度扫描器.

不只检查 Last Commit，而是从五个维度判断一个包「还能不能用」:

* 维护活跃度（真人提交、发布节奏、bus factor）
* Issue 响应（近 90 天是否有真人/维护者回复）
* PR 健康（是否只是机器人在合并）
* 运行时 / target framework 是否跟上官方支持周期
* 自身及直接依赖中是否存在未修复的 CVE

用法::

    python -m oss_health pypi:requests
    python -m oss_health npm:express --format md -o report.md
    python -m oss_health github:psf/requests
    python -m oss_health demo
"""

from .config import TOOL_NAME, TOOL_VERSION

__all__ = ["TOOL_NAME", "TOOL_VERSION"]
__version__ = TOOL_VERSION
