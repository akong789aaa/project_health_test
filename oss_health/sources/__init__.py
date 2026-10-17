"""数据源实现集合。"""

from .eol import EOLSource, Cycle
from .github import GitHubSource
from .npm import NpmSource
from .nuget import NuGetSource
from .osv import OSVSource, VulnQueryResult, dedupe_advisories, parse_vulnerability
from .pypi import PyPISource

__all__ = [
    "Cycle",
    "EOLSource",
    "GitHubSource",
    "NpmSource",
    "NuGetSource",
    "OSVSource",
    "PyPISource",
    "VulnQueryResult",
    "dedupe_advisories",
    "parse_vulnerability",
]
