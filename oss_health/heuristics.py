"""启发式规则：识别机器人账号、维护者身份、自动化提交。"""

from __future__ import annotations

import re
from typing import Any, Optional

from .config import BOT_LOGIN_EXACT, BOT_LOGIN_SUFFIXES, BOT_NAME_ALLOW, MAINTAINER_ASSOCIATIONS

_BOT_NAME_RE = re.compile(
    r"(?:^|[\s\[\]()\-_./])(?:bot|bots|automation|autobot|dependabot|renovate|github-actions|release-please)(?:$|[\s\[\]()\-_./])",
    re.IGNORECASE,
)


def _get(obj: Any, key: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def is_bot_login(login: Optional[str], user_type: Optional[str] = None) -> bool:
    login = (login or "").strip()
    if user_type and str(user_type).lower() == "bot":
        return True
    if not login:
        return False
    lower = login.lower()
    if lower in {item.lower() for item in BOT_LOGIN_EXACT}:
        return True
    if lower.endswith("[bot]"):
        return True
    for suffix in BOT_LOGIN_SUFFIXES:
        if suffix == "[bot]":
            continue
        if lower.endswith(suffix) and lower not in BOT_NAME_ALLOW:
            return True
    if lower.startswith("bot-") or lower.startswith("auto-"):
        return True
    return False


def is_bot_user(user: Any) -> bool:
    """GitHub user 对象（dict）→ 是否机器人。"""
    if not user:
        return False
    return is_bot_login(_get(user, "login"), _get(user, "type"))


def is_bot_commit_author(commit: dict[str, Any]) -> bool:
    """判断 GitHub commits API 的一条提交是否由机器人完成。

    优先级：GitHub 账号 -> git 作者名/邮箱 -> committer。
    """
    if not commit:
        return False
    author = commit.get("author")
    if author and is_bot_user(author):
        return True
    git_author = (commit.get("commit") or {}).get("author") or {}
    name = git_author.get("name") or ""
    email = git_author.get("email") or ""
    if name and name.lower() not in BOT_NAME_ALLOW and _BOT_NAME_RE.search(name):
        return True
    if email:
        lower = email.lower()
        if "[bot]" in lower or lower.startswith("bot@") or lower.endswith("@bot.github.com"):
            return True
        if "action" in lower and "github" in lower:
            return True
    # 注意：不使用 committer 判断。GitHub 网页端合并的提交 committer 是 web-flow，
    # 但真正的作者可能是真人；committer 信息不可靠。
    return False


def is_maintainer(author_association: Optional[str]) -> bool:
    return bool(author_association) and str(author_association).upper() in MAINTAINER_ASSOCIATIONS


def is_automation_pr(pr: dict[str, Any]) -> bool:
    """机器人开的 PR（dependabot / renovate 等）或其 merge 由机器触发。"""
    if is_bot_user(pr.get("user")):
        return True
    title = (pr.get("title") or "").lower()
    markers = ("bump ", "chore(deps)", "update dependency", "update dependencies", "dependabot")
    return any(m in title for m in markers)


def commit_identity(commit: dict[str, Any]) -> tuple[str, bool]:
    """返回 (展示名, 是否机器人) 。"""
    author = commit.get("author") or {}
    git_author = (commit.get("commit") or {}).get("author") or {}
    login = author.get("login")
    name = git_author.get("name") or login or "unknown"
    is_bot = is_bot_commit_author(commit)
    return (login or name), is_bot
