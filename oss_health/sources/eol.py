"""endoflife.date 数据源：官方运行时支持周期（Python / Node.js / .NET）。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ..config import EOL_PRODUCTS
from ..http_client import HttpClient, HttpError, OfflineMiss
from ..util import parse_iso, utcnow
from ..versions import compare_versions, latest_version


@dataclass
class Cycle:
    product: str
    cycle: str
    release_date: Optional[datetime] = None
    eol: Optional[datetime] = None
    support: Optional[datetime] = None
    latest: str = ""
    lts: bool = False

    def is_eol(self, now: Optional[datetime] = None) -> bool:
        now = now or utcnow()
        return bool(self.eol and self.eol < now)

    @property
    def eol_label(self) -> str:
        return self.eol.strftime("%Y-%m-%d") if self.eol else "未公布"


class EOLSource:
    BASE = "https://endoflife.date/api"

    def __init__(self, client: HttpClient):
        self.client = client
        self._cache: dict[str, list[Cycle]] = {}

    def product(self, product: str) -> list[Cycle]:
        if product in self._cache:
            return self._cache[product]
        url = f"{self.BASE}/{product}.json"
        data = self.client.get_json(url)
        cycles: list[Cycle] = []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                cycles.append(
                    Cycle(
                        product=product,
                        cycle=str(item.get("cycle", "")),
                        release_date=parse_iso(item.get("releaseDate")),
                        eol=parse_iso(item.get("eol")) if item.get("eol") not in (False, None) else None,
                        support=parse_iso(item.get("support")) if item.get("support") not in (False, None) else None,
                        latest=str(item.get("latest") or ""),
                        lts=bool(item.get("lts")),
                    )
                )
        cycles.sort(key=lambda c: c.cycle, reverse=True)
        self._cache[product] = cycles
        return cycles

    # ------------------------------------------------------------------
    # 帮助方法
    # ------------------------------------------------------------------

    def latest_cycle(self, product: str) -> Optional[Cycle]:
        cycles = [c for c in self.product(product) if c.cycle]
        if not cycles:
            return None
        best = cycles[0]
        for c in cycles[1:]:
            if compare_versions(c.cycle, best.cycle, "generic") > 0:
                best = c
        return best

    def current_supported(self, product: str, now: Optional[datetime] = None) -> list[Cycle]:
        return [c for c in self.product(product) if not c.is_eol(now)]

    def supported_labels(self, product: str, now: Optional[datetime] = None) -> list[str]:
        return [c.cycle for c in self.current_supported(product, now)]

    def eol_labels(self, product: str, now: Optional[datetime] = None) -> list[str]:
        return [c.cycle for c in self.product(product) if c.is_eol(now)]

    def cycle(self, product: str, cycle: str) -> Optional[Cycle]:
        for c in self.product(product):
            if c.cycle == cycle:
                return c
        return None

    @staticmethod
    def display_name(product: str) -> str:
        return EOL_PRODUCTS.get(product, product)
