"""HTTP API для WAF.

Этот модуль дает отдельный API (без UI), чтобы:
- проверять одиночный запрос (scan)
- проверять пачку запросов (batch)
- управлять базой правил (get/put)
- получать статистику (stats)

API сделан на FastAPI, чтобы:
- была живая документация Swagger/OpenAPI на `/docs` и `/openapi.json`
- удобно тестировать через TestClient

Формат базы правил (db json):
- thr: int
- ign_ua: list[str]
- rls: list[dict] (поля: rid, rtp, w, ps, fld)
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .core import nrq, scr, dec, Rl, CfgErr
from .webapp import _ld_db, _sv_db, _mk_rl, _waf_do


class ScanIn(BaseModel):
    """Input schema for scan endpoints.

    Attributes:
        ip: Client IP.
        req: Request line, e.g. "GET /?q=x HTTP/1.1".
        ua: User-Agent.
        st: HTTP status if known (0 otherwise).
    """

    ip: str = ""
    req: str = Field(..., min_length=1)
    ua: str = ""
    st: int = 0


class ScanOut(BaseModel):
    """Output schema for scan endpoints.

    Attributes:
        scr: Score.
        dec: Decision: "allow" or "block".
        thr: Threshold used.
        m: Matched rule ids.
    """

    scr: int
    dec: str
    thr: int
    m: list[str]


class BatchIn(BaseModel):
    """Input schema for batch scan.

    Attributes:
        items: List of ScanIn objects.
    """

    items: list[ScanIn]


class BatchOut(BaseModel):
    """Output schema for batch scan.

    Attributes:
        items: List of ScanOut results.
        n: Total items.
    """

    items: list[ScanOut]
    n: int


class StatsOut(BaseModel):
    """Simple runtime stats.

    Attributes:
        up_s: Uptime seconds.
        scans: Total scans handled.
        blocks: Total blocks decided.
    """

    up_s: float
    scans: int
    blocks: int


def mk_api(dbp: Path) -> FastAPI:
    """Create FastAPI WAF API application.

    Args:
        dbp: Path to rules database json.

    Returns:
        FastAPI app.
    """
    app = FastAPI(title="waflite-api", version="0.1.0")
    t0 = time.time()
    st = {"scans": 0, "blocks": 0}

    def gdb() -> dict[str, Any]:
        return _ld_db(dbp)

    def sdb(d: dict[str, Any]) -> None:
        _sv_db(dbp, d)

    @app.get("/api/v1/health")
    def health() -> dict[str, Any]:
        """Healthcheck.

        Returns:
            Dict with ok flag.
        """
        return {"ok": True}

    @app.get("/api/v1/rules")
    def rules_get() -> dict[str, Any]:
        """Get rules db.

        Returns:
            Rules database as dict.
        """
        return gdb()

    @app.put("/api/v1/rules")
    def rules_put(d: dict[str, Any]) -> dict[str, Any]:
        """Replace rules db.

        Args:
            d: New db dict.

        Returns:
            {"ok": True}

        Raises:
            HTTPException: If payload is invalid.
        """
        if not isinstance(d, dict):
            raise HTTPException(400, "bad json")
        if "rls" in d and not isinstance(d["rls"], list):
            raise HTTPException(400, "bad rls")
        sdb(d)
        return {"ok": True}

    @app.post("/api/v1/scan", response_model=ScanOut)
    def scan(x: ScanIn) -> ScanOut:
        """Scan single request and return decision.

        Args:
            x: Scan input.

        Returns:
            ScanOut decision.

        Raises:
            HTTPException: If config invalid.
        """
        db = gdb()
        try:
            r = _waf_do(db, x.model_dump())
        except CfgErr as e:
            raise HTTPException(400, str(e)) from e

        st["scans"] += 1
        if r["dec"] == "block":
            st["blocks"] += 1
        return ScanOut(scr=int(r["scr"]), dec=str(r["dec"]), thr=int(r["thr"]), m=list(r["m"]))

    @app.post("/api/v1/batch", response_model=BatchOut)
    def batch(x: BatchIn) -> BatchOut:
        """Scan batch of requests.

        Args:
            x: Batch input.

        Returns:
            BatchOut with per-item decisions.
        """
        out: list[ScanOut] = []
        for it in x.items:
            out.append(scan(it))
        return BatchOut(items=out, n=len(out))

    @app.get("/api/v1/stats", response_model=StatsOut)
    def stats() -> StatsOut:
        """Get runtime stats.

        Returns:
            StatsOut.
        """
        return StatsOut(up_s=time.time() - t0, scans=int(st["scans"]), blocks=int(st["blocks"]))

    return app
