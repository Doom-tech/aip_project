"""CLI for waflite."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .core import nrq, scr, dec
from .io import rdln, prs
from .rep import wr_jsonl, wr_csv
from .rules import ld_cfg, ld_rls


def _ap() -> argparse.ArgumentParser:
    """Build argparse parser."""
    p = argparse.ArgumentParser(prog="waflite", add_help=True)
    p.add_argument("--in", dest="inp", required=True, help="input file path")
    p.add_argument("--fmt", dest="fmt", default="nginx", choices=["nginx", "raw"])
    p.add_argument("--out", dest="outp", required=True, help="output file path")
    p.add_argument("--ofmt", dest="ofmt", default="jsonl", choices=["jsonl", "csv"])
    p.add_argument("--cfg", dest="cfg", default="", help="config JSON path (optional)")
    return p


def run_cli(argv: list[str] | None = None) -> int:
    """Run CLI.

    Args:
        argv: Arguments list without program name.

    Returns:
        Exit code (0 ok, 2 on handled error).
    """
    a = _ap().parse_args(argv)
    ip = Path(a.inp)
    op = Path(a.outp)
    cp = Path(a.cfg) if str(a.cfg).strip() else None

    cfg = ld_cfg(cp)
    thr, rls, ign_ua = ld_rls(cfg)

    rows: list[dict[str, Any]] = []
    try:
        for ln in rdln(ip):
            pr = prs(a.fmt, ln).asd()
            rq = nrq(pr)

            s, ms = scr(rls, rq)
            ua = rq.get("ua", "")
            if any(x.lower() in ua.lower() for x in ign_ua):
                s = max(0, s - 3)

            rows.append(
                {
                    "ip": rq.get("ip", ""),
                    "req": rq.get("req", ""),
                    "ua": rq.get("ua", ""),
                    "st": rq.get("st", 0),
                    "scr": s,
                    "dec": dec(s, thr),
                    "m": ",".join(ms),
                }
            )
    except Exception as e:
        raise SystemExit(f"err: {e}") from e

    if a.ofmt == "jsonl":
        wr_jsonl(op, rows)
    else:
        wr_csv(op, rows)
    return 0
