"""CLI runner for WAF API."""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from .api import mk_api


def _ap() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="waflite-api", add_help=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=8010, type=int)
    p.add_argument("--db", default="data/rules_db.json", help="rules db path (json)")
    return p


def run_api(argv: list[str] | None = None) -> int:
    """Run API server.

    Args:
        argv: Arg list.

    Returns:
        Exit code.
    """
    a = _ap().parse_args(argv)
    app = mk_api(Path(a.db))
    uvicorn.run(app, host=a.host, port=a.port, log_level="info")
    return 0
