"""CLI runner for web app."""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from .webapp import mk_app


def _ap() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="waflite-web", add_help=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=8000, type=int)
    p.add_argument("--db", default="data/rules_db.json", help="rules db path (json)")
    return p


def run_web(argv: list[str] | None = None) -> int:
    a = _ap().parse_args(argv)
    app = mk_app(Path(a.db))
    uvicorn.run(app, host=a.host, port=a.port, log_level="info")
    return 0
