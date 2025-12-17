"""Entry point for `python -m waflite.webmain` (простая штука)."""

from .webcli import run_web

if __name__ == "__main__":
    raise SystemExit(run_web())
