"""Entry point for `python -m waflite`."""

from .cli import run_cli

if __name__ == "__main__":
    raise SystemExit(run_cli())
