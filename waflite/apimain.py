"""Entry point for `python -m waflite.apimain`."""

from .apicli import run_api

if __name__ == "__main__":
    raise SystemExit(run_api())
