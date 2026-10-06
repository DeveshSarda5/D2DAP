"""Start the dashboard (FastAPI backend + static frontend).

python scripts/run_dashboard.py            # http://127.0.0.1:8000
python scripts/run_dashboard.py --port 8080
"""

from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    print(f"Dashboard: http://{args.host}:{args.port}")
    uvicorn.run("app.api.main:app", host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
