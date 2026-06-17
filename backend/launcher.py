from __future__ import annotations

import argparse
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn

from backend.app.config import HOST, PORT, APP_VERSION
from backend.app.main import app


def open_browser(host: str, port: int) -> None:
    time.sleep(1.2)
    webbrowser.open(f"http://{host}:{port}")


def print_banner() -> None:
    print()
    print("=" * 50)
    print("  🛡️  Windows 应急响应助手")
    print(f"  版本: {APP_VERSION}")
    print(f"  监听: http://{HOST}:{PORT}")
    print("  按 Ctrl+C 退出")
    print("=" * 50)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows 应急响应助手")
    parser.add_argument("--host", default=HOST, help="监听地址")
    parser.add_argument("--port", type=int, default=PORT, help="监听端口")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--verbose", action="store_true", help="显示详细日志")
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")

    args = parser.parse_args()

    log_level = "info" if args.verbose else "warning"

    print_banner()

    if not args.no_browser:
        threading.Thread(target=open_browser, args=(args.host, args.port), daemon=True).start()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=log_level,
        access_log=args.verbose,
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "()": "uvicorn.logging.DefaultFormatter",
                    "fmt": "%(levelprefix)s %(message)s",
                    "use_colors": True,
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "uvicorn": {"handlers": ["default"], "level": "INFO"},
                "uvicorn.error": {"level": "INFO"},
                "uvicorn.access": {"handlers": ["default"], "level": "INFO"},
            },
        },
    )


if __name__ == "__main__":
    main()
