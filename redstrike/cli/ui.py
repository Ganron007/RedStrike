"""`redstrike ui` — launch the API (if needed) and open the cockpit browser tab (11.1)."""

from __future__ import annotations

import argparse
import threading
import time
import webbrowser


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redstrike ui",
        description="Open the RedStrike cockpit (serves the API if it is not already running).",
    )
    parser.add_argument("--api", default="http://127.0.0.1:8890", help="API base URL")
    parser.add_argument("--scope", default=None)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--ungated", action="store_true")
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args(argv)

    base = args.api.rstrip("/")
    import urllib.error
    import urllib.request

    def _up() -> bool:
        try:
            urllib.request.urlopen(base + "/health", timeout=2)
            return True
        except (urllib.error.URLError, OSError):
            return False

    if not _up():
        host, port = "127.0.0.1", 8890
        if ":" in base and base.startswith("http://"):
            maybe = base.split("://", 1)[1]
            host_part, _, port_part = maybe.partition(":")
            host, port = host_part or host, int(port_part or 8890)

        def _serve() -> None:
            import uvicorn

            from redstrike.api.server import create_app

            app = create_app(
                scope_path=args.scope,
                api_key=args.api_key,
                profile=args.profile,
                ungated=bool(args.ungated),
            )
            uvicorn.run(app, host=host, port=port, log_level="warning")

        threading.Thread(target=_serve, daemon=True).start()
        for _ in range(50):
            if _up():
                break
            time.sleep(0.2)

    if not args.no_browser:
        webbrowser.open(base + "/ui/")
    print(f"cockpit: {base}/ui/  (Ctrl-C to stop the embedded API)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    main()
