#!/usr/bin/env python3
"""Start the Bootleg server.

    python3 run.py                     # http://127.0.0.1:8000
    python3 run.py --host 0.0.0.0      # reachable from your targets

For anything internet-facing, put it behind nginx/caddy with TLS and run it
under gunicorn instead:

    gunicorn -w 4 -b 127.0.0.1:8000 --timeout 600 'bootleg.app:create_app()'
"""

import argparse

from bootleg.app import create_app
from bootleg.config import Config


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Bootleg server.")
    parser.add_argument("--host", default=Config.HOST, help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=Config.PORT, help="port (default: 8000)")
    parser.add_argument("--debug", action="store_true", help="auto-reload and verbose errors")
    args = parser.parse_args()

    app = create_app()
    print("  Bootleg  ->  http://{0}:{1}".format(args.host, args.port))
    print("  data     ->  {0}".format(app.config["DATA_DIR"]))
    app.run(host=args.host, port=args.port, debug=args.debug,
            threaded=True, use_reloader=args.debug)


if __name__ == "__main__":
    main()
