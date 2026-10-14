"""Command-line interface: ``loghunter analyze <files>``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .detectors import Config, run_all
from .models import SEVERITY_ORDER
from .parsers import parse_files
from .report import render_html, render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="loghunter",
        description="Detect brute force, password spraying and web attacks in "
                    "SSH and Apache/Nginx logs.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyse one or more log files (.log or .gz)")
    a.add_argument("files", nargs="+", type=Path)
    a.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    a.add_argument("-o", "--output", type=Path, help="write the report to this file")
    a.add_argument("--year", type=int,
                   help="year for syslog timestamps that have none (default: current year)")
    a.add_argument("--threshold", type=int, default=5,
                   help="failed SSH logins in the window to raise brute force (default 5)")
    a.add_argument("--window", type=int, default=300,
                   help="sliding window in seconds (default 300)")
    a.add_argument("--spray-users", type=int, default=5,
                   help="distinct usernames to raise password spraying (default 5)")
    a.add_argument("--scan-threshold", type=int, default=20,
                   help="4xx responses in the window to raise scanning (default 20)")
    a.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                   help="hide alerts below this severity")
    a.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                   help="exit with code 2 if an alert of this severity or higher exists "
                        "(useful in CI or cron)")
    a.add_argument("--no-color", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    missing = [f for f in args.files if not f.exists()]
    if missing:
        print(f"error: file not found: {', '.join(map(str, missing))}", file=sys.stderr)
        return 1

    events, stats = parse_files(args.files, year=args.year)
    cfg = Config(bruteforce_threshold=args.threshold, window_seconds=args.window,
                 spray_users=args.spray_users, scan_threshold=args.scan_threshold)
    min_rank = SEVERITY_ORDER[args.min_severity]
    alerts = [a for a in run_all(events, cfg) if a.severity_rank >= min_rank]

    if args.format == "json":
        report = render_json(alerts, stats)
    elif args.format == "html":
        report = render_html(alerts, stats)
    else:
        use_color = not args.no_color and not args.output and sys.stdout.isatty()
        report = render_text(alerts, stats, color=use_color)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Report written to {args.output} ({len(alerts)} alert(s))")
    else:
        print(report)

    if args.fail_on and any(a.severity_rank >= SEVERITY_ORDER[args.fail_on] for a in alerts):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
