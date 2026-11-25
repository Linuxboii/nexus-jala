"""Command-line interface for nexus-jala."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error

from . import __version__
from .colors import Painter, should_color
from .fetch import fetch_headers, normalise_url
from .grader import GRADE_ORDER, Report, audit, grade_at_least
from .headers import parse_raw

STATUS_STYLE = {
    "pass": ("PASS", "green"),
    "warn": ("WARN", "yellow"),
    "fail": ("FAIL", "red"),
    "info": ("INFO", "cyan"),
}
GRADE_STYLE = {"A+": "green", "A": "green", "B": "green", "C": "yellow", "D": "yellow", "F": "red"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nexus-jala",
        description="Audit and grade HTTP security headers of a URL or a saved raw headers file. "
                    "Only scan systems you own or are authorized to test.",
    )
    p.add_argument("url", nargs="?", default="http://localhost",
                   help="URL to audit (default: http://localhost). A bare host gets https://")
    p.add_argument("-f", "--file", metavar="PATH",
                   help="audit a saved raw headers file (e.g. from 'curl -sI URL > h.txt'); use - for stdin")
    p.add_argument("--assume-http", action="store_true",
                   help="with --file: treat the response as served over plain HTTP (default assumes HTTPS)")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default 10)")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    p.add_argument("--no-follow", action="store_true", help="do not follow redirects; audit the first response")
    p.add_argument("--user-agent", default=None, help="override the User-Agent header")
    p.add_argument("--min-grade", choices=GRADE_ORDER, default=None,
                   help="exit with status 1 if the grade is below this (useful in CI)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def render(report: Report, paint: Painter) -> str:
    lines = []
    target = report.target
    if report.final_url and report.final_url != report.target:
        target += f" -> {report.final_url}"
    status = f"HTTP {report.status}" if report.status else "saved headers"
    lines.append(f"{paint('nexus-jala', 'bold')}  {target}  {paint('(' + status + ')', 'dim')}")
    grade = report.grade
    lines.append(f"Grade: {paint(grade, 'bold', GRADE_STYLE[grade])}  "
                 f"({report.score}/{report.max_score} points)")
    lines.append("")
    width = max(len(f.title) for f in report.findings)
    for f in report.findings:
        label, color = STATUS_STYLE[f.status]
        pts = f"{f.score:>2}/{f.max_score:<2}" if f.max_score else "  -  "
        lines.append(f"  {paint(label, 'bold', color)}  {f.title:<{width}}  {pts}  {f.summary}")
        for tip in f.advice:
            lines.append(f"        {paint('->', 'dim')} {tip}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paint = Painter(should_color(sys.stdout) and not args.no_color)

    try:
        if args.file:
            if args.file == "-":
                text = sys.stdin.read()
            else:
                with open(args.file, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            status, headers = parse_raw(text)
            report = audit(headers, target=args.file, https=not args.assume_http, status=status)
        else:
            kwargs = {}
            if args.user_agent:
                kwargs["user_agent"] = args.user_agent
            result = fetch_headers(args.url, timeout=args.timeout, verify=not args.insecure,
                                   follow=not args.no_follow, **kwargs)
            report = audit(result.headers, target=normalise_url(args.url), https=result.https,
                           status=result.status, final_url=result.final_url)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        reason = getattr(exc, "reason", None) or exc
        print(f"nexus-jala: error: {reason}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render(report, paint))

    if args.min_grade and not grade_at_least(report.grade, args.min_grade):
        if not args.json:
            print(f"\nGrade {report.grade} is below the required minimum {args.min_grade}.", file=sys.stderr)
        return 1
    return 0
