"""Command line interface.

    python -m mtw run                      # daily run with all enabled sources
    python -m mtw run --sources openphish  # only some sources
    python -m mtw run --input mylist.txt   # add your own domains or URLs
    python -m mtw check biat-login.xyz     # explain the score of one domain
    python -m mtw demo                     # offline demo on bundled sample data
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .collectors import COLLECTORS
from .config import ROOT, load_allowlist, load_brands, load_settings
from .matcher import Matcher
from .pipeline import run


def _load(args):
    cfg = Path(args.config_dir) if args.config_dir else None
    brands = load_brands(cfg / "brands.yml" if cfg else None)
    settings = load_settings(cfg / "settings.yml" if cfg else None)
    allow = load_allowlist(cfg / "allowlist.txt" if cfg else None)
    return brands, settings, allow


def cmd_run(args) -> int:
    brands, settings, allow = _load(args)
    if args.sources.strip().lower() == "none":
        sources = []
    else:
        sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    unknown = [s for s in sources if s not in COLLECTORS]
    if unknown:
        print(f"unknown source(s): {', '.join(unknown)}. Choose from {', '.join(COLLECTORS)}", file=sys.stderr)
        return 2
    day = date.fromisoformat(args.date) if args.date else date.today()
    summary = run(root=Path(args.root), brands=brands, settings=settings, allowlist=allow,
                  sources=sources, inputs=args.input or [], day=day, use_state=not args.no_state)
    print(json.dumps(summary.__dict__, indent=2))
    return 0


def cmd_check(args) -> int:
    brands, settings, allow = _load(args)
    m = Matcher(brands, settings, allow)
    for value in args.domains:
        if m.is_allowed(value.lower()):
            print(f"{value}: official or allowlisted domain")
            continue
        f = m.evaluate(value, keep_below_threshold=True)
        if f is None:
            print(f"{value}: no brand match")
            continue
        print(f"{value}: score {f.score} ({f.severity}) -> {f.brand_name} [{f.country}]")
        if f.unicode_host != f.host:
            print(f"  displays as: {f.unicode_host}")
        for r in f.reasons:
            print(f"  - {r}")
    return 0


def cmd_demo(args) -> int:
    brands, settings, allow = _load(args)
    out = Path(args.root) if args.root != "." else ROOT / "examples"
    sample = ROOT / "examples" / "sample_feed.txt"
    # Start clean so repeated demos do not pile up history.
    for sub in ("data", "feeds", "hunts", "out", "reports"):
        shutil.rmtree(out / sub, ignore_errors=True)
    summary = run(root=out, brands=brands, settings=settings, allowlist=allow, sources=[],
                  inputs=[str(sample)], day=date.fromisoformat(args.date) if args.date else date.today(),
                  use_state=False)
    print(json.dumps(summary.__dict__, indent=2))
    print(f"\nOpen {out / summary.report_path} to see the report.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mtw", description="Maghreb Threat Watch")
    p.add_argument("--version", action="version", version=f"mtw {__version__}")
    p.add_argument("--config-dir", help="folder with brands.yml, settings.yml, allowlist.txt")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="collect, score and write reports")
    r.add_argument("--sources", default=",".join(COLLECTORS),
                   help=f"comma separated list or 'none' (default: {','.join(COLLECTORS)})")
    r.add_argument("--input", action="append", help="extra local file of domains or URLs (repeatable)")
    r.add_argument("--date", help="run date YYYY-MM-DD (default: today)")
    r.add_argument("--root", default=".", help="output folder (default: current folder)")
    r.add_argument("--no-state", action="store_true", help="do not read or update data/state.json")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="explain how one or more domains score")
    c.add_argument("domains", nargs="+")
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("demo", help="offline demo on examples/sample_feed.txt")
    d.add_argument("--root", default=".", help="output folder (default: examples/)")
    d.add_argument("--date", help="report date YYYY-MM-DD")
    d.set_defaults(func=cmd_demo)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose or args.command == "run" else logging.WARNING,
                        format="%(levelname)s %(message)s")
    return args.func(args)
