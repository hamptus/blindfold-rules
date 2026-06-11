#!/usr/bin/env python3
"""Builds Blindfold's full-power bundled rule lists.

Fetches the industry-standard filter lists (the same families Wipr and
AdGuard build on), converts them with abp2safari, layers Blindfold's curated
rules on top, and writes one blockerList.json per content blocker:

    Ads        ← EasyList                + curated ad rules
    Privacy    ← EasyPrivacy             + curated tracker rules
    Annoyances ← Fanboy's Annoyance      + curated cosmetic/CMP/popup rules
                 (includes EasyList Cookie + Fanboy Social)

Safari allows 150,000 rules per content blocker. Caps below leave headroom
in the Annoyances blocker for the AI / custom / imported lists that merge
into it at compile time (imports are capped at 50,000 in the app).

ALWAYS validate the output before committing:

    swift tools/validate_rules.swift ContentBlockers/*/blockerList.json

Usage:
    python3 tools/build_lists.py [--cache DIR]   # DIR holds pre-downloaded .txt
"""

import argparse
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import abp2safari
import generate_rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SOURCES = {
    "ads": {
        "urls": ["https://easylist.to/easylist/easylist.txt"],
        "extras": generate_rules.build_ads,
        "max_rules": 145_000,
        "output": "ContentBlockers/Ads/blockerList.json",
    },
    "privacy": {
        "urls": ["https://easylist.to/easylist/easyprivacy.txt"],
        "extras": generate_rules.build_privacy,
        "max_rules": 145_000,
        "output": "ContentBlockers/Privacy/blockerList.json",
    },
    "annoyances": {
        "urls": [
            "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
            "https://easylist.to/easylist/fanboy-annoyance.txt",
        ],
        "extras": generate_rules.build_annoyances,
        "max_rules": 95_000,
        "output": "ContentBlockers/Annoyances/blockerList.json",
    },
}


def fetch(urls, cache_dir):
    name = os.path.basename(urls[0])
    if cache_dir:
        path = os.path.join(cache_dir, name)
        if os.path.exists(path):
            print(f"  using cached {path}")
            return open(path, encoding="utf-8", errors="replace").read()
    last_error = None
    for url in urls:
        try:
            print(f"  fetching {url}")
            request = urllib.request.Request(url, headers={"User-Agent": "Blindfold-list-builder/1.0"})
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8", errors="replace")
        except Exception as error:  # try the mirror
            last_error = error
    raise SystemExit(f"failed to fetch {name}: {last_error}")


HOST_ONLY = re.compile(r"^\|\|([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\^$")
MAX_ESTIMATOR_DOMAINS = 6000


def host_only_domains(text):
    """Plain `||domain^` block rules — fed to the helper extension's stats
    estimator so it recognizes what the blockers actually block."""
    domains = []
    for line in text.splitlines():
        m = HOST_ONLY.match(line.strip())
        if m:
            domains.append(m.group(1))
        if len(domains) >= MAX_ESTIMATOR_DOMAINS:
            break
    return domains


def build(list_id, spec, cache_dir):
    print(f"[{list_id}]")
    text = fetch(spec["urls"], cache_dir)
    buckets, stats = abp2safari.convert(text.splitlines())

    # Curated Blindfold rules ride in front of the standard list's network
    # block so list-level exceptions can still cancel them.
    extras = spec["extras"]()
    buckets["network"] = extras + buckets["network"]

    rules = abp2safari.assemble(buckets, max_rules=spec["max_rules"])

    out = spec.get("dist") or os.path.join(ROOT, spec["output"])
    with open(out, "w") as f:
        json.dump(rules, f, separators=(",", ":"))
    size_mb = os.path.getsize(out) / 1e6
    print(f"  {out if spec.get('dist') else spec['output']}: {len(rules):,} rules ({size_mb:.1f} MB)")
    interesting = {k: v for k, v in stats.report().items() if v >= 50 or k.startswith("skip")}
    print(f"  stats: {interesting}")
    return len(rules), host_only_domains(text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", help="directory with pre-downloaded list .txt files")
    parser.add_argument("--dist", help="write <DIR>/<list>.json for the OTA rules repo "
                                       "instead of the app's bundled files")
    args = parser.parse_args()

    if args.dist:
        os.makedirs(args.dist, exist_ok=True)
        for list_id, spec in SOURCES.items():
            spec["output"] = None
            spec["dist"] = os.path.join(args.dist, f"{list_id}.json")

    total = 0
    estimator_domains = {}
    for list_id, spec in SOURCES.items():
        count, domains = build(list_id, spec, args.cache)
        total += count
        estimator_domains[list_id] = domains
    if not args.dist:
        generate_rules.write_blocklist_js(
            extra_ads=estimator_domains.get("ads", []),
            extra_trackers=estimator_domains.get("privacy", []),
        )
    target = f"{args.dist}/*.json" if args.dist else "ContentBlockers/*/blockerList.json"
    print(f"total: {total:,} rules — now run: swift tools/validate_rules.swift {target}")


if __name__ == "__main__":
    main()
