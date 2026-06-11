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

# Regional EasyList-family lists matching Blindfold's localized markets — an
# English-only blocklist is useless on heise.de or lemonde.fr. Each source is
# optional (a 404 upstream must never break the build) and capped so no single
# list can crowd out the rest. No maintained ABP-format mirror exists for
# Japanese; revisit when one does.
ADBP = "https://easylist-downloads.adblockplus.org"
REGIONAL_LISTS = [
    {"name": "easylistgermany", "urls": ["https://easylist.to/easylistgermany/easylistgermany.txt"]},
    {"name": "liste_fr", "urls": [f"{ADBP}/liste_fr.txt"]},
    {"name": "easylistitaly", "urls": [f"{ADBP}/easylistitaly.txt"]},
    {"name": "easylistspanish", "urls": [f"{ADBP}/easylistspanish.txt"]},
    {"name": "easylistportuguese", "urls": [f"{ADBP}/easylistportuguese.txt"]},
    {"name": "easylistdutch", "urls": [f"{ADBP}/easylistdutch.txt"]},
    {"name": "ruadlist", "urls": [f"{ADBP}/advblock.txt"]},          # RU + UA
    {"name": "easylistchina", "urls": [f"{ADBP}/easylistchina.txt"]},
    {"name": "abpindo", "urls": [f"{ADBP}/abpindo.txt"]},            # Indonesian
    {"name": "indianlist", "urls": [f"{ADBP}/indianlist.txt"]},
    {"name": "koreanlist", "urls": [f"{ADBP}/koreanlist.txt"]},
]
REGIONAL_CAP = 6_000   # network rules per regional list

SOURCES = {
    "ads": {
        "urls": ["https://easylist.to/easylist/easylist.txt"],
        "extras": generate_rules.build_ads,
        "supplements": REGIONAL_LISTS,
        "max_rules": 145_000,
        "output": "ContentBlockers/Ads/blockerList.json",
    },
    "privacy": {
        "urls": ["https://easylist.to/easylist/easyprivacy.txt"],
        "extras": generate_rules.build_privacy,
        # Peter Lowe's ad/tracking server list — a default in uBlock/AdGuard.
        "supplements": [{
            "name": "peterlowe",
            "urls": ["https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext"],
        }],
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


def fetch(urls, cache_dir, name=None, optional=False):
    name = name or os.path.basename(urls[0])
    if cache_dir:
        path = os.path.join(cache_dir, name if name.endswith(".txt") else f"{name}.txt")
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
    if optional:
        print(f"  WARNING: skipping optional source {name}: {last_error}")
        return None
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

    # Supplementary sources (regional lists, Peter Lowe's). Their exceptions
    # ride along too — regional lists whitelist sites their rules would break.
    for supplement in spec.get("supplements", []):
        sup_text = fetch(supplement["urls"], cache_dir, name=supplement["name"], optional=True)
        if sup_text is None:
            continue
        sup_buckets, _ = abp2safari.convert(sup_text.splitlines())
        kept = 0
        for bucket_name, rules in sup_buckets.items():
            if bucket_name == "network":
                rules = rules[:REGIONAL_CAP]
            buckets[bucket_name].extend(rules)
            kept += len(rules)
        print(f"  + {supplement['name']}: {kept:,} rules")

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
