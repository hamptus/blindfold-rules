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

    swift tools/validate_rules.swift --prune ContentBlockers/*/blockerList.json

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
        # AdGuard Annoyances (uBO-format build): cookie notices, popups,
        # widgets — strong procedural/scriptlet coverage Fanboy lacks.
        # assemble() dedupes the overlap with Fanboy.
        "supplements": [{
            "name": "adguard_annoyances",
            "urls": ["https://filters.adtidy.org/extension/ublock/filters/14.txt"],
        }],
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


SCOPING_KEYS = ("if-domain", "unless-domain", "if-top-url", "unless-top-url",
                "resource-type", "load-type", "load-context")
MIN_UNSCOPED_EXCEPTION_FILTER = 8


# Resource types a site-agnostic, match-everything block may cover: beacons
# and pop-ups. Anything else (fetch, script, image...) blocked on every page
# breaks the web.
GLOBAL_BLOCK_OK_TYPES = {"ping", "other", "popup"}
SITE_SCOPING_KEYS = ("if-domain", "unless-domain", "if-top-url", "unless-top-url")


def lint_rules(rules):
    """Rules that would silently disable a whole list, or break every site.
    An `ignore-previous-rules` with no scope and a match-everything url-filter
    cancels every earlier rule on every page, and WebKit compiles it without
    complaint. A match-everything `block` with no site scope and a broad
    resource type (`raw`, `fetch`, `script`...) blocks that kind of load on
    every page: `*$ping,third-party` once compiled to third-party `raw`,
    which is every cross-site fetch and XHR, and broke sign-in pages."""
    problems = []
    for index, rule in enumerate(rules):
        action_type = rule.get("action", {}).get("type")
        if action_type == "block":
            trigger = rule.get("trigger", {})
            if any(key in trigger for key in SITE_SCOPING_KEYS):
                continue
            if trigger.get("url-filter", "") not in (".*", "*", "^", ""):
                continue
            types = set(trigger.get("resource-type") or ["all"])
            if not types <= GLOBAL_BLOCK_OK_TYPES:
                problems.append(f"rule {index}: site-agnostic match-everything block {json.dumps(rule)}")
            continue
        if action_type != "ignore-previous-rules":
            continue
        trigger = rule.get("trigger", {})
        if any(key in trigger for key in SCOPING_KEYS):
            continue
        url_filter = trigger.get("url-filter", "")
        if url_filter in (".*", "*", "^", "") or len(url_filter) < MIN_UNSCOPED_EXCEPTION_FILTER:
            problems.append(f"rule {index}: unscoped ignore-previous-rules {json.dumps(rule)}")
    return problems


MIN_PRIMARY_LINES = 10_000
MIN_KEPT_FRACTION = 0.70


def previous_rule_count(path):
    """Rule count of the list about to be replaced, or None."""
    try:
        with open(path, encoding="utf-8") as f:
            return len(json.load(f))
    except (OSError, ValueError):
        return None


def build(list_id, spec, cache_dir, allow_shrink=False):
    print(f"[{list_id}]")
    text = fetch(spec["urls"], cache_dir)
    # A truncated download or an HTML challenge page served with a 200 would
    # otherwise publish a much smaller list. The app's floor (1,000 rules)
    # does not protect a first download.
    lines = text.splitlines()
    if len(lines) < MIN_PRIMARY_LINES and not allow_shrink:
        raise SystemExit(f"[{list_id}] primary source has only {len(lines):,} lines "
                         f"(floor {MIN_PRIMARY_LINES:,}); refusing to build")
    buckets, stats, runtime = abp2safari.convert(lines)

    # Supplementary sources (regional lists, Peter Lowe's). Their exceptions
    # ride along too — regional lists whitelist sites their rules would break.
    for supplement in spec.get("supplements", []):
        sup_text = fetch(supplement["urls"], cache_dir, name=supplement["name"], optional=True)
        if sup_text is None:
            continue
        sup_buckets, _, sup_runtime = abp2safari.convert(sup_text.splitlines())
        for key in runtime:
            runtime[key].extend(sup_runtime[key])
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
    problems = lint_rules(rules)
    if problems:
        raise SystemExit(f"[{list_id}] refusing to write a list that disables itself:\n  "
                         + "\n  ".join(problems[:20]))

    out = spec.get("dist") or os.path.join(ROOT, spec["output"])
    previous = previous_rule_count(out)
    if previous and len(rules) < previous * MIN_KEPT_FRACTION and not allow_shrink:
        raise SystemExit(f"[{list_id}] {len(rules):,} rules is under "
                         f"{MIN_KEPT_FRACTION:.0%} of the previous {previous:,}; "
                         "refusing to replace it (pass --allow-shrink if intended)")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rules, f, separators=(",", ":"))
    size_mb = os.path.getsize(out) / 1e6
    print(f"  {out if spec.get('dist') else spec['output']}: {len(rules):,} rules ({size_mb:.1f} MB)")
    interesting = {k: v for k, v in stats.report().items() if v >= 50 or k.startswith("skip")}
    print(f"  stats: {interesting}")
    return len(rules), host_only_domains(text), runtime


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", help="directory with pre-downloaded list .txt files")
    parser.add_argument("--dist", help="write <DIR>/<list>.json for the OTA rules repo "
                                       "instead of the app's bundled files")
    parser.add_argument("--allow-shrink", action="store_true",
                        help="accept a list under 70%% of the one it replaces")
    args = parser.parse_args()

    if args.dist:
        os.makedirs(args.dist, exist_ok=True)
        for list_id, spec in SOURCES.items():
            spec["output"] = None
            spec["dist"] = os.path.join(args.dist, f"{list_id}.json")

    total = 0
    estimator_domains = {}
    merged_runtime = {"procedural": [], "scriptlets": []}
    for list_id, spec in SOURCES.items():
        count, domains, runtime = build(list_id, spec, args.cache, args.allow_shrink)
        total += count
        estimator_domains[list_id] = domains
        for key in merged_runtime:
            merged_runtime[key].extend(runtime[key])
    if args.dist:
        # The OTA rules repo publishes the runtime indexes alongside the
        # blocker lists so the helper can eventually fetch them over the air.
        generate_rules.write_cosmetics_js(
            procedural=merged_runtime["procedural"],
            scriptlets=merged_runtime["scriptlets"],
            out_dir=args.dist,
        )
    else:
        generate_rules.write_blocklist_js(
            extra_ads=estimator_domains.get("ads", []),
            extra_trackers=estimator_domains.get("privacy", []),
        )
        generate_rules.write_cosmetics_js(
            procedural=merged_runtime["procedural"],
            scriptlets=merged_runtime["scriptlets"],
        )
    target = f"{args.dist}/*.json" if args.dist else "ContentBlockers/*/blockerList.json"
    print(f"total: {total:,} rules; now run: swift tools/validate_rules.swift --prune {target}")


if __name__ == "__main__":
    main()
