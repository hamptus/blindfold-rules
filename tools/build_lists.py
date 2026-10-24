#!/usr/bin/env python3
"""Builds Blindfold's full-power bundled rule lists.

Fetches the industry-standard filter lists (the same families Wipr and
AdGuard build on), converts them with abp2safari, layers Blindfold's curated
rules on top, and writes one blockerList.json per content blocker:

    Ads        ← EasyList                + curated ad rules
    Privacy    ← EasyPrivacy             + curated tracker rules
    Annoyances ← Fanboy's Annoyance      + curated cosmetic/CMP/popup rules
                 (includes EasyList Cookie + Fanboy Social)

Each blocker's URL exceptions that pass the checks in "Cross-blocker network
exceptions" below are also copied into the other two blockers, because Safari
never lets one content blocker's exception cancel another's block.

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
        # Blindfold's own rules (tools/lists), never capped or fetched.
        "local": ["blindfold-ads.txt"],
        # Fast fixes owned by the blindfold-rules repo (reviewed PRs there),
        # merged when present and back-ported into blindfold-ads.txt later.
        # Not covered by that repo's tools/SOURCE.sha256 check.
        "local_optional": ["hotfix-ads.txt"],
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
        # Blindfold's own fixes for this blocker. An exception only cancels
        # blocks in its own content blocker, so Privacy fixes live here
        # (propagate_exceptions() copies the qualifying ones to the others).
        "local": ["blindfold-privacy.txt"],
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
        "local": ["blindfold-annoyances.txt"],
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


LISTS_DIR = os.path.join(ROOT, "tools", "lists")


def read_local_list(name):
    """Lines of one of Blindfold's own filter lists in tools/lists."""
    with open(os.path.join(LISTS_DIR, name), encoding="utf-8") as f:
        return f.read().splitlines()


def local_list_names(spec):
    """The spec's required local lists, plus its optional ones that exist."""
    names = list(spec.get("local", []))
    names += [name for name in spec.get("local_optional", [])
              if os.path.exists(os.path.join(LISTS_DIR, name))]
    return names


def merge_local_lists(list_id, spec, buckets, runtime):
    """Converts and appends the spec's local lists. Any rule the converter
    skips fails the build: a hand-written rule that silently vanished would
    look shipped and not be."""
    for name in local_list_names(spec):
        local_buckets, local_stats, local_runtime = abp2safari.convert(read_local_list(name))
        skipped = {k: v for k, v in local_stats.report().items() if k.startswith("skip")}
        if skipped:
            raise SystemExit(f"[{list_id}] {name} has rules the converter skipped: {skipped}")
        for key in runtime:
            runtime[key].extend(local_runtime[key])
        for bucket_name, rules in local_buckets.items():
            buckets[bucket_name].extend(rules)
        print(f"  + {name}: {sum(len(r) for r in local_buckets.values()):,} rules, "
              f"{len(local_runtime['scriptlets'])} scriptlets")


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
MATCH_EVERYTHING_FILTERS = (".*", "*", "^", "", abp2safari.NETWORK_URL_FILTER)
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
            url_filter = trigger.get("url-filter", "")
            if url_filter not in MATCH_EVERYTHING_FILTERS:
                continue
            types = set(trigger.get("resource-type") or ["all"])
            if not types <= GLOBAL_BLOCK_OK_TYPES:
                problems.append(f"rule {index}: site-agnostic match-everything block {json.dumps(rule)}")
            elif url_filter != abp2safari.NETWORK_URL_FILTER:
                # `.*` also matches blob: URLs, which WebKit treats as
                # third-party `other`: it blocked Cloudflare's challenge workers.
                problems.append(f"rule {index}: match-everything block also matches blob: URLs {json.dumps(rule)}")
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


# --- Cross-blocker network exceptions ----------------------------------------
# Safari runs every content blocker on its own: an `ignore-previous-rules` in
# one list never cancels a block in another. EasyList (Ads) carries
# @@||pubads.g.doubleclick.net/ssai/ so Google DAI video streams can be
# created, but Peter Lowe's list in Privacy blocks all of doubleclick.net, so
# the CBS Sports live player failed until blindfold-privacy.txt copied the
# exception by hand. This step copies a source blocker's URL exceptions into
# the other blockers, after their block rules, so one list's breakage fix
# reaches the others.
#
# Only exceptions that pass every check below are copied. The checks keep a
# fix written for ads from opening a hole in the tracker blocker:
#
#   1. URL exceptions only: `ignore-previous-rules` rules from the converter's
#      network_exceptions bucket. $document, $elemhide and $generichide
#      exceptions live in other buckets and are never copied; cosmetic
#      exceptions (#@#) never become network rules; $genericblock is not
#      converted at all.
#   2. Anchored to a concrete host (`||host...`). An unanchored pattern such
#      as `@@/gtm.js$domain=amd.com` cancels that path on every host,
#      trackers included. Match-everything filters fail this check too, so a
#      page-wide `@@*$domain=...` is never copied.
#   3. Narrow: it must name a path beyond the host. A bare `@@||host^` with
#      no $domain= would unblock that whole host on every site; with a
#      $domain= scope (`@@||moatads.com^$script,domain=nascar.com`) it would
#      still re-enable a host the target blocks as a tracker, on every page
#      of that site, so it is not copied either (3b). A path exception may
#      be site-scoped or unscoped. An unscoped path
#      exception is copied only from a blocker's primary list (EasyList,
#      EasyPrivacy, Fanboy) or Blindfold's own lists: supplements such as
#      EasyList China carry unscoped carve-outs for trackers their own rules
#      over-block (`@@||wl.jd.com/wl.js`), so only their site-scoped
#      exceptions travel.
#   4. The target only blocks that URL with a whole-host rule (`||host^` on
#      the host, a parent or a subdomain). The exception then carves a hole in a broad
#      host block, which is the CBS case. When the target blocks the path
#      itself (`||host/path`, a generic `/path` pattern), its maintainers
#      judged that exact resource, and their block stands. When nothing in
#      the target matches, the copy would be dead weight and is skipped.
#
#   5. Not ad-serving infrastructure (AD_INFRA_* below): GPT/securepubads,
#      googletagservices, pagead2/adservice, Amazon (apstag), header bidding
#      (prebid, bid adapters), ad verification, native/video ad networks.
#      Ad lists except these per site so a page's ad stack loads where the
#      list authors chose to show ads; copied into Privacy they re-enabled
#      gpt.js and ppub_config on weather.com, which works without them.
#      Only the allow-set (AD_INFRA_ALLOW) passes: proven content fixes such
#      as Google DAI stream creation (pubads.g.doubleclick.net/ssai/), which
#      CBS Sports live video needs.
#
# The copied rule keeps the converter's if-domain, load-type and resource-type
# exactly, with one narrowing: a copy that would also match top-frame page
# loads (no resource-type, or `document` without the child-frame pin) is
# split so it never matches the page itself. An ignore-previous-rules that
# matches the page URL also cancels the target's element hiding for that
# page, which the source list never asked for.

HOST_END = r"([^a-zA-Z0-9_.%-].*)?$"
ANCHORED_HOST = re.compile(r"((?:[a-z0-9-]+\\\.)+[a-z0-9-]+)", re.I)
HOST_TERMINATORS = ("\\/", abp2safari.SEPARATOR, ":", "$", "\\?")
# Every Safari type except `document`, for the non-page half of a split copy.
NON_PAGE_TYPES = sorted(set(abp2safari.ALL_TYPES) | {"popup"})
SITE_SCOPE_KEYS = ("if-domain", "if-top-url")
CROSS_EXAMPLES = 3

# Rule 5. Registrable domains whose URLs are ad serving, bidding or ad
# verification: an exception on any of their hosts is never copied. Taken
# from what the cross-blocker step actually kept from today's lists.
AD_INFRA_DOMAINS = frozenset({
    # Google ad serving
    "doubleclick.net", "googlesyndication.com", "googletagservices.com",
    "googleadservices.com", "2mdn.net", "imasdk.googleapis.com",
    # Amazon, header bidding, SSPs, exchanges
    "amazon-adsystem.com", "assoc-amazon.com", "adnxs.com", "adnxs-simple.com",
    "rubiconproject.com", "pubmatic.com", "improvedigital.com", "criteo.com",
    "criteo.net", "openx.net", "casalemedia.com", "indexww.com", "smartadserver.com",
    "adform.net", "htlbid.com", "yieldlove.com", "optad360.net", "proper.io",
    "triplelift.com", "sharethrough.com", "sovrn.com", "lijit.com", "33across.com",
    "gumgum.com", "kargo.com", "sonobi.com", "yieldmo.com", "media.net",
    "advertising.com", "adtech.de", "weborama.fr", "grapeshot.co.uk",
    # Publisher ad managers and ad-supported networks
    "adthrive.com", "mediavine.com", "ezodn.com", "vntsm.com", "adinplay.com",
    "playwire.com", "orangeclickmedia.com", "bf-ad.net", "uimserv.net",
    "pagefair.com", "infolinks.com", "advertserve.com", "ladsp.com",
    # Native, recommendation and video ad networks
    "taboola.com", "outbrain.com", "popin.cc", "ntv.io", "connatix.com",
    "aniview.com", "caroda.io", "vdo.ai", "ex.co", "primis.tech", "teads.tv",
    "spotxchange.com", "spotx.tv", "smartclip.net", "fwmrm.net", "liverail.com",
    "adap.tv", "springserve.com", "getpublica.com", "lfstmedia.com",
    "adswizz.com",
    # Ad verification and ad pixels
    "adsafeprotected.com", "doubleverify.com", "moatads.com",
    "confiant-integrations.net", "ads-twitter.com",
    # Affiliate and adult/pop ad networks
    "linksynergy.com", "pepperjamnetwork.com", "pjtra.com", "pntrac.com",
    "pntrs.com", "zenaps.com", "admitad.com", "alipromo.com", "trafficjunky.net",
    "exoclick.com", "exosrv.com", "magsrv.com", "realsrv.com", "tsyndicate.com",
    "juicyads.com", "adtng.com",
    # Regional ad networks
    "adriver.ru", "adfox.ru", "begun.ru", "adspirit.de", "mediav.com",
})
# Ad serving on hosts that also serve content: (host suffix, path prefix).
AD_INFRA_PATHS = (
    ("google.com", "/adsense/"),
    ("yandex.ru", "/ads/"),
)
AD_INFRA_HOST_PREFIXES = ("adservice.google.", "an.yandex.")
# First-party copies of an ad stack (`abcnews.com/.../prebid.min.js`).
AD_INFRA_PATH_TOKENS = re.compile(
    r"prebid|apstag|pubads_impl|/gpt\.js|adsbygoogle|show_ads|/gampad/|admanager|vpaid")
# Proven content fixes that stay copyable: Google Dynamic Ad Insertion
# creates the video stream itself here (CBS Sports live, history.com VOD),
# and the HLS playlists it returns are the player's only source.
AD_INFRA_ALLOW = (
    ("pubads.g.doubleclick.net", "/ssai/"),
    ("pubads.g.doubleclick.net", "/ondemand/"),
)
CANARY_URL = "https://canary.invalid/x"


def parse_anchored(url_filter):
    """`||host...` url-filter -> (host, path, path_prefix), or None when the
    filter is not anchored to one concrete host. `path` is the literal text
    after the host with wildcards removed; `path_prefix` stops at the first
    wildcard."""
    prefix = abp2safari.DOMAIN_PREFIX
    if not url_filter.startswith(prefix):
        return None
    rest = url_filter[len(prefix):]
    m = ANCHORED_HOST.match(rest)
    if not m:
        return None
    after = rest[m.end():]
    if after and not after.startswith(HOST_TERMINATORS) and after != HOST_END:
        return None   # the host continues with a wildcard: `cdn.*.example`
    host = m.group(1).replace("\\.", ".").lower()
    if after.endswith(HOST_END):
        after = after[: -len(HOST_END)]
    after = after.replace(abp2safari.SEPARATOR, "/")

    def unescape(text):
        return re.sub(r"\\(.)", r"\1", text).rstrip("$")
    path_prefix = unescape(after.split(".*")[0]).lower()
    path = unescape(after.replace(".*", "")).lower()
    return host, path, path_prefix


def _hosts_related(a, b):
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _base(host):
    return ".".join(host.split(".")[-2:])


def required_literal(url_filter):
    """The longest literal run every URL the regex matches must contain
    (lowercased), or "" when it cannot be read safely. Used only to skip
    regex searches that cannot match."""
    if ")?" in url_filter:
        return ""   # an optional group: its literals are not required
    text = re.sub(r"\[[^\]]*\]", "\0", url_filter)
    runs = re.findall(r"(?:\\.|[A-Za-z0-9_=&%,;:'~!@#-])+", text)
    best = max((re.sub(r"\\(.)", r"\1", run) for run in runs), key=len, default="")
    return best.lower()


class BlockIndex:
    """A target blocker's block rules, indexed to answer: how does this
    blocker block a given exception's URL? Match-everything blocks (typed
    globals such as `*$ping,third-party`, or `|https:$domain=...`) are left
    out: an exception that only cancels those is not worth copying."""

    def __init__(self, rules):
        self.by_base = {}
        self.generic = []
        for rule in rules:
            if rule.get("action", {}).get("type") != "block":
                continue
            url_filter = rule["trigger"].get("url-filter", "")
            if url_filter in MATCH_EVERYTHING_FILTERS:
                continue
            parsed = parse_anchored(url_filter)
            if parsed:
                host, path, path_prefix = parsed
                host_level = not re.search(r"[a-z0-9]", path)
                self.by_base.setdefault(_base(host), []).append(
                    (host, path_prefix, host_level, url_filter))
            else:
                self.generic.append((required_literal(url_filter), url_filter))
        self._compiled = {}
        # Patterns that match any URL at all (`|https:$domain=...`) block
        # whole pages' worth of requests, not this host: same as above.
        self.generic = [(literal, url_filter) for literal, url_filter in self.generic
                        if not self._search(url_filter, CANARY_URL)]

    def _search(self, url_filter, url):
        pattern = self._compiled.get(url_filter)
        if pattern is None:
            try:
                pattern = re.compile(url_filter, re.I)
            except re.error:
                pattern = re.compile(r"(?!)")
            self._compiled[url_filter] = pattern
        return pattern.search(url) is not None

    def classify(self, host, path, path_prefix):
        """'path' when a rule names this resource, 'host' when only rules
        that block the whole host do, None when nothing blocks it. A rule
        that also matches the bare host URL blocks the whole host, so it
        counts as a host block whatever its shape (`.doubleclick.net/`)."""
        sample = f"https://{host}{path if path[:1] in ('/', '?', ':') else '/' + path}"
        bare = f"https://{host}/"
        sample_lower = sample.lower()
        host_hit = False
        for rule_host, rule_prefix, host_level, url_filter in self.by_base.get(_base(host), ()):
            if not _hosts_related(host, rule_host):
                continue
            if host_level:
                # A whole-host block on a subdomain of the exception's host
                # is still just a host block the exception narrows.
                host_hit = True
            elif self._search(url_filter, sample):
                if self._search(url_filter, bare):
                    host_hit = True
                else:
                    return "path"
            elif rule_prefix.startswith(path_prefix):
                # A narrower path rule inside the excepted area.
                return "path"
        for literal, url_filter in self.generic:
            if literal and literal not in sample_lower:
                continue
            if self._search(url_filter, sample):
                if self._search(url_filter, bare):
                    host_hit = True
                else:
                    return "path"
        return "host" if host_hit else None


def page_safe_copies(rule):
    """The rule, split so no copy matches a top-frame page load."""
    trigger = rule["trigger"]
    types = trigger.get("resource-type")
    pinned = trigger.get("load-context") == ["child-frame"]
    if types is not None and ("document" not in types or pinned):
        return [rule]
    others = NON_PAGE_TYPES if types is None else [t for t in types if t != "document"]
    copies = []
    if others:
        copies.append({"trigger": {**trigger, "resource-type": sorted(others)},
                       "action": dict(rule["action"])})
    if "load-context" not in trigger:
        copies.append({"trigger": {**trigger, "resource-type": ["document"],
                                   "load-context": ["child-frame"]},
                       "action": dict(rule["action"])})
    return copies


def is_ad_infrastructure(host, path, path_prefix):
    """Rule 5: does this exception's URL belong to ad serving?"""
    if any(host == h and path_prefix.startswith(p) for h, p in AD_INFRA_ALLOW):
        return False
    labels = host.split(".")
    if any(".".join(labels[i:]) in AD_INFRA_DOMAINS for i in range(len(labels) - 1)):
        return True
    if host.startswith(AD_INFRA_HOST_PREFIXES):
        return True
    if any((host == h or host.endswith("." + h)) and path_prefix.startswith(p)
           for h, p in AD_INFRA_PATHS):
        return True
    return bool(AD_INFRA_PATH_TOKENS.search(path))


def cross_exception_verdict(rule, index, unscoped_ok=True):
    """'keep' or the reason one source exception is not copied into the
    blocker `index` describes. See the rules above. `unscoped_ok` is False
    for an exception that came from a supplement list."""
    if rule.get("action", {}).get("type") != "ignore-previous-rules":
        return "not-a-url-exception"
    trigger = rule["trigger"]
    parsed = parse_anchored(trigger.get("url-filter", ""))
    if not parsed:
        return "not-host-anchored"
    host, path, path_prefix = parsed
    site_scoped = any(key in trigger for key in SITE_SCOPE_KEYS)
    if not re.search(r"[a-z0-9]", path):
        # Rule 3b: a whole-host exception is never copied, even scoped.
        return "scoped-whole-host" if site_scoped else "unscoped-whole-host"
    if not site_scoped and not unscoped_ok:
        return "unscoped-from-supplement"
    if is_ad_infrastructure(host, path, path_prefix):
        return "ad-infrastructure"
    how = index.classify(host, path, path_prefix)
    if how == "path":
        return "target-blocks-this-path"
    if how is None:
        return "no-op-in-target"
    return "keep"


def propagate_exceptions(states):
    """Copies each blocker's URL exceptions into the other blockers'
    network_exceptions bucket (after their block rules in assemble()).
    Returns {(source, target): {"keep"/reason: [rules]}} for reporting."""
    sources = {list_id: abp2safari.dedupe(state["buckets"]["network_exceptions"])
               for list_id, state in states.items()}
    unscoped_ok = {list_id: state.get("unscoped_ok") for list_id, state in states.items()}
    report = {}
    for target, state in states.items():
        index = BlockIndex(state["buckets"]["network"])
        seen = {json.dumps(r, sort_keys=True) for r in state["buckets"]["network_exceptions"]}
        added = []
        for source, rules in sources.items():
            if source == target:
                continue
            verdicts = report.setdefault((source, target), {})
            trusted = unscoped_ok[source]
            for rule in rules:
                verdict = cross_exception_verdict(
                    rule, index,
                    trusted is None or json.dumps(rule, sort_keys=True) in trusted)
                verdicts.setdefault(verdict, []).append(rule)
                if verdict != "keep":
                    continue
                for copy in page_safe_copies(rule):
                    key = json.dumps(copy, sort_keys=True)
                    if key not in seen:
                        seen.add(key)
                        added.append(copy)
        state["buckets"]["network_exceptions"].extend(added)
        state["cross_added"] = len(added)
    return report


def print_cross_report(report):
    for (source, target), verdicts in report.items():
        counts = {k: len(v) for k, v in sorted(verdicts.items())}
        print(f"  exceptions {source} -> {target}: {counts}")
        for verdict, rules in sorted(verdicts.items()):
            for rule in rules[:CROSS_EXAMPLES]:
                print(f"    {verdict}: {json.dumps(rule['trigger'])[:160]}")


MIN_PRIMARY_LINES = 10_000
MIN_KEPT_FRACTION = 0.70


def previous_rule_count(path):
    """Rule count of the list about to be replaced, or None."""
    try:
        with open(path, encoding="utf-8") as f:
            return len(json.load(f))
    except (OSError, ValueError):
        return None


def collect(list_id, spec, cache_dir, allow_shrink=False):
    """Converts every source of one blocker into rule buckets. Exceptions
    from the other blockers are added before finish() assembles them."""
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
    primary_exceptions = len(buckets["network_exceptions"])

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

    before_local = len(buckets["network_exceptions"])
    merge_local_lists(list_id, spec, buckets, runtime)
    # Exceptions from the primary list and Blindfold's own lists may be
    # copied to other blockers without a $domain= scope; a supplement's
    # (regional lists, Peter Lowe's, AdGuard Annoyances) only with one.
    exceptions = buckets["network_exceptions"]
    unscoped_ok = {json.dumps(rule, sort_keys=True)
                   for rule in exceptions[:primary_exceptions] + exceptions[before_local:]}

    # Curated Blindfold rules ride in front of the standard list's network
    # block so list-level exceptions can still cancel them.
    extras = spec["extras"]()
    buckets["network"] = extras + buckets["network"]
    return {"buckets": buckets, "stats": stats, "runtime": runtime, "text": text,
            "unscoped_ok": unscoped_ok}


def finish(list_id, spec, state, allow_shrink=False):
    """Assembles, lints and writes one blocker's list."""
    buckets, stats, runtime, text = (state[k] for k in ("buckets", "stats", "runtime", "text"))
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
    print(f"[{list_id}] {out if spec.get('dist') else spec['output']}: {len(rules):,} rules "
          f"({size_mb:.1f} MB, cap {spec['max_rules']:,}), "
          f"{state.get('cross_added', 0):,} copied from other blockers' exceptions")
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
    parser.add_argument("--no-cross-exceptions", action="store_true",
                        help="do not copy URL exceptions between blockers (for comparison)")
    args = parser.parse_args()

    if args.dist:
        os.makedirs(args.dist, exist_ok=True)
        for list_id, spec in SOURCES.items():
            spec["output"] = None
            spec["dist"] = os.path.join(args.dist, f"{list_id}.json")

    total = 0
    estimator_domains = {}
    merged_runtime = {"procedural": [], "scriptlets": []}
    states = {list_id: collect(list_id, spec, args.cache, args.allow_shrink)
              for list_id, spec in SOURCES.items()}
    if args.no_cross_exceptions:
        print("cross-blocker exceptions: off")
    else:
        print("cross-blocker exceptions:")
        print_cross_report(propagate_exceptions(states))
    for list_id, spec in SOURCES.items():
        count, domains, runtime = finish(list_id, spec, states[list_id], args.allow_shrink)
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
