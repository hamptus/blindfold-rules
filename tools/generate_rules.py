#!/usr/bin/env python3
"""Generates Blindfold's bundled content-blocker rule lists.

Outputs:
  ContentBlockers/Ads/blockerList.json         — ad network blocking
  ContentBlockers/Privacy/blockerList.json     — tracker/analytics blocking
  ContentBlockers/Annoyances/blockerList.json  — cosmetic rules, popups, CMP overlays
  WebExtension/Resources/blocklist.js          — domain sets for the helper's stats estimator

These bundled lists are the floor, not the ceiling: the app downloads fresher,
larger lists over the air (see RuleUpdateService). Keep this curated set accurate
and conservative — it is what users get offline on first launch.
"""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SEPARATOR = r"([^a-zA-Z0-9_.%-].*)?$"


def domain_rule(domain, resource_types=None, third_party=True, action="block"):
    rule = {
        "trigger": {
            "url-filter": r"^[a-z][a-z+.-]*://([^/:]+\.)?" + domain.replace(".", r"\.") + SEPARATOR,
            "url-filter-is-case-sensitive": False,
        },
        "action": {"type": action},
    }
    if third_party:
        rule["trigger"]["load-type"] = ["third-party"]
    if resource_types:
        rule["trigger"]["resource-type"] = resource_types
    return rule


def css_rule(selector, if_domain=None):
    trigger = {"url-filter": ".*"}
    if if_domain:
        trigger["if-domain"] = if_domain
    return {"trigger": trigger, "action": {"type": "css-display-none", "selector": selector}}


# --- Ad networks (blocked for third-party loads) -------------------------------

AD_DOMAINS = [
    # Google ads stack
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "googletagservices.com", "adservice.google.com", "admob.com",
    # Major exchanges / SSPs / DSPs
    "adnxs.com", "adsrvr.org", "rubiconproject.com", "magnite.com", "pubmatic.com",
    "openx.net", "criteo.com", "criteo.net", "smartadserver.com", "casalemedia.com",
    "indexww.com", "33across.com", "sharethrough.com", "triplelift.com",
    "yieldmo.com", "teads.tv", "spotxchange.com", "spotx.tv", "fwmrm.net",
    "innovid.com", "serving-sys.com", "zedo.com", "bidswitch.net", "contextweb.com",
    "sovrn.com", "lijit.com", "gumgum.com", "adyoulike.com", "adform.net",
    "yieldlab.net", "smaato.net", "inmobi.com", "applovin.com", "unityads.unity3d.com",
    "vungle.com", "ironsrc.com", "supersonicads.com", "chartboost.com",
    "amazon-adsystem.com", "media.net", "mediavine.com", "adthrive.com",
    "raptive.com", "ezoic.net", "ezodn.com", "adlightning.com",
    # Native / content recommendation
    "taboola.com", "outbrain.com", "revcontent.com", "mgid.com", "zergnet.com",
    "content-ad.net", "adblade.com", "nativeads.com", "plista.com",
    # Retargeting / misc networks
    "adroll.com", "perfectaudience.com", "steelhousemedia.com", "quantcast.com",
    "yieldoptimizer.com", "mathtag.com", "turn.com", "advertising.com",
    "adtechus.com", "undertone.com", "conversantmedia.com", "dotomi.com",
    "buysellads.com", "buysellads.net", "carbonads.com", "carbonads.net",
    "bsa.live", "adbutler.com", "broadstreetads.com",
    # Pop / aggressive networks
    "popads.net", "popcash.net", "propellerads.com", "propellerclick.com",
    "adcash.com", "hilltopads.net", "exoclick.com", "juicyads.com",
    "trafficjunky.net", "trafficfactory.biz", "adsterra.com",
    "highperformanceformat.com", "onclickalgo.com", "onclasrv.com",
    "adskeeper.com", "mybetterad.com", "clickadu.com", "adspyglass.com",
    # Video ads
    "imasdk.googleapis.com", "springserve.com", "tremorhub.com", "stickyadstv.com",
    "uplynk.com", "yumenetworks.com", "brightcove.com",  # brightcove ad modules only via path rules below
]
# Domains where blanket blocking breaks legitimate content; block only ad paths.
AD_DOMAINS.remove("brightcove.com")
AD_DOMAINS.remove("uplynk.com")

AD_SUBDOMAIN_PATTERNS = [
    # Common ad-serving hostname prefixes on any domain. Third-party only, so a
    # site's own "ads." host for its first-party pages is unaffected.
    r"^[a-z][a-z+.-]*://ads\.",
    r"^[a-z][a-z+.-]*://adserver\.",
    r"^[a-z][a-z+.-]*://adservice\.",
    r"^[a-z][a-z+.-]*://banners?\.",
    r"^[a-z][a-z+.-]*://creatives?\.",
]

AD_PATH_RULES = [
    # Safe, unambiguous ad-serving paths.
    (r"/pagead/js/adsbygoogle", ["script"]),
    (r"/adsbygoogle\.js", ["script"]),
    (r"/gpt/pubads_impl", ["script"]),
    (r"/gampad/ads\?", ["raw", "document"]),
    (r"/securepubads\.", ["script", "raw"]),
]

# --- Trackers (blocked for third-party loads) ----------------------------------

TRACKER_DOMAINS = [
    # Google analytics stack
    "google-analytics.com", "analytics.google.com", "googletagmanager.com",
    # Meta
    "connect.facebook.net",
    # Audience measurement
    "scorecardresearch.com", "quantserve.com", "imrworldwide.com", "chartbeat.com",
    "parsely.com", "permutive.com", "comscore.com",
    # Session replay / heatmaps
    "hotjar.com", "fullstory.com", "mouseflow.com", "clarity.ms", "luckyorange.com",
    "inspectlet.com", "smartlook.com", "logrocket.com", "sessioncam.com",
    # Product analytics
    "mixpanel.com", "segment.com", "segment.io", "amplitude.com",
    "heapanalytics.com", "kissmetrics.io", "crazyegg.com", "matomo.cloud",
    "plausible.io", "usefathom.com", "statcounter.com", "clicky.com",
    # Mobile attribution
    "adjust.com", "appsflyer.com", "kochava.com", "branch.io", "app.link",
    "singular.net", "tenjin.io",
    # Data brokers / identity graphs
    "demdex.net", "omtrdc.net", "2o7.net", "everesttech.net", "krxd.net",
    "bluekai.com", "exelator.com", "eyeota.net", "id5-sync.com", "rlcdn.com",
    "pippio.com", "tapad.com", "agkn.com", "liadm.com", "adsymptotic.com",
    "owneriq.net", "narrative.io", "throtle.io",
    # Social pixels
    "analytics.tiktok.com", "tr.snapchat.com", "sc-static.net",
    "static.ads-twitter.com", "analytics.twitter.com", "ads-api.twitter.com",
    "snap.licdn.com", "px.ads.linkedin.com", "ct.pinterest.com",
    "events.redditmedia.com", "alb.reddit.com", "bat.bing.com",
    # Marketing automation beacons
    "track.hubspot.com", "js.hs-analytics.net", "pardot.com", "marketo.net",
    "mktoresp.com", "act-on.com", "eloqua.com",
    # Ad verification (tracks users to "verify" ads)
    "moatads.com", "adsafeprotected.com", "doubleverify.com", "iasds01.com",
    # Misc
    "mc.yandex.ru", "yandexmetrica.com", "newrelic.com", "nr-data.net",
    "addthis.com", "sharethis.com", "po.st", "cxense.com", "bounceexchange.com",
    "bouncex.net", "wunderkind.co", "pushcrew.com", "onesignal.com",
    "pushengage.com", "izooto.com", "webpushr.com",
]

TRACKER_PATH_RULES = [
    (r"/collect\?v=1&", ["raw", "image"]),          # Universal Analytics beacon
    (r"/g/collect\?v=2", ["raw", "image"]),          # GA4 beacon
    (r"/gtag/js\?", ["script"]),
    (r"/fbevents\.js", ["script"]),
    (r"/tr\?id=[0-9]+&ev=", ["raw", "image"]),       # Meta pixel
    # Safari's url-filter regex dialect has no disjunction — a single `(js|php)`
    # would make WebKit reject the ENTIRE list. One rule per extension.
    (r"/piwik\.js", ["script", "raw"]),
    (r"/piwik\.php", ["script", "raw"]),
    (r"/matomo\.js", ["script", "raw"]),
    (r"/matomo\.php", ["script", "raw"]),
]

# --- Annoyances -----------------------------------------------------------------

COSMETIC_SELECTORS = [
    # Google ad units
    "ins.adsbygoogle", "div[id^=\"div-gpt-ad\"]", "div[id^=\"google_ads_iframe\"]",
    "iframe[id^=\"google_ads_iframe\"]", "#google_ads_frame1",
    # Native ad widgets
    "[id^=\"taboola-\"]", ".trc_related_container", ".OUTBRAIN", ".ob-widget",
    ".rc-widget", "[data-widget-id^=\"rev_\"]", ".mgbox", ".zergnet-widget",
    # Generic ad containers (kept narrow to avoid false positives)
    ".ad-leaderboard", ".ad-billboard", ".ad-skyscraper", ".ad-sidebar-rail",
    "div[class^=\"ad-slot-\"]", "div[data-ad-unit-path]", "div[data-google-query-id]",
    "[aria-label=\"advertisement\" i]", "[aria-label=\"sponsored\" i]",
    # Sponsored content markers
    ".sponsored-content-container", ".partner-content-box", ".paid-post-wrapper",
]

CMP_SELECTORS = [
    # Consent-management overlays (the helper extension restores page scroll).
    "#onetrust-consent-sdk", "#CybotCookiebotDialog", "#CybotCookiebotDialogBodyUnderlay",
    ".qc-cmp2-container", "#didomi-host", ".fc-consent-root", "#truste-consent-track",
    "#usercentrics-root", ".osano-cm-window", "#cookiescript_injected",
    "#cookie-law-info-bar", ".cky-consent-container", "#hs-eu-cookie-confirmation",
    ".cc-window.cc-banner", "#cookieNotice", ".js-consent-banner",
]

POPUP_DOMAINS = [
    "popads.net", "popcash.net", "propellerads.com", "onclickalgo.com",
    "onclasrv.com", "adsterra.com", "hilltopads.net",
]


def build_ads():
    rules = [domain_rule(d) for d in sorted(set(AD_DOMAINS))]
    for pattern in AD_SUBDOMAIN_PATTERNS:
        rules.append({
            "trigger": {
                "url-filter": pattern,
                "url-filter-is-case-sensitive": False,
                "load-type": ["third-party"],
                "resource-type": ["script", "image", "raw", "document"],
            },
            "action": {"type": "block"},
        })
    for path, types in AD_PATH_RULES:
        rules.append({
            "trigger": {"url-filter": path, "resource-type": types},
            "action": {"type": "block"},
        })
    return rules


def build_privacy():
    rules = [domain_rule(d) for d in sorted(set(TRACKER_DOMAINS))]
    for path, types in TRACKER_PATH_RULES:
        rules.append({
            "trigger": {"url-filter": path, "load-type": ["third-party"], "resource-type": types},
            "action": {"type": "block"},
        })
    # Strip cookies on requests to known data brokers even when first-party framed.
    for d in ["demdex.net", "krxd.net", "bluekai.com", "rlcdn.com", "id5-sync.com"]:
        rules.append(domain_rule(d, third_party=False, action="block-cookies"))
    return rules


def build_annoyances():
    rules = [css_rule(s) for s in COSMETIC_SELECTORS + CMP_SELECTORS]
    for d in sorted(set(POPUP_DOMAINS)):
        rules.append(domain_rule(d, resource_types=["popup"], third_party=False))
    return rules


def write(path, rules):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=1)
    print(f"{path}: {len(rules)} rules")


def write_blocklist_js(extra_ads=None, extra_trackers=None):
    """Domain sets used by the helper extension to estimate blocked requests.

    build_lists.py passes in host-only domains extracted from EasyList /
    EasyPrivacy so the estimator keeps pace with what the blockers block."""
    payload = {
        "ads": sorted(set(AD_DOMAINS + POPUP_DOMAINS + list(extra_ads or []))),
        "trackers": sorted(set(
            d for d in TRACKER_DOMAINS + list(extra_trackers or [])
            # JS matcher works on hostnames; strip path-style entries.
            if "/" not in d
        )),
        "cosmetic": COSMETIC_SELECTORS,
        "cmp": CMP_SELECTORS,
    }
    full = os.path.join(ROOT, "WebExtension/Resources/blocklist.js")
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write("// Generated by tools/generate_rules.py — do not edit by hand.\n")
        f.write("const BLINDFOLD_BLOCKLIST = ")
        json.dump(payload, f, indent=1)
        f.write(";\n")
    # The same data as plain JSON. The worker loads this one with fetch():
    # importScripts of a script first imported after the install phase is a
    # NetworkError under the Service Worker spec, so the JS form is only a
    # fallback. tools/jstests/test_blocklist_loading.mjs checks the two agree.
    with open(os.path.join(ROOT, "WebExtension/Resources/blocklist.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))
        f.write("\n")
    print(f"WebExtension/Resources/blocklist.js + blocklist.json: "
          f"{len(payload['ads'])} ad domains, {len(payload['trackers'])} tracker domains")


# --- Runtime cosmetic index (helper extension) ---------------------------------

# Curated procedural seeds: applied by cosmetic.js where declarative rules can't
# reach. `generic` runs on every site, so each entry must be near-impossible to
# match legitimate content; domain entries come from the big lists at build time.
SEED_GENERIC_PROCEDURAL = [
    # Anti-adblock nag overlays that name themselves.
    'body > div[class*="adblock" i]:has-text(/ad ?block/i)',
    'body > div[id*="adblock" i]:has-text(/ad ?block/i)',
]

SEED_DOMAIN_PROCEDURAL = [
    # (host, selector) — populated by the full list build; keep empty here.
]

MAX_RUNTIME_PROCEDURAL = 25_000
MAX_COSMETICS_BYTES = 2_000_000


def write_cosmetics_js(procedural=None, scriptlets=None, out_dir=None):
    """Emits the helper extension's runtime rule indexes:

    cosmetics.js            — BLINDFOLD_COSMETICS, read by cosmetic.js (isolated world)
    cosmetics-scriptlets.js — BLINDFOLD_SCRIPTLET_INDEX, read by scriptlets.js (MAIN world)
    scriptlet-hosts.js       — compact host list used to scope dynamic registration

    `out_dir` overrides the default WebExtension/Resources target — the OTA
    rules repo passes its dist directory so the indexes publish alongside the
    blocker lists."""
    domains = {}
    count = 0
    dropped = 0
    entries = list(SEED_DOMAIN_PROCEDURAL) + list(procedural or [])
    for host, selector in entries:
        if count >= MAX_RUNTIME_PROCEDURAL:
            dropped += 1
            continue
        bucket = domains.setdefault(host, [])
        if selector not in bucket:
            bucket.append(selector)
            count += 1
    payload = {
        "version": 1,
        "generic": SEED_GENERIC_PROCEDURAL,
        "domains": domains,
    }
    target = out_dir or os.path.join(ROOT, "WebExtension/Resources")
    full = os.path.join(target, "cosmetics.js")
    # Size-check BEFORE the file lands — an oversized index must never
    # replace the good one on disk.
    tmp = full + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("// Generated by tools/build_lists.py — do not edit by hand.\n")
        f.write("const BLINDFOLD_COSMETICS = ")
        json.dump(payload, f, separators=(",", ":"))
        f.write(";\n")
    size = os.path.getsize(tmp)
    if size > MAX_COSMETICS_BYTES:
        os.unlink(tmp)
        raise SystemExit(f"cosmetics.js is {size:,} bytes (cap {MAX_COSMETICS_BYTES:,}) — "
                         "tighten MAX_RUNTIME_PROCEDURAL or per-domain caps")
    os.replace(tmp, full)
    if dropped:
        print(f"  cosmetics.js: dropped {dropped:,} procedural rules over the "
              f"{MAX_RUNTIME_PROCEDURAL:,} cap")
    print(f"{full}: {count:,} domain procedural rules, "
          f"{len(SEED_GENERIC_PROCEDURAL)} generic ({size / 1e3:.0f} kB)")

    sindex = {}
    for host, name, args in (scriptlets or []):
        entry = [name] + list(args)
        bucket = sindex.setdefault(host, [])
        if entry not in bucket:
            bucket.append(entry)
    full = os.path.join(target, "cosmetics-scriptlets.js")
    with open(full, "w", encoding="utf-8") as f:
        f.write("// Generated by tools/build_lists.py — do not edit by hand.\n")
        f.write("const BLINDFOLD_SCRIPTLET_INDEX = ")
        json.dump(sindex, f, separators=(",", ":"))
        f.write(";\n")
    print(f"{full}: "
          f"{sum(len(v) for v in sindex.values()):,} scriptlet rules on {len(sindex):,} hosts")

    # The full index stays out of the service worker and out of unrelated pages.
    # This small companion lets background.js register the index only on hosts
    # that can use it. Sorted output keeps builds deterministic.
    hosts_full = os.path.join(target, "scriptlet-hosts.js")
    with open(hosts_full, "w", encoding="utf-8") as f:
        f.write("// Generated by tools/build_lists.py — do not edit by hand.\n")
        f.write("const BLINDFOLD_SCRIPTLET_HOSTS = ")
        json.dump(sorted(sindex), f, separators=(",", ":"))
        f.write(";\n")
    print(f"{hosts_full}: {len(sindex):,} hosts")


if __name__ == "__main__":
    write("ContentBlockers/Ads/blockerList.json", build_ads())
    write("ContentBlockers/Privacy/blockerList.json", build_privacy())
    write("ContentBlockers/Annoyances/blockerList.json", build_annoyances())
    write_blocklist_js()
    write_cosmetics_js()
