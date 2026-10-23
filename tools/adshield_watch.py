#!/usr/bin/env python3
"""Daily Ad Shield drift check.

Ad Shield (the vendor anti-adblock behind html-load.com and error-report.com)
runs on Yahoo and on Future plc sites. Blindfold counters it with hand-written
rules in tools/lists/blindfold-ads.txt and tools/lists/hotfix-ads.txt. Those
rules key on how the loader is delivered today: a static third-party
<script src> whose onerror handler reloads from rotating fallback hosts
(Future plc), or an inline script that writes the loader into the page
(Yahoo). When the vendor changes hosts or technique, the rules silently stop
matching. This script fetches the watched pages, extracts the Ad Shield
signatures from the raw HTML and compares them with what the rules know.

The watched sites, the blocked and muted hosts, and the inline needles all
come from the rules files, so a rule change updates the watch list too.

Drift (any of these sets "drift": true in the report):

  signature_vanished    the page fetched fine but carries no Ad Shield
                        signature at all (technique change, or Ad Shield left)
  loader_not_blocked    an Ad Shield loader tag loads from a host no block
                        rule covers for that site
  fallback_not_muted    an Ad Shield loader tag has an onerror/onload handler
                        and no mute-script-events rule covers its host
  inline_needle_missing an inline Ad Shield script exists but a site rule's
                        needle (abort-current-inline-script search, or
                        prevent-innerHTML needle) matches none of them
  inline_loader_unhandled  an inline Ad Shield script exists on a site with
                        no inline rule at all
  unknown_host          Ad Shield code references a host that appears
                        nowhere in the rules files (comments included), is
                        not the site itself, and is not a known bait host
  final_host_not_covered  the page redirected to a site no Ad Shield rule
                        names, so none of the rules apply there

A failed fetch (HTTP error, timeout, bot challenge) is reported but is never
drift on its own. The exit status is 0 unless the script itself crashes.

To acknowledge a host without a rule (a bait or first-party CDN host), name it
in a comment in tools/lists/hotfix-ads.txt through a reviewed PR.

Usage:
    python3 tools/adshield_watch.py [--out report.json] [--issue-body issue.md]
        [--fixtures DIR] [--only HOST,...] [--workers N] [--timeout S]

Standard library only.
"""

import argparse
import concurrent.futures
import datetime
import gzip
import hashlib
import html
import html.parser
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

TOOLS = os.path.dirname(os.path.abspath(__file__))
LISTS_DIR = os.path.join(TOOLS, "lists")
RULE_FILES = ("blindfold-ads.txt", "hotfix-ads.txt")
REPORT_VERSION = 1
ISSUE_MARKER = "<!-- adshield-drift-report v1 -->"

USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/26.0 Safari/605.1.15")

# The rules name yahoo.com; these are the pages Ad Shield runs on there.
PAGE_OVERRIDES = {
    "yahoo.com": [
        "https://www.yahoo.com/",
        "https://news.yahoo.com/",
        "https://finance.yahoo.com/",
        "https://sports.yahoo.com/",
    ],
}

# Hosts Ad Shield's detector probes on purpose (bait requests and ad stack
# checks). They show up in its code every day and are not drift.
BAIT_DOMAINS = {
    "ad-delivery.net",
    "doubleclick.net",
    "taboola.com",
    "googlesyndication.com",
    "googletagservices.com",
    "googletagmanager.com",
    "google-analytics.com",
}

# Vendor fingerprints that hold across hosts. The data-sdk attribute
# ("l/1.2.22" on Future plc tags, "y-l/1.0.x" in Yahoo's inline loader), the
# string-permutation decoder its handlers are built on, and the names its
# blocker-detection wrapper uses on Yahoo.
SDK_ATTR_RE = re.compile(r"^[a-z]{0,3}-?l/\d+(?:\.\d+){1,3}$")
SDK_INLINE_RE = re.compile(r"data-sdk\\?[\"']\s*,\s*\\?[\"']([a-z]{0,3}-?l/\d+(?:\.\d+){1,3})")
DECODER_RE = re.compile(r"\[\(\w+\+[\w.]+\)\*[\w.]+%\w+\]|\[\d+\*\(\w+\+\d+\)%\w+\]")
EVAL_RE = re.compile(r"\(\)=(?:>|\\u003e|&gt;)eval|await eval")
VENDOR_MARKERS = {
    "benji-adshield-global": re.compile(r"__benjiAdShield\w*"),
    "benji-bfa-key": re.compile(r"benji_as_bfa"),
    "last-bfa-at": re.compile(r"last_bfa_at"),
}

MARKER_NAMES = set(VENDOR_MARKERS) | {"permutation-decoder", "eval-call", "data-sdk"}

# A script that is Next.js's serialized copy of the page (RSC flight data).
FLIGHT_RE = re.compile(r"^\s*self\.__next_f\.push")
FLIGHT_WINDOW = 20_000

HOST_IN_TEXT_RE = re.compile(r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?![\w-])")
URL_HOST_RE = re.compile(r"(?:https?:)?(?:\\?/){2}((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})", re.I)
NOT_TLDS = {"py", "txt", "js", "json", "md", "css", "html", "swift", "yml", "sh", "mjs"}
MULTI_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au",
                        "co.nz", "co.jp", "com.br", "co.in", "co.za", "com.mx"}

CHALLENGE_RE = re.compile(r"Just a moment\.\.\.|cf-challenge|captcha-delivery|Access Denied|"
                          r"Request unsuccessful\. Incapsula|px-captcha", re.I)
CHALLENGE_MAX_BYTES = 60_000

ISSUE_BODY_LIMIT = 60_000


# --- hosts ------------------------------------------------------------------

def reg_domain(host):
    """Registrable domain, close enough for the hosts this watches."""
    labels = (host or "").lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_covered(host, hosts):
    """True when host is one of hosts or a subdomain of one."""
    if not host:
        return False
    host = host.lower()
    return any(host == h or host.endswith("." + h) for h in hosts)


VALID_HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")
# A real DNS shape: 2 to 8 labels of at most 63 characters, no empty or
# hyphen-edged labels, an all-letter TLD. Keeps a page from spelling words
# out across many long labels ("ignore.previous.instructions...").
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TLD_RE = re.compile(r"^[a-z]{2,24}$")


def clean_host(host):
    """A page-derived host, lowercased, or None when it is not a plain DNS
    name. Everything page-derived that reaches the report or the issue goes
    through here, so a page cannot smuggle text in as a "host"."""
    if not isinstance(host, str):
        return None
    host = host.strip().lower().rstrip(".")
    if not VALID_HOST_RE.match(host):
        return None
    labels = host.split(".")
    if not 2 <= len(labels) <= 8 or not TLD_RE.match(labels[-1]):
        return None
    if not all(DNS_LABEL_RE.match(label) for label in labels):
        return None
    return host


def hosts_in_text(text):
    hosts = set()
    for match in HOST_IN_TEXT_RE.finditer(text.lower()):
        host = match.group(1)
        if host.rsplit(".", 1)[-1] in NOT_TLDS:
            continue
        hosts.add(host)
    return hosts


def url_hosts(text):
    hosts = set()
    for m in URL_HOST_RE.finditer(text):
        host = clean_host(m.group(1))
        if host and host.rsplit(".", 1)[-1] not in NOT_TLDS:
            hosts.add(host)
    return hosts


# --- rules ------------------------------------------------------------------

SCRIPTLET_RE = re.compile(r"^(?P<domains>[^#]*)#%#//scriptlet\((?P<args>.*)\)\s*$")
UBO_SCRIPTLET_RE = re.compile(r"^(?P<domains>[^#]*)##\+js\((?P<args>.*)\)\s*$")
NETWORK_RE = re.compile(r"^\|\|(?P<host>[a-z0-9.-]+)\^(?:\$(?P<opts>.*))?$")
QUOTED_ARG_RE = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"")


def scriptlet_args(raw, ubo=False):
    if ubo:
        return [a.strip() for a in raw.split(",")]
    return [(m.group(1) if m.group(1) is not None else m.group(2)) for m in QUOTED_ARG_RE.finditer(raw)]


def needle_matcher(needle):
    """A scriptlet needle: /regex/ or a plain substring."""
    if len(needle) > 2 and needle.startswith("/") and needle.endswith("/"):
        try:
            return re.compile(needle[1:-1])
        except re.error:
            return re.compile(re.escape(needle))
    return re.compile(re.escape(needle))


def needle_alternatives(needle):
    """Top-level branches of a /a|b|c/ needle, for the "absent" diagnostics."""
    if not (needle.startswith("/") and needle.endswith("/")):
        return [needle]
    return [b for b in re.split(r"(?<!\\)\|", needle[1:-1]) if b]


class Rules:
    """What the rules files say about Ad Shield."""

    def __init__(self, files):
        self.files = []
        self.known_hosts = set()       # every host the rules files mention
        self.seed_hosts = set()        # hosts named in Ad Shield rules or headers
        self.block = []                # (host, domains or None)
        self.mute = []                 # (needle, domains)
        self.inline = []               # (rule text, name, needle, domains)
        self.rule_domains = set()      # domains Ad Shield rules apply to
        for name, lines in files:
            self.files.append(name)
            self._parse(name, lines)

    @classmethod
    def from_dir(cls, lists_dir=LISTS_DIR):
        files = []
        for name in RULE_FILES:
            path = os.path.join(lists_dir, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    files.append((name, f.read().splitlines()))
        if not files:
            raise SystemExit(f"no rules files in {lists_dir}")
        return cls(files)

    def _parse(self, name, lines):
        in_adshield = False
        candidates = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            self.known_hosts |= hosts_in_text(line)
            if line.startswith("!"):
                if line.startswith("! ---"):
                    in_adshield = "ad shield" in line.lower()
                    if in_adshield:
                        self.seed_hosts |= hosts_in_text(line)
                continue
            candidates.append((line, in_adshield))
        # A rule outside an Ad Shield section still counts when it names an
        # Ad Shield host (hotfix-ads.txt has no sections).
        for line, in_section in candidates:
            if in_section:
                m = NETWORK_RE.match(line)
                if m:
                    self.seed_hosts.add(m.group("host"))
        for line, in_section in candidates:
            if in_section or any(h in line for h in self.seed_hosts):
                self._add_rule(line)

    def _add_rule(self, line):
        m = NETWORK_RE.match(line)
        if m:
            domains = None
            for opt in (m.group("opts") or "").split(","):
                if opt.startswith("domain="):
                    domains = {d for d in opt[len("domain="):].split("|") if d and not d.startswith("~")}
            self.block.append((m.group("host"), domains))
            self.seed_hosts.add(m.group("host"))
            if domains:
                self.rule_domains |= domains
            return
        m = SCRIPTLET_RE.match(line) or UBO_SCRIPTLET_RE.match(line)
        if not m:
            return
        domains = {d.strip() for d in m.group("domains").split(",") if d.strip() and not d.startswith("~")}
        args = scriptlet_args(m.group("args"), ubo=line.find("##+js(") >= 0)
        if not args or not domains:
            return
        name, rest = args[0], args[1:]
        self.rule_domains |= domains
        if name == "mute-script-events" and rest:
            self.mute.append((rest[0], domains))
        elif name in ("abort-current-inline-script", "acis") and len(rest) >= 2:
            self.inline.append((line, name, rest[1], domains))
        elif name in ("prevent-innerHTML",) and len(rest) >= 2:
            self.inline.append((line, name, rest[1], domains))

    # Per-site views. A rule applies to a site when one of its domains is the
    # site's registrable domain or a parent of it.
    @staticmethod
    def _applies(domains, host):
        return domains is None or host_covered(host, domains) or reg_domain(host) in domains

    def block_hosts(self, host):
        return {h for h, domains in self.block if self._applies(domains, host)}

    def mute_needles(self, host):
        return [n for n, domains in self.mute if self._applies(domains, host)]

    def inline_rules(self, host):
        return [(text, name, needle) for text, name, needle, domains in self.inline
                if self._applies(domains, host)]

    def covers_site(self, host):
        return host_covered(host, self.rule_domains) or reg_domain(host) in self.rule_domains

    def is_known(self, host):
        known_regs = {reg_domain(h) for h in self.known_hosts}
        return host_covered(host, self.known_hosts) or reg_domain(host) in known_regs

    def watch_list(self):
        """(rule domain, page URL) pairs, derived from the Ad Shield rules."""
        pages = []
        for domain in sorted(self.rule_domains):
            for url in PAGE_OVERRIDES.get(domain, [f"https://www.{domain}/"]):
                pages.append((domain, url))
        return pages


# --- HTML -------------------------------------------------------------------

class ScriptCollector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self._current = {"attrs": {k.lower(): (v if v is not None else "") for k, v in attrs},
                             "text": []}

    def handle_data(self, data):
        if self._current is not None:
            self._current["text"].append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._current is not None:
            self._current["text"] = "".join(self._current["text"])
            self.scripts.append(self._current)
            self._current = None


def collect_scripts(page_html):
    parser = ScriptCollector()
    try:
        parser.feed(page_html)
        parser.close()
    except Exception:  # malformed markup: keep what was parsed
        pass
    return parser.scripts


UNSAFE_TEXT_RE = re.compile(r"[^\w.~:/?#@!$&'()*+,;=%-]")


def safe_text(value, limit=300):
    """Page-controlled text (src, id) as it goes into the report and the
    issue: URL characters only, so a page cannot write Markdown or prose
    into what the issue reader sees."""
    return UNSAFE_TEXT_RE.sub("", value or "")[:limit]


def script_src_host(src, page_host):
    if not src:
        return None
    if src.startswith("//"):
        src = "https:" + src
    try:
        host = urllib.parse.urlparse(src).hostname
    except ValueError:  # e.g. "http://[::1"
        return None
    return clean_host(host or page_host)


def url_host(url):
    """Validated host of a URL, or None (malformed URLs included)."""
    try:
        return clean_host(urllib.parse.urlparse(url or "").hostname)
    except ValueError:
        return None


def vendor_markers(text):
    found = sorted(name for name, rx in VENDOR_MARKERS.items() if rx.search(text))
    if DECODER_RE.search(text):
        found.append("permutation-decoder")
    if EVAL_RE.search(text):
        found.append("eval-call")
    return found


def rule_needle_hits(text, rules, host):
    hits = set()
    for seed in rules.seed_hosts:
        if seed in text:
            hits.add(seed)
    for _, _, needle in rules.inline_rules(host):
        if needle_matcher(needle).search(text):
            hits.add(needle)
        for alt in needle_alternatives(needle):
            if alt != needle and needle_matcher("/" + alt + "/").search(text):
                hits.add(alt)
    return sorted(hits)


def windows_around(text, patterns, width):
    """Slices of text within width chars of any pattern match."""
    spans = []
    for pattern in patterns:
        for m in re.finditer(re.escape(pattern), text):
            spans.append((max(0, m.start() - width), m.end() + width))
    spans.sort()
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return "".join(text[s:e] for s, e in merged)


def extract_signatures(page_html, page_host, rules):
    """Ad Shield signatures in one page's raw HTML."""
    signatures, other_handlers = [], []
    page_reg = reg_domain(page_host)
    inline_candidates = []
    for script in collect_scripts(page_html):
        attrs, text = script["attrs"], script["text"]
        src = attrs.get("src")
        if src:
            src_host = script_src_host(src, page_host)
            handlers = {k: attrs[k] for k in ("onerror", "onload") if k in attrs}
            sdk = attrs.get("data-sdk", "")
            handler_text = " ".join(handlers.values())
            markers = vendor_markers(handler_text)
            if SDK_ATTR_RE.match(sdk):
                markers.append("data-sdk")
            third_party = src_host and reg_domain(src_host) != page_reg
            known_loader = src_host and host_covered(src_host, rules.seed_hosts)
            is_adshield = bool(sdk and SDK_ATTR_RE.match(sdk)) or (
                third_party and handlers and ("permutation-decoder" in markers or known_loader))
            if is_adshield:
                signatures.append({
                    "kind": "loader_tag",
                    "src": safe_text(src),
                    "src_host": src_host,
                    "handlers": sorted(handlers),
                    "handler_bytes": len(handler_text),
                    "data_sdk": safe_text(sdk, 40) or None,
                    "id": safe_text(attrs.get("id"), 80) or None,
                    "markers": sorted(set(markers)),
                    "rule_needles": rule_needle_hits(src + " " + handler_text, rules, page_host),
                    "hosts": sorted(url_hosts(handler_text)),
                })
            elif third_party and handlers:
                other_handlers.append({"src": safe_text(src), "src_host": src_host,
                                       "handlers": sorted(handlers)})
            continue
        if not text.strip():
            continue
        needles = rule_needle_hits(text, rules, page_host)
        markers = vendor_markers(text)
        sdk_versions = sorted(set(SDK_INLINE_RE.findall(text)))
        strong = any(m in VENDOR_MARKERS for m in markers) or sdk_versions
        decoder_eval = "permutation-decoder" in markers and "eval-call" in markers
        if needles or strong or decoder_eval:
            inline_candidates.append((text, needles, markers, sdk_versions))

    has_primary = any(not FLIGHT_RE.match(text) for text, *_ in inline_candidates)
    for text, needles, markers, sdk_versions in inline_candidates:
        flight = bool(FLIGHT_RE.match(text))
        if flight and has_primary:
            # Next.js serializes the same loader again for hydration; the
            # primary copy already carries everything.
            continue
        scope = text
        if flight:
            anchors = needles + [m.group(0) for rx in VENDOR_MARKERS.values() for m in rx.finditer(text)]
            scope = windows_around(text, anchors, FLIGHT_WINDOW)
        signatures.append({
            "kind": "inline_script",
            "bytes": len(text),
            "flight_copy": flight,
            "markers": markers + (["data-sdk"] if sdk_versions else []),
            "data_sdk": sdk_versions,
            "rule_needles": needles,
            "hosts": sorted(url_hosts(scope)),
        })
    return signatures, other_handlers


# --- analysis ---------------------------------------------------------------

def analyze_page(rule_domain, url, page_html, rules, final_url=None):
    """Signatures and drift for one fetched page."""
    final_url = final_url or url
    page_host = url_host(final_url) or url_host(url) or rule_domain
    signatures, other_handlers = extract_signatures(page_html, page_host, rules)
    drift = []

    if not rules.covers_site(page_host):
        drift.append({"kind": "final_host_not_covered",
                      "detail": f"{url} landed on {page_host}, which no Ad Shield rule names"})

    if not signatures:
        drift.append({"kind": "signature_vanished",
                      "detail": "no Ad Shield loader tag or inline script in the page"})

    block_hosts = rules.block_hosts(page_host)
    mute_needles = rules.mute_needles(page_host)
    for sig in signatures:
        if sig["kind"] != "loader_tag":
            continue
        if not host_covered(sig["src_host"], block_hosts):
            drift.append({"kind": "loader_not_blocked",
                          "detail": f"loader {sig['src_host'] or '(unparseable src)'} is not blocked on {page_host}"})
        if sig["handlers"] and not any(needle_matcher(n).search(sig["src"]) for n in mute_needles):
            drift.append({"kind": "fallback_not_muted",
                          "detail": f"{'/'.join(sig['handlers'])} on the {sig['src_host'] or '(unparseable src)'} tag is not muted"})

    inline = [s for s in signatures if s["kind"] == "inline_script"]
    inline_rules = rules.inline_rules(page_host)
    absent = set()
    if inline:
        if not inline_rules:
            drift.append({"kind": "inline_loader_unhandled",
                          "detail": "inline Ad Shield script on a site with no inline rule"})
        for text, name, needle in inline_rules:
            if not any(needle in s["rule_needles"] for s in inline):
                drift.append({"kind": "inline_needle_missing",
                              "detail": f"{name} needle {needle} matches no inline Ad Shield script",
                              "rule": text[:200]})
    page_needles = {n for s in signatures for n in s["rule_needles"]}
    for _, _, needle in inline_rules:
        for alt in needle_alternatives(needle):
            if alt not in page_needles:
                absent.add(alt)

    unknown = {}
    page_reg = reg_domain(page_host)
    for sig in signatures:
        hosts = set(sig["hosts"])
        if sig.get("src_host"):
            hosts.add(sig["src_host"])
        for host in hosts:
            if reg_domain(host) in (page_reg, reg_domain(rule_domain)):
                continue
            if reg_domain(host) in BAIT_DOMAINS or rules.is_known(host):
                continue
            unknown.setdefault(host, sig["kind"])
    for host, where in sorted(unknown.items()):
        drift.append({"kind": "unknown_host", "detail": f"{host} (in {where})", "host": host})

    return {
        "signatures": signatures,
        "unknown_hosts": sorted(unknown),
        "other_handler_scripts": other_handlers,
        "rule_needles_absent": sorted(absent),
        "drift": drift,
    }


# --- fetching ---------------------------------------------------------------

def bounded_decompress(raw, wbits, max_bytes):
    """At most max_bytes of decompressed output, however small the input."""
    decompressor = zlib.decompressobj(wbits)
    return decompressor.decompress(raw, max_bytes)


def decode_body(raw, encoding, max_bytes=8_000_000):
    """Body text, never more than max_bytes decoded bytes (a gzip bomb only
    yields its first max_bytes)."""
    encoding = (encoding or "").strip().lower()
    if encoding in ("gzip", "x-gzip"):
        raw = bounded_decompress(raw, 16 + zlib.MAX_WBITS, max_bytes)
    elif encoding == "deflate":
        try:
            raw = bounded_decompress(raw, zlib.MAX_WBITS, max_bytes)
        except zlib.error:
            raw = bounded_decompress(raw, -zlib.MAX_WBITS, max_bytes)
    return raw[:max_bytes].decode("utf-8", errors="replace")


def fetch(url, timeout=25, attempts=3, max_bytes=8_000_000):
    """(result dict, html or None). Never raises for network trouble."""
    result = {"ok": False, "status": None, "final_url": None, "bytes": 0,
              "attempts": 0, "error": None, "challenge": False}
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    }
    body = None
    for attempt in range(1, attempts + 1):
        result["attempts"] = attempt
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result["status"] = response.status
                result["final_url"] = safe_text(response.geturl(), 500)
                raw = response.read(max_bytes + 1)
                body = decode_body(raw[:max_bytes], response.headers.get("Content-Encoding"), max_bytes)
                result["error"] = None
                break
        except urllib.error.HTTPError as error:
            result["status"] = error.code
            result["error"] = f"HTTP {error.code}"
            if error.code == 404:
                break
        except Exception as error:  # timeouts, resets, DNS, bad gzip
            result["error"] = f"{type(error).__name__}: {safe_text(str(error), 200)}"
        if attempt < attempts:
            time.sleep(2 * attempt)
    if body is not None:
        result["bytes"] = len(body)
        if len(body) < CHALLENGE_MAX_BYTES and CHALLENGE_RE.search(body):
            result["challenge"] = True
            result["error"] = "bot challenge page"
            return result, None
        result["ok"] = True
    return result, body


def fixture_fetch(fixtures_dir):
    def fetch_fixture(url, **_):
        host = urllib.parse.urlparse(url).hostname or ""
        for name in (host, host[4:] if host.startswith("www.") else None):
            if not name:
                continue
            path = os.path.join(fixtures_dir, name + ".html")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    body = f.read()
                return ({"ok": True, "status": 200, "final_url": url, "bytes": len(body),
                         "attempts": 1, "error": None, "challenge": False}, body)
        return ({"ok": False, "status": None, "final_url": None, "bytes": 0, "attempts": 1,
                 "error": "no fixture", "challenge": False}, None)
    return fetch_fixture


# --- report -----------------------------------------------------------------

def run(rules, fetcher, only=None, workers=8, timeout=25):
    pages = rules.watch_list()
    if only:
        wanted = {o.strip().lower() for o in only if o.strip()}
        pages = [(d, u) for d, u in pages
                 if d in wanted or (urllib.parse.urlparse(u).hostname or "") in wanted]

    empty = {"signatures": [], "unknown_hosts": [], "other_handler_scripts": [],
             "rule_needles_absent": [], "drift": [], "analysis_error": None}

    def one(item):
        rule_domain, url = item
        entry = {"site": url_host(url) or rule_domain, "rule_domain": rule_domain, "url": url}
        entry.update(empty)
        # One bad page (odd markup, a parser corner case, a fetcher bug) is
        # recorded on that page and never aborts the run.
        try:
            fetch_result, body = fetcher(url, timeout=timeout)
        except Exception as error:
            fetch_result, body = ({"ok": False, "status": None, "final_url": None, "bytes": 0,
                                   "attempts": 0, "challenge": False,
                                   "error": f"fetcher crashed: {type(error).__name__}"}, None)
        entry["fetch"] = fetch_result
        if body is not None:
            try:
                entry.update(analyze_page(rule_domain, url, body, rules, fetch_result.get("final_url")))
            except Exception as error:
                entry["analysis_error"] = type(error).__name__
        return entry

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        sites = list(pool.map(one, pages))

    drift_items = [dict(item, site=s["site"]) for s in sites for item in s["drift"]]
    # Same drift on two days gives the same fingerprint, so a reader of the
    # issue can tell a repeat from something new.
    fingerprint = hashlib.sha256("\n".join(sorted(
        f"{i['site']}|{i['kind']}|{i['detail']}" for i in drift_items)).encode()).hexdigest()[:12]
    sdk_versions = sorted({v for s in sites for sig in s["signatures"]
                           for v in ([sig["data_sdk"]] if isinstance(sig["data_sdk"], str)
                                     else (sig["data_sdk"] or []))})
    return {
        "version": REPORT_VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rules_files": rules.files,
        "known": {
            "seed_hosts": sorted(rules.seed_hosts),
            "block_hosts": sorted({h for h, _ in rules.block}),
            "mute_needles": sorted({n for n, _ in rules.mute}),
            "inline_needles": sorted({n for _, _, n, _ in rules.inline}),
        },
        "drift": bool(drift_items),
        "summary": {
            "pages": len(sites),
            "fetched_ok": sum(1 for s in sites if s["fetch"]["ok"]),
            "fetch_failed": sorted(s["site"] for s in sites if not s["fetch"]["ok"]),
            "analysis_errors": sorted(s["site"] for s in sites if s["analysis_error"]),
            "with_signature": sum(1 for s in sites if s["signatures"]),
            "drift_sites": sorted({i["site"] for i in drift_items}),
            "drift_kinds": sorted({i["kind"] for i in drift_items}),
            "sdk_versions": sdk_versions,
            "drift_fingerprint": fingerprint if drift_items else None,
        },
        "drift_items": drift_items,
        "sites": sites,
    }


def issue_evidence(report):
    """The slice of the report an issue carries: drift items, and the full
    entries of the sites with drift."""
    drift_sites = set(report["summary"]["drift_sites"])
    return {
        "version": report["version"],
        "generated_at": report["generated_at"],
        "summary": report["summary"],
        "drift_items": report["drift_items"],
        "sites": [issue_site(s) for s in report["sites"] if s["site"] in drift_sites],
    }


def _hosts(values):
    return sorted({h for h in (clean_host(v) for v in values or []) if h})


def issue_site(site):
    """A site entry rebuilt from validated fields only: hosts that pass
    clean_host, rule-derived strings, the watcher's own marker names, and
    numbers. No src, id, URL path or other page text reaches the issue, which
    an agent reads and acts on."""
    fetch = site.get("fetch") or {}
    signatures = []
    for sig in site.get("signatures", []):
        sdk = sig.get("data_sdk")
        sdks = [sdk] if isinstance(sdk, str) else list(sdk or [])
        signatures.append({
            "kind": sig.get("kind"),
            "src_host": clean_host(sig.get("src_host")),
            "handlers": [h for h in sig.get("handlers", []) if h in ("onerror", "onload")],
            "data_sdk": [v for v in sdks if SDK_ATTR_RE.match(v or "")],
            "markers": sorted(set(sig.get("markers", [])) & MARKER_NAMES),
            "rule_needles": sig.get("rule_needles", []),
            "hosts": _hosts(sig.get("hosts")),
            "bytes": sig.get("bytes") or sig.get("handler_bytes"),
            "flight_copy": sig.get("flight_copy"),
        })
    error = fetch.get("error")
    return {
        "site": clean_host(site.get("site")),
        "rule_domain": site.get("rule_domain"),
        "fetch": {"ok": bool(fetch.get("ok")), "status": fetch.get("status"),
                  "final_host": url_host(fetch.get("final_url")),
                  "attempts": fetch.get("attempts"), "bytes": fetch.get("bytes"),
                  "challenge": bool(fetch.get("challenge")),
                  "error": error.split(":", 1)[0] if isinstance(error, str) else None},
        "analysis_error": site.get("analysis_error"),
        "signatures": signatures,
        "unknown_hosts": _hosts(site.get("unknown_hosts")),
        "other_handler_hosts": _hosts(o.get("src_host") for o in site.get("other_handler_scripts", [])),
        "rule_needles_absent": site.get("rule_needles_absent", []),
        "drift": site.get("drift", []),
    }


def code_fence(text):
    """A backtick fence longer than any backtick run inside text."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def human_summary(report):
    s = report["summary"]
    lines = [f"Checked {s['pages']} pages: {s['fetched_ok']} fetched, "
             f"{s['with_signature']} with an Ad Shield signature, "
             f"{len(s['fetch_failed'])} fetch failures (not drift on their own)."]
    if s["sdk_versions"]:
        lines.append("")
        lines.append(f"Ad Shield SDK versions seen: {', '.join(s['sdk_versions'])}.")
    if not report["drift"]:
        lines.append("")
        lines.append("No drift.")
        return "\n".join(lines)
    by_kind = {}
    for item in report["drift_items"]:
        by_kind.setdefault(item["kind"], []).append(item)
    lines.append("")
    lines.append(f"Drift on {len(s['drift_sites'])} pages (fingerprint {s['drift_fingerprint']}; "
                 "the same fingerprint as an earlier report means nothing changed):")
    lines.append("")
    for kind in sorted(by_kind):
        items = by_kind[kind]
        details = sorted({i["detail"] for i in items})
        sites = sorted({i["site"] for i in items})
        shown = ", ".join(sites[:8]) + (f" and {len(sites) - 8} more" if len(sites) > 8 else "")
        lines.append(f"- `{kind}` on {shown}: {'; '.join(details[:3])}"
                     + (f" (+{len(details) - 3} more)" if len(details) > 3 else ""))
    if s["fetch_failed"]:
        lines.append("")
        lines.append(f"Fetch failures: {', '.join(s['fetch_failed'])}.")
    return "\n".join(lines)


def issue_body(report, run_url=None):
    head = [ISSUE_MARKER, f"## Ad Shield drift check, {report['generated_at'][:10]}", "",
            human_summary(report), ""]
    if run_url:
        head += [f"Run (full report artifact): {run_url}", ""]
    head += ["Drift definitions and the hotfix flow: README.md, \"Ad Shield drift\". "
             "Fixes go to tools/lists/hotfix-ads.txt through a reviewed PR.", "",
             "Evidence (drift items and the full entries of the pages with drift):", ""]
    evidence = issue_evidence(report)
    blob = json.dumps(evidence, indent=1, sort_keys=True)
    budget = ISSUE_BODY_LIMIT - len("\n".join(head)) - 200
    if len(blob) > budget:
        evidence["sites"] = [{k: v for k, v in s.items() if k != "other_handler_hosts"}
                             for s in evidence["sites"]]
        for site in evidence["sites"]:
            for sig in site["signatures"]:
                sig["hosts"] = sig["hosts"][:20]
        blob = json.dumps(evidence, indent=1, sort_keys=True)
    if len(blob) > budget:
        evidence.pop("sites")
        evidence["truncated"] = "site entries dropped to fit; see the run artifact"
        blob = json.dumps(evidence, indent=1, sort_keys=True)
    fence = code_fence(blob)
    return "\n".join(head + [fence + "json", blob, fence, ""])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", help="write the JSON report here (default: stdout)")
    parser.add_argument("--issue-body", help="also write a Markdown issue body here")
    parser.add_argument("--run-url", default=os.environ.get("RUN_URL"),
                        help="link to the workflow run, for the issue body")
    parser.add_argument("--lists-dir", default=LISTS_DIR)
    parser.add_argument("--fixtures", help="read <host>.html from DIR instead of fetching")
    parser.add_argument("--only", help="comma-separated rule domains or page hosts")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=25)
    args = parser.parse_args(argv)

    rules = Rules.from_dir(args.lists_dir)
    fetcher = fixture_fetch(args.fixtures) if args.fixtures else fetch
    report = run(rules, fetcher, only=(args.only or "").split(",") if args.only else None,
                 workers=args.workers, timeout=args.timeout)
    blob = json.dumps(report, indent=1, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    else:
        print(blob)
    if args.issue_body:
        with open(args.issue_body, "w", encoding="utf-8") as f:
            f.write(issue_body(report, args.run_url))
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"drift={'true' if report['drift'] else 'false'}\n")
    print(human_summary(report), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
