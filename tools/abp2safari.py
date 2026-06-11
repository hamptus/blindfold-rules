"""AdBlock Plus filter syntax → Safari content-blocker JSON.

Converts the industry-standard lists (EasyList, EasyPrivacy, Fanboy's
Annoyance) into WebKit's declarative format. Mirrors the conversion rules of
BlindfoldKit/FilterCompiler.swift, extended for the full breadth of real
lists, and emits ONLY constructs WebKit's compiler accepts — Safari's regex
dialect has no disjunctions, and one bad rule silently kills an entire list.
Every generated list must still pass tools/validate_rules.swift before
shipping.

Rule ordering follows the standard Safari-converter scheme so exceptions
cancel only what they should:

    1. cosmetic (css-display-none)
    2. elemhide/generichide exceptions   (cancel cosmetic rules only)
    3. network blocks / block-cookies
    4. network exceptions                 (cancel network rules)
    5. document exceptions                (cancel everything for a site)
"""

import json
import re
from collections import defaultdict

SEPARATOR = r"[^a-zA-Z0-9_.%-]"
DOMAIN_PREFIX = r"^[a-z][a-z+.-]*://([^/:]+\.)?"

RESOURCE_TYPE_MAP = {
    "script": "script",
    "image": "image",
    "stylesheet": "style-sheet",
    "font": "font",
    "media": "media",
    "object": "raw",
    "xmlhttprequest": "raw",
    "websocket": "raw",
    "ping": "raw",
    "other": "raw",
    "popup": "popup",
    "subdocument": "document",
}
ALL_TYPES = sorted(set(RESOURCE_TYPE_MAP.values()) - {"popup"})

# Options that change behavior in ways Safari can't express: dropping the
# OPTION would change semantics, so the whole rule is skipped.
UNSUPPORTED_OPTIONS = (
    "redirect", "redirect-rule", "csp", "removeparam", "replace", "rewrite",
    "important", "badfilter", "header", "permissions", "cname", "denyallow",
    "to", "method", "strict1p", "strict3p", "all", "inline-script", "inline-font",
)

# Extended-CSS / scriptlet separators Safari has no equivalent for.
EXTENDED_MARKERS = ("#?#", "#$#", "#%#", "##^", "#@#^")
EXTENDED_SELECTOR = re.compile(
    r":(?:-abp-|contains|upward|xpath|style|remove|matches-css|matches-attr"
    r"|matches-prop|min-text-length|watch-attr|nth-ancestor|matches-path|others)"
)

MAX_SELECTORS_PER_RULE = 100
MAX_SELECTOR_CHARS = 8000


class Stats:
    def __init__(self):
        self.counts = defaultdict(int)

    def skip(self, reason):
        self.counts[f"skip:{reason}"] += 1

    def keep(self, kind):
        self.counts[kind] += 1

    def report(self):
        return dict(sorted(self.counts.items()))


def is_ascii(text):
    try:
        text.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def escape_regex(pattern):
    """ABP pattern body → Safari regex body (* and ^ are ABP wildcards)."""
    body = []
    for ch in pattern:
        if ch == "*":
            body.append(".*")
        elif ch == "^":
            body.append(SEPARATOR)
        elif ch in ".+?()[]{}\\$|/":
            body.append("\\" + ch)
        else:
            body.append(ch)
    return "".join(body)


def url_filter_for(raw_pattern):
    """ABP URL pattern → Safari url-filter regex, or None when unconvertible."""
    pattern = raw_pattern
    if not pattern or not is_ascii(pattern):
        return None
    # Regex literals use full JS regex syntax (disjunctions, lookarounds...)
    # that Safari mostly rejects; the handful in the big lists isn't worth it.
    if len(pattern) > 1 and pattern.startswith("/") and pattern.endswith("/"):
        return None

    prefix = ""
    suffix = ""
    if pattern.startswith("||"):
        pattern = pattern[2:]
        prefix = DOMAIN_PREFIX
    elif pattern.startswith("|"):
        pattern = pattern[1:]
        prefix = "^"
    if pattern.endswith("|"):
        pattern = pattern[:-1]
        suffix = "$"

    if not pattern:
        return None

    body = escape_regex(pattern)
    # "||host^" should also match when the host ends the URL.
    if prefix == DOMAIN_PREFIX and raw_pattern.endswith("^") and suffix == "":
        body = body[: -len(SEPARATOR)]
        suffix = f"({SEPARATOR}.*)?$"
    return prefix + body + suffix


def normalize_domain(domain):
    """Safari if-domain matches exactly; a leading * includes subdomains."""
    domain = domain.lower().strip()
    if not domain or not is_ascii(domain) or "*" in domain:
        return None  # wildcard-TLD entries (google.*) can't be expressed
    return "*" + domain


def parse_network(line, stats):
    """One ABP network line → (bucket, rule) or None."""
    pattern = line
    options = []
    # Split off $options — the rightmost $ followed by option-ish tokens.
    dollar = pattern.rfind("$")
    if dollar > 0:
        tail = pattern[dollar + 1:]
        if tail and re.fullmatch(r"[a-zA-Z0-9,~=|_\-.*:/]+", tail):
            options = tail.lower().split(",")
            pattern = pattern[:dollar]

    is_exception = pattern.startswith("@@")
    if is_exception:
        pattern = pattern[2:]

    trigger = {}
    action = "ignore-previous-rules" if is_exception else "block"
    bucket = "network_exceptions" if is_exception else "network"
    resource_types = []
    case_sensitive = False

    for opt in options:
        name, _, value = opt.partition("=")
        if name == "third-party" or name == "3p":
            trigger["load-type"] = ["third-party"]
        elif name in ("~third-party", "first-party", "1p"):
            trigger["load-type"] = ["first-party"]
        elif name == "domain":
            if_domains, unless_domains = [], []
            for d in value.split("|"):
                if d.startswith("~"):
                    nd = normalize_domain(d[1:])
                    if nd:
                        unless_domains.append(nd)
                else:
                    nd = normalize_domain(d)
                    if nd:
                        if_domains.append(nd)
            # Safari can't mix if-domain and unless-domain; positives dominate.
            if if_domains:
                trigger["if-domain"] = sorted(if_domains)
            elif unless_domains:
                trigger["unless-domain"] = sorted(unless_domains)
            else:
                stats.skip("domain-unconvertible")
                return None
        elif name == "match-case":
            case_sensitive = True
        elif name == "block-cookies":
            action = "block-cookies"
        elif name in ("document", "doc") and is_exception:
            bucket = "document_exceptions"
        elif name in ("elemhide", "ehide", "generichide", "ghide") and is_exception:
            bucket = "css_exceptions"
        elif name in RESOURCE_TYPE_MAP:
            resource_types.append(RESOURCE_TYPE_MAP[name])
        elif name.startswith("~") and name[1:] in RESOURCE_TYPE_MAP:
            excluded = RESOURCE_TYPE_MAP[name[1:]]
            resource_types = [t for t in ALL_TYPES if t != excluded]
        elif name in ("document", "doc") and not is_exception:
            resource_types.append("document")
        else:
            stats.skip(f"option:{name}" if name in UNSUPPORTED_OPTIONS else "option:other")
            return None

    # ABP "subdocument" means iframes, but Safari's "document" also covers top
    # pages. Unscoped, that would block whole sites — only keep it constrained.
    if "document" in resource_types and not is_exception:
        if trigger.get("load-type") != ["third-party"] and "if-domain" not in trigger:
            stats.skip("subdocument-unscoped")
            return None

    if resource_types:
        trigger["resource-type"] = sorted(set(resource_types))

    if bucket in ("document_exceptions", "css_exceptions"):
        # Site-wide pass: express ||host^ as if-domain so it cancels by page.
        m = re.fullmatch(r"\|\|([a-z0-9.-]+)\^?\*?", pattern)
        if m:
            nd = normalize_domain(m.group(1))
            if not nd:
                stats.skip("exception-domain")
                return None
            rule_trigger = {"url-filter": ".*", "if-domain": [nd]}
        else:
            uf = url_filter_for(pattern) if pattern else ".*"
            if not uf:
                stats.skip("pattern")
                return None
            rule_trigger = {"url-filter": uf}
        stats.keep(bucket)
        return bucket, {"trigger": rule_trigger, "action": {"type": "ignore-previous-rules"}}

    url_filter = url_filter_for(pattern)
    if not url_filter:
        stats.skip("pattern")
        return None
    trigger["url-filter"] = url_filter
    if case_sensitive:
        trigger["url-filter-is-case-sensitive"] = True

    stats.keep(bucket)
    return bucket, {"trigger": trigger, "action": {"type": action}}


def selector_ok(selector):
    return (
        selector
        and is_ascii(selector)
        and not EXTENDED_SELECTOR.search(selector)
        and "{" not in selector
        and "}" not in selector
    )


def split_cosmetic_domains(domains):
    if_domains, unless_domains = [], []
    for d in domains.split(","):
        d = d.strip()
        if not d:
            continue
        if d.startswith("~"):
            nd = normalize_domain(d[1:])
            if nd:
                unless_domains.append(nd)
        else:
            nd = normalize_domain(d)
            if nd:
                if_domains.append(nd)
    return if_domains, unless_domains


def convert(lines, stats=None):
    """Converts ABP filter lines → dict of ordered rule buckets."""
    stats = stats or Stats()
    buckets = {
        "css": [],
        "css_exceptions": [],
        "network": [],
        "network_exceptions": [],
        "document_exceptions": [],
    }
    # selector → set of unless-domains collected from #@# exception lines,
    # applied to GENERIC (domain-free) cosmetic rules afterwards.
    unhide = defaultdict(set)
    # (if_domains, unless_domains) → [selectors] for merge.
    cosmetic = defaultdict(list)

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        if any(marker in line for marker in EXTENDED_MARKERS[:4]):
            stats.skip("extended-css")
            continue

        if "#@#" in line:
            domains, _, selector = line.partition("#@#")
            selector = selector.strip()
            if selector_ok(selector):
                for d in domains.split(","):
                    nd = normalize_domain(d.strip().lstrip("~"))
                    if nd:
                        unhide[selector].add(nd)
            stats.keep("unhide")
            continue

        if "##" in line:
            domains, _, selector = line.partition("##")
            selector = selector.strip()
            if not selector_ok(selector):
                stats.skip("selector")
                continue
            if_domains, unless_domains = split_cosmetic_domains(domains)
            if domains and not if_domains and not unless_domains:
                stats.skip("selector-domain")
                continue
            cosmetic[(tuple(sorted(if_domains)), tuple(sorted(unless_domains)))].append(selector)
            stats.keep("css")
            continue

        result = parse_network(line, stats)
        if result:
            bucket, rule = result
            buckets[bucket].append(rule)

    # Emit cosmetic rules, folding unhide exceptions into generic rules and
    # merging selectors that share identical domain scope (rule-count diet:
    # tens of thousands of generic selectors → a few hundred rules).
    for (if_domains, unless_domains), selectors in cosmetic.items():
        groups = defaultdict(list)
        for selector in selectors:
            extra_unless = unhide.get(selector, set()) if not if_domains else set()
            groups[tuple(sorted(set(unless_domains) | extra_unless))].append(selector)
        for unless, sels in groups.items():
            for chunk in chunk_selectors(sorted(set(sels))):
                trigger = {"url-filter": ".*"}
                if if_domains:
                    trigger["if-domain"] = list(if_domains)
                elif unless:
                    trigger["unless-domain"] = list(unless)
                buckets["css"].append({
                    "trigger": trigger,
                    "action": {"type": "css-display-none", "selector": ", ".join(chunk)},
                })

    return buckets, stats


def chunk_selectors(selectors):
    chunk, size = [], 0
    for s in selectors:
        if chunk and (len(chunk) >= MAX_SELECTORS_PER_RULE or size + len(s) > MAX_SELECTOR_CHARS):
            yield chunk
            chunk, size = [], 0
        chunk.append(s)
        size += len(s) + 2
    if chunk:
        yield chunk


def dedupe(rules):
    seen = set()
    out = []
    for rule in rules:
        key = json.dumps(rule, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(rule)
    return out


def assemble(buckets, max_rules=None):
    """Buckets → one ordered, deduplicated Safari rule list."""
    ordered = (
        dedupe(buckets["css"])
        + dedupe(buckets["css_exceptions"])
        + dedupe(buckets["network"])
        + dedupe(buckets["network_exceptions"])
        + dedupe(buckets["document_exceptions"])
    )
    if max_rules and len(ordered) > max_rules:
        # Trim from the middle of the network block — exceptions must survive
        # or sites the list authors deliberately whitelisted would break.
        overflow = len(ordered) - max_rules
        css_len = len(dedupe(buckets["css"])) + len(dedupe(buckets["css_exceptions"]))
        net_end = css_len + len(dedupe(buckets["network"]))
        ordered = ordered[: net_end - overflow] + ordered[net_end:]
    return ordered
