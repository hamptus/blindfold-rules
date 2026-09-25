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

# ABP type -> Safari types. Safari's legacy `raw` type is fetch + websocket +
# ping + other at once, so `*$ping,third-party` (EasyPrivacy: third-party
# beacons) mapped to raw blocked every cross-site fetch and XHR on every
# page, which broke sign-in flows such as Apple's (idmsa.apple.com fetching
# its SRP worker from appleid.cdn-apple.com). Each ABP type now gets only
# the Safari types it means. WebKit files navigator.sendBeacon under
# `other` and <a ping> under `ping`, so ABP's `ping` needs both (verified
# against WKContentRuleList on WebKit 26).
RESOURCE_TYPE_MAP = {
    "script": ("script",),
    "image": ("image",),
    "stylesheet": ("style-sheet",),
    "font": ("font",),
    "media": ("media",),
    "object": ("other",),
    "xmlhttprequest": ("fetch",),
    "websocket": ("websocket",),
    "ping": ("ping", "other"),
    "other": ("other",),
    "popup": ("popup",),
    "subdocument": ("document",),
}
# ABP's implicit type set for a negated-type rule. Excludes `document`: in
# Safari that also matches top-level pages, so a `$~script` rule would block
# navigating to the site itself.
ALL_TYPES = sorted({t for types in RESOURCE_TYPE_MAP.values() for t in types} - {"popup", "document"})
# First token of a `$` tail that looks like an option list. A tail that starts
# like this but fails the option grammar ($csp=... 'self', $removeparam=/re/)
# is an option we cannot parse, not part of the URL pattern.
OPTION_HEAD = re.compile(r"^~?[a-z][a-z0-9_-]*(?:=|,|$)")

# Options that change behavior in ways Safari can't express: dropping the
# OPTION would change semantics, so the whole rule is skipped.
UNSUPPORTED_OPTIONS = (
    "redirect", "redirect-rule", "csp", "removeparam", "replace", "rewrite",
    "important", "badfilter", "header", "permissions", "cname", "denyallow",
    "to", "method", "strict1p", "strict3p", "all", "inline-script", "inline-font",
)

# Extended-CSS / scriptlet separators Safari has no equivalent for. The
# declarative output skips them, but convert() also returns them in a
# `runtime` collector so the helper extension can apply them in-page.
EXTENDED_MARKERS = ("#?#", "#$#", "#%#", "##^", "#@#^")
EXTENDED_SELECTOR = re.compile(
    r":(?:-abp-|contains|has-text|upward|xpath|style|remove|matches-css|matches-attr"
    r"|matches-prop|min-text-length|watch-attr|nth-ancestor|matches-path|others)"
)

# Procedural operators the helper's runtime engine cannot evaluate.
UNSUPPORTED_PROCEDURAL = re.compile(
    r":(?:xpath|style|matches-css|matches-css-before|matches-css-after|matches-attr"
    r"|matches-prop|min-text-length|watch-attr|matches-path|others|matches-media"
    r"|remove-attr|remove-class|shadow|-abp-properties)\("
)

# Operators only cosmetic.js can evaluate. A canonicalized selector without
# any of them is plain CSS (`:has()` included) and belongs in the declarative
# list: cosmetic.js's parseProcedural returns null for it, which silently
# dropped about 1,400 rules.
RUNTIME_OPERATOR = re.compile(r":(?:has-text|upward|remove)\(")
RUNTIME_TOP_OPS = ("has-text", "upward", "remove", "not", "has")

# Scriptlets the helper's MAIN-world library implements (canonical names).
SUPPORTED_SCRIPTLETS = {
    "set-constant", "abort-on-property-read", "abort-on-property-write",
    "no-setTimeout-if", "noeval-if",
    "set-cookie", "set-cookie-reload",
    "set-local-storage-item", "set-session-storage-item",
    "addEventListener-defuser", "adjust-setInterval", "adjust-setTimeout",
}
SCRIPTLET_ALIASES = {
    "set": "set-constant",
    "aopr": "abort-on-property-read",
    "aopw": "abort-on-property-write",
    "nostif": "no-setTimeout-if",
    "no-setTimeout-if": "no-setTimeout-if",
    "setTimeout-defuser": "no-setTimeout-if",
    "noeval-if": "noeval-if",
    "prevent-eval-if": "noeval-if",
    "prevent-setTimeout": "no-setTimeout-if",
    "aeld": "addEventListener-defuser",
    "prevent-addEventListener": "addEventListener-defuser",
    "nano-sib": "adjust-setInterval",
    "nano-setInterval-booster": "adjust-setInterval",
    "nano-stb": "adjust-setTimeout",
    "nano-setTimeout-booster": "adjust-setTimeout",
}
ADGUARD_SCRIPTLET = re.compile(r"^//scriptlet\((.*)\)\s*$")

# set-constant values scriptlets.js coerceValue turns into real values. Keep in
# step with it. Anything else would be set as a literal string ("{}" instead of
# an object), and site code calling methods on it throws.
SET_CONSTANT_VALUES = {
    "true", "false", "null", "undefined", "",
    "noopFunc", "trueFunc", "falseFunc", "throwFunc", "noopCallbackFunc",
    "noopPromiseResolve", "noopPromiseReject",
    "emptyArr", "emptyObj", "[]", "{}",
}
NUMERIC_VALUE = re.compile(r"^-?\d+(\.\d+)?$")

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
    # "||" anchors a DOMAIN; a pattern starting with "/" after it is either an
    # AdGuard regex hostname ("||/^….net$/^" — WebKit rejects mid-pattern
    # assertions, one bad rule kills the list) or a nonsensical empty-host
    # path rule. Neither can ever match a real URL — drop both.
    if prefix == DOMAIN_PREFIX and pattern.startswith("/"):
        return None
    if pattern.startswith("/") and "/" in pattern[1:]:
        head = pattern[1:].split("/")[0]
        if any(ch in head for ch in "^$()[]\\?+"):
            return None

    body = escape_regex(pattern)
    # "||host^" should also match when the host ends the URL.
    if prefix == DOMAIN_PREFIX and raw_pattern.endswith("^") and suffix == "":
        body = body[: -len(SEPARATOR)]
        suffix = f"({SEPARATOR}.*)?$"
    return prefix + body + suffix


DOMAIN_OK = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def normalize_domain(domain):
    """Safari if-domain matches exactly; a leading * includes subdomains.
    Rejects wildcard TLDs (google.*) and AdGuard regex domains (/^…$/) —
    neither is expressible, and a regex domain poisons the whole list."""
    domain = domain.lower().strip()
    if not domain or not is_ascii(domain) or not DOMAIN_OK.match(domain):
        return None
    return "*" + domain


def domain_scope(entries, stats):
    """ABP domain list → {"if-domain": [...]} / {"unless-domain": [...]} / {},
    or None when Safari can't express it without widening the rule.

    Safari can't mix if-domain and unless-domain in one trigger. Keeping only
    the positives made `a.com,~forum.a.com##.ad` hide on the forum the authors
    excluded, and when none of the positives converted (`google.*`) the rule
    turned global with just the exclusions. Both cases are skipped now, as is
    an exclusion we can't express (dropping it would widen the rule)."""
    if_domains, unless_domains = [], []
    had_positive = False
    for d in entries:
        d = d.strip()
        if not d:
            continue
        if d.startswith("~"):
            nd = normalize_domain(d[1:])
            if not nd:
                stats.skip("domain-unconvertible")
                return None
            unless_domains.append(nd)
        else:
            had_positive = True
            nd = normalize_domain(d)
            if nd:
                if_domains.append(nd)
    if if_domains and unless_domains:
        stats.skip("domain-mixed")
        return None
    if had_positive and not if_domains:
        stats.skip("domain-unconvertible")
        return None
    if if_domains:
        return {"if-domain": sorted(set(if_domains))}
    if unless_domains:
        return {"unless-domain": sorted(set(unless_domains))}
    return {}


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
        elif OPTION_HEAD.match(tail.lower()):
            stats.skip("option:unparsed")
            return None

    is_exception = pattern.startswith("@@")
    if is_exception:
        pattern = pattern[2:]

    trigger = {}
    action = "ignore-previous-rules" if is_exception else "block"
    bucket = "network_exceptions" if is_exception else "network"
    resource_types = []
    excluded_types = set()
    subdocument = False
    case_sensitive = False

    for opt in options:
        name, _, value = opt.partition("=")
        if name == "third-party" or name == "3p":
            trigger["load-type"] = ["third-party"]
        elif name in ("~third-party", "first-party", "1p"):
            trigger["load-type"] = ["first-party"]
        elif name == "domain":
            scope = domain_scope(value.split("|"), stats)
            if scope is None:
                return None
            trigger.update(scope)
        elif name == "match-case":
            case_sensitive = True
        elif name == "block-cookies":
            action = "block-cookies"
        elif name in ("document", "doc") and is_exception:
            bucket = "document_exceptions"
        elif name in ("elemhide", "ehide", "generichide", "ghide") and is_exception:
            bucket = "css_exceptions"
        elif name == "subdocument":
            subdocument = True
        elif name in RESOURCE_TYPE_MAP:
            resource_types.extend(RESOURCE_TYPE_MAP[name])
        elif name.startswith("~") and name[1:] in RESOURCE_TYPE_MAP:
            # Accumulate: `$~script,~stylesheet` excludes both, not just the
            # last one (the Swift compiler was fixed the same way).
            excluded_types.update(RESOURCE_TYPE_MAP[name[1:]])
        elif name in ("document", "doc") and not is_exception:
            resource_types.append("document")
        else:
            stats.skip(f"option:{name}" if name in UNSUPPORTED_OPTIONS else "option:other")
            return None

    if subdocument and not resource_types and not excluded_types:
        # ABP subdocument = iframes. Safari's `document` also covers top-level
        # pages, so pin it to child frames instead of dropping the rule.
        resource_types = ["document"]
        trigger["load-context"] = ["child-frame"]
    elif subdocument:
        unscoped = trigger.get("load-type") != ["third-party"] and "if-domain" not in trigger
        if unscoped:
            # `$script,subdocument`: load-context would pin the script part
            # to frames too, and `document` alone would block top pages.
            # Keep the other types rather than losing the whole rule.
            stats.skip("subdocument-part")
        else:
            resource_types.append("document")
    if not resource_types and excluded_types:
        resource_types = [t for t in ALL_TYPES if t not in excluded_types]
        if not resource_types:
            stats.skip("types-empty")
            return None
    elif excluded_types:
        resource_types = [t for t in resource_types if t not in excluded_types]

    # A `document` type without the child-frame pin also covers top pages.
    # Unscoped, that would block whole sites, so only keep it constrained.
    if "document" in resource_types and not is_exception and "load-context" not in trigger:
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
            uf = url_filter_for(pattern) if pattern not in ("", "*", "|", "||") else ".*"
            if not uf:
                stats.skip("pattern")
                return None
            rule_trigger = {"url-filter": uf}
            # Keep the $domain= limit. Dropping it turned EasyList's
            # `@@$generichide,domain=a.com|b.com` into an unconditioned `.*`
            # ignore-previous-rules that cancelled every earlier rule on every
            # site (all Ads element hiding, 2026-09-22).
            for key in ("if-domain", "unless-domain"):
                if key in trigger:
                    rule_trigger[key] = trigger[key]
            # An unless-domain-only `.*` exception still cancels on almost
            # every site, so it counts as global too.
            if uf == ".*" and "if-domain" not in rule_trigger:
                stats.skip("exception-global")
                return None
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


def runtime_domains(domains):
    """Positive, concrete hosts a runtime rule applies to ([] when generic)."""
    hosts = []
    for d in domains.split(","):
        d = d.strip().lower()
        if not d or d.startswith("~") or not is_ascii(d) or not DOMAIN_OK.match(d):
            continue
        hosts.append(d)
    return hosts


def canonicalize_procedural(selector):
    """Folds operator synonyms onto the small set the JS engine parses."""
    return (selector
            .replace(":-abp-has(", ":has(")
            .replace(":-abp-contains(", ":has-text(")
            .replace(":contains(", ":has-text(")
            .replace(":nth-ancestor(", ":upward("))


def normalize_scriptlet_name(name):
    name = name.strip()
    if name.endswith(".js"):
        name = name[:-3]
    for prefix in ("ubo-", "abp-"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return SCRIPTLET_ALIASES.get(name, name)


def parse_scriptlet_args(body):
    """Comma-separated scriptlet args; AdGuard quotes them, uBO doesn't.
    Commas inside quoted strings (JSON values etc.) are not separators."""
    parts, current, in_quote = [], [], None
    for ch in body:
        if in_quote:
            current.append(ch)
            if ch == in_quote:
                in_quote = None
        elif ch in ("'", '"'):
            in_quote = ch
            current.append(ch)
        elif ch == ",":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    parts.append("".join(current).strip())
    return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in "'\"" else p
            for p in parts]


def balanced_arg(text, start):
    """Contents of the paren group opened just before `start`, or None."""
    depth = 1
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start:i]
    return None


def has_nested_has(selector):
    """`:has()` inside a `:has()` argument is invalid CSS; WebKit drops the
    whole merged rule without reporting an error."""
    i = selector.find(":has(")
    while i >= 0:
        arg = balanced_arg(selector, i + 5)
        if arg is None or ":has(" in arg:
            return True
        i = selector.find(":has(", i + 5 + len(arg))
    return False


def selector_ok(selector):
    return bool(
        selector
        and is_ascii(selector)
        and not EXTENDED_SELECTOR.search(selector)
        and "+js(" not in selector
        and "{" not in selector
        and "}" not in selector
        and not has_nested_has(selector)
    )


def first_procedural_index(selector):
    """Mirror of cosmetic.js firstProceduralIndex."""
    depth = 0
    for i, ch in enumerate(selector):
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            depth -= 1
            continue
        if ch != ":" or depth != 0:
            continue
        rest = selector[i + 1:]
        if rest.startswith(("has-text(", "upward(", "remove(")):
            return i
        if rest.startswith(("has(", "not(")):
            arg = balanced_arg(selector, i + rest.index("(") + 2)
            if arg is not None and RUNTIME_OPERATOR.search(arg):
                return i
    return -1


def procedural_shape_ok(selector):
    """True when cosmetic.js parseProcedural can evaluate `selector`: a CSS
    prefix followed only by chained operators. Trailing CSS after an operator
    (`p:has-text(x) + form`) makes it return null, so those rules were dead."""
    selector = selector.strip()
    start = first_procedural_index(selector)
    if start < 0:
        return False
    i = start
    while i < len(selector):
        if selector[i] != ":":
            return False
        open_at = selector.find("(", i)
        if open_at < 0:
            return False
        name = selector[i + 1:open_at]
        arg = balanced_arg(selector, open_at + 1)
        if arg is None or name not in RUNTIME_TOP_OPS:
            return False
        if name == "not" and not re.fullmatch(r"\s*:has-text\(.*\)\s*", arg):
            return False
        if name == "has" and RUNTIME_OPERATOR.search(arg) and not procedural_shape_ok(arg):
            return False
        i = open_at + 1 + len(arg) + 1
    return True


def split_cosmetic_domains(domains, stats):
    """(if_domains, unless_domains), or None when the scope can't be expressed."""
    scope = domain_scope(domains.split(","), stats)
    if scope is None:
        return None
    return scope.get("if-domain", []), scope.get("unless-domain", [])


def convert(lines, stats=None):
    """Converts ABP filter lines → (rule buckets, stats, runtime rules).

    `runtime` carries what the declarative output can't express but the helper
    web extension can apply in-page: procedural cosmetic selectors (raw
    strings, parsed client-side by cosmetic.js) and scriptlet invocations.
    """
    stats = stats or Stats()
    buckets = {
        "css": [],
        "css_exceptions": [],
        "network": [],
        "network_exceptions": [],
        "document_exceptions": [],
    }
    runtime = {"procedural": [], "scriptlets": []}

    def collect_scriptlet(domains, body):
        args = parse_scriptlet_args(body)
        if not args or not args[0]:
            stats.skip("scriptlet-empty")
            return
        name = normalize_scriptlet_name(args[0])
        if name not in SUPPORTED_SCRIPTLETS:
            stats.skip("scriptlet-unsupported")
            return
        if name == "set-constant":
            value = args[2] if len(args) > 2 else ""
            if value not in SET_CONSTANT_VALUES and not NUMERIC_VALUE.match(value):
                stats.skip("scriptlet-value")
                return
        hosts = runtime_domains(domains)
        if not hosts:
            stats.skip("scriptlet-generic")
            return
        for host in hosts:
            runtime["scriptlets"].append((host, name, args[1:]))
        stats.keep("runtime-scriptlet")

    # selector → set of unless-domains collected from #@# exception lines,
    # applied to GENERIC (domain-free) cosmetic rules afterwards.
    unhide = defaultdict(set)
    # (if_domains, unless_domains) → [selectors] for merge.
    cosmetic = defaultdict(list)

    def add_cosmetic(domains, selector):
        if not selector_ok(selector):
            stats.skip("selector")
            return
        scope = split_cosmetic_domains(domains, stats)
        if scope is None:
            return
        if_domains, unless_domains = scope
        cosmetic[(tuple(sorted(if_domains)), tuple(sorted(unless_domains)))].append(selector)
        stats.keep("css")

    def collect_procedural(domains, selector):
        selector = canonicalize_procedural(selector)
        if UNSUPPORTED_PROCEDURAL.search(selector):
            stats.skip("procedural-unsupported")
            return
        hosts = runtime_domains(domains)
        if not hosts:
            stats.skip("procedural-generic")
            return
        if not RUNTIME_OPERATOR.search(selector):
            # Plain CSS once canonicalized (`:-abp-has(` → `:has(`): Safari
            # evaluates it natively. Only site-scoped ones, as before; a
            # generic `:has()` on every page is too costly to risk.
            add_cosmetic(domains, selector)
            return
        if not procedural_shape_ok(selector):
            stats.skip("procedural-shape")
            return
        for host in hosts:
            runtime["procedural"].append((host, selector))
        stats.keep("runtime-procedural")

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        if "#?#" in line:
            domains, _, selector = line.partition("#?#")
            selector = selector.strip()
            if selector:
                collect_procedural(domains, selector)
            continue
        if "#%#" in line:
            domains, _, payload = line.partition("#%#")
            m = ADGUARD_SCRIPTLET.match(payload.strip())
            if m:
                collect_scriptlet(domains, m.group(1))
            else:
                stats.skip("inline-js")
            continue
        if "#$#" in line or "##^" in line:
            stats.skip("extended-css")
            continue

        if "#@#" in line:
            domains, _, selector = line.partition("#@#")
            selector = selector.strip()
            # Scriptlet exceptions aren't selectors; we have no suppression
            # mechanism, but they must not pollute the unhide table.
            if selector_ok(selector) and not selector.startswith("+js("):
                for d in domains.split(","):
                    nd = normalize_domain(d.strip().lstrip("~"))
                    if nd:
                        unhide[selector].add(nd)
            stats.keep("unhide")
            continue

        if "##" in line:
            domains, _, selector = line.partition("##")
            selector = selector.strip()
            if selector.startswith("+js("):
                body = selector[4:-1] if selector.endswith(")") else selector[4:]
                collect_scriptlet(domains, body)
                continue
            if EXTENDED_SELECTOR.search(selector):
                collect_procedural(domains, selector)
                continue
            add_cosmetic(domains, selector)
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

    return buckets, stats, runtime


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
        # Trim from the end of the network block ONLY — exceptions must
        # survive (or sites the list authors deliberately whitelisted would
        # break), and cosmetics must never be silently eaten by an oversized
        # overflow (negative-slice corruption).
        overflow = len(ordered) - max_rules
        net_len = len(dedupe(buckets["network"]))
        css_len = len(dedupe(buckets["css"])) + len(dedupe(buckets["css_exceptions"]))
        trim = min(overflow, net_len)
        net_end = css_len + net_len
        ordered = ordered[: net_end - trim] + ordered[net_end:]
        if trim < overflow:
            print(f"  WARNING: still {len(ordered):,} rules after trimming the "
                  f"entire network block (cap {max_rules:,})")
    return ordered
