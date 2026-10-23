#!/usr/bin/env python3
"""Tests for adshield_watch.py, offline, against saved HTML fixtures.

Run: python3 -m unittest discover -s tools -p 'test_adshield_watch.py'

The fixtures in tools/fixtures/adshield are the Ad Shield script tags cut from
the live pages on 2026-10-23 (long obfuscated string bodies shortened):
techradar.com (static html-load.com loader tag with onload/onerror),
finance.yahoo.com (inline loader script), www.yahoo.com (the same loader as a
Next.js JSON-escaped script) and wallpaper.com (a Future plc site that had no
Ad Shield that day).
"""

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
import adshield_watch as aw  # noqa: E402

FIXTURES = os.path.join(TOOLS, "fixtures", "adshield")

# A trimmed copy of the Ad Shield section of blindfold-ads.txt, so these tests
# do not move when the real list gains sites.
RULES_TEXT = """\
! --- Ad Shield (html-load.com, error-report.com) ---
! Blocking html-load.com sends the tag's onerror to rotating fallback hosts
! (vein.oofadvanced.com and others), so that handler is muted too.
yahoo.com,techradar.com,wallpaper.com#%#//scriptlet('abort-current-inline-script', 'document.createElement', '/html-load\\.com|error-report\\.com|if\\(await eval/')
yahoo.com#%#//scriptlet('prevent-innerHTML', 'script', 'error-report')
||html-load.com^$domain=techradar.com|wallpaper.com
techradar.com,wallpaper.com#%#//scriptlet('mute-script-events', 'html-load.com')

! --- Yahoo ---
www.yahoo.com##div:has(> div > [id^="top_center-"])
"""


def rules(extra_hotfix=None):
    files = [("blindfold-ads.txt", RULES_TEXT.splitlines())]
    if extra_hotfix is not None:
        files.append(("hotfix-ads.txt", extra_hotfix.splitlines()))
    return aw.Rules(files)


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def kinds(result):
    return sorted({d["kind"] for d in result["drift"]})


class RulesParsing(unittest.TestCase):
    def test_trimmed_rules(self):
        r = rules()
        self.assertEqual(r.seed_hosts, {"html-load.com", "error-report.com"})
        self.assertEqual(r.block_hosts("www.techradar.com"), {"html-load.com"})
        self.assertEqual(r.block_hosts("www.yahoo.com"), set())
        self.assertEqual(r.mute_needles("www.techradar.com"), ["html-load.com"])
        self.assertEqual(len(r.inline_rules("news.yahoo.com")), 2)
        self.assertTrue(r.is_known("vein.oofadvanced.com"))   # named in a comment
        self.assertTrue(r.is_known("other.oofadvanced.com"))  # same registrable domain
        self.assertFalse(r.is_known("s.yimg.com"))
        pages = [u for _, u in r.watch_list()]
        self.assertIn("https://www.techradar.com/", pages)
        self.assertIn("https://finance.yahoo.com/", pages)
        self.assertIn("https://sports.yahoo.com/", pages)

    def test_real_rules_files_watch_yahoo_and_future_plc(self):
        r = aw.Rules.from_dir(aw.LISTS_DIR)
        pages = dict((u, d) for d, u in r.watch_list())
        for url in ("https://www.yahoo.com/", "https://news.yahoo.com/",
                    "https://finance.yahoo.com/", "https://sports.yahoo.com/",
                    "https://www.techradar.com/", "https://www.tomsguide.com/"):
            self.assertIn(url, pages)
        self.assertGreaterEqual(len(pages), 30)
        self.assertIn("html-load.com", r.block_hosts("www.tomsguide.com"))
        self.assertIn("html-load.com", r.mute_needles("www.tomsguide.com"))
        self.assertTrue(r.is_known("report.error-report.com"))
        # Hosts outside the Ad Shield rules are not watched.
        self.assertNotIn("https://www.reuters.com/", pages)


class Signatures(unittest.TestCase):
    def test_future_plc_loader_tag_no_drift(self):
        result = aw.analyze_page("techradar.com", "https://www.techradar.com/",
                                 fixture("techradar.com.html"), rules())
        tags = [s for s in result["signatures"] if s["kind"] == "loader_tag"]
        self.assertEqual(len(tags), 1, result["signatures"])
        tag = tags[0]
        self.assertEqual(tag["src_host"], "html-load.com")
        self.assertEqual(tag["data_sdk"], "l/1.2.22")
        self.assertEqual(tag["handlers"], ["onerror", "onload"])
        self.assertIn("permutation-decoder", tag["markers"])
        self.assertEqual(result["drift"], [])
        # The plain gtag script carries no handler and is not a signature.
        self.assertEqual(result["other_handler_scripts"], [])

    def test_yahoo_inline_loader_both_forms(self):
        for name, url in (("finance.yahoo.com.html", "https://finance.yahoo.com/"),
                          ("www.yahoo.com.html", "https://www.yahoo.com/")):
            with self.subTest(name):
                result = aw.analyze_page("yahoo.com", url, fixture(name), rules())
                inline = [s for s in result["signatures"] if s["kind"] == "inline_script"]
                self.assertEqual(len(inline), 1, result["signatures"])
                sig = inline[0]
                self.assertIn("error-report.com", sig["rule_needles"])
                self.assertIn("benji-adshield-global", sig["markers"])
                self.assertIn("y-l/1.0.1", sig["data_sdk"])
                self.assertIn("report.error-report.com", sig["hosts"])
                # Bait hosts the detector probes are not drift; the loader's
                # first-party CDN host is new to the rules.
                self.assertEqual(result["unknown_hosts"], ["s.yimg.com"])
                self.assertEqual(kinds(result), ["unknown_host"])
                self.assertIn("if\\(await eval", result["rule_needles_absent"])

    def test_acknowledged_host_in_hotfix_comment_is_not_drift(self):
        r = rules("! Ad Shield loader CDN on Yahoo, stopped by the inline rules: s.yimg.com\n")
        result = aw.analyze_page("yahoo.com", "https://finance.yahoo.com/",
                                 fixture("finance.yahoo.com.html"), r)
        self.assertEqual(result["drift"], [])

    def test_flight_copy_is_skipped_when_primary_exists(self):
        page = fixture("finance.yahoo.com.html")
        copy = '<script>self.__next_f.push([1,"x https://evil-copy.example.net/ error-report.com"])</script>'
        result = aw.analyze_page("yahoo.com", "https://finance.yahoo.com/",
                                 page.replace("</head>", copy + "</head>"), rules())
        self.assertNotIn("evil-copy.example.net", result["unknown_hosts"])


class SyntheticDrift(unittest.TestCase):
    def test_new_fallback_and_loader_host(self):
        page = fixture("techradar.com.html")
        page = page.replace("https://html-load.com/themeBundle/", "https://cdn.fresh-loader.net/themeBundle/")
        page = page.replace('onerror="', 'onerror="fetch(&quot;https://vein2.newfallback.xyz/x.js&quot;);', 1)
        result = aw.analyze_page("techradar.com", "https://www.techradar.com/", page, rules())
        self.assertEqual(result["unknown_hosts"], ["cdn.fresh-loader.net", "vein2.newfallback.xyz"])
        self.assertIn("loader_not_blocked", kinds(result))
        self.assertIn("fallback_not_muted", kinds(result))
        self.assertIn("unknown_host", kinds(result))

    def test_signature_removed(self):
        page = re.sub(r"<script async=\"\" id=\"DUrYulQrRTJOTA\".*?</script>", "",
                      fixture("techradar.com.html"), flags=re.S)
        self.assertNotIn("html-load.com", page)
        result = aw.analyze_page("techradar.com", "https://www.techradar.com/", page, rules())
        self.assertEqual(kinds(result), ["signature_vanished"])

    def test_site_without_ad_shield(self):
        result = aw.analyze_page("wallpaper.com", "https://www.wallpaper.com/",
                                 fixture("wallpaper.com.html"), rules())
        self.assertEqual(kinds(result), ["signature_vanished"])

    def test_inline_loader_drops_the_rule_needles(self):
        page = fixture("finance.yahoo.com.html").replace("error-report.com", "err-collect.net")
        result = aw.analyze_page("yahoo.com", "https://finance.yahoo.com/", page, rules())
        self.assertEqual(len(result["signatures"]), 1)  # still found by vendor markers
        missing = [d for d in result["drift"] if d["kind"] == "inline_needle_missing"]
        self.assertEqual(len(missing), 2, result["drift"])
        self.assertIn("report.err-collect.net", result["unknown_hosts"])

    def test_inline_loader_on_site_without_inline_rule(self):
        r = aw.Rules([("blindfold-ads.txt", [
            "! --- Ad Shield (html-load.com) ---",
            "||html-load.com^$domain=example-future.com",
        ])])
        page = fixture("finance.yahoo.com.html")
        result = aw.analyze_page("example-future.com", "https://www.example-future.com/", page, r)
        self.assertIn("inline_loader_unhandled", kinds(result))

    def test_redirect_off_the_rules(self):
        result = aw.analyze_page("techradar.com", "https://www.techradar.com/",
                                 fixture("techradar.com.html"), rules(),
                                 final_url="https://www.techradar-global.com/")
        self.assertIn("final_host_not_covered", kinds(result))


class Report(unittest.TestCase):
    def fake_fetcher(self, pages):
        def fetch(url, **_):
            host = aw.urllib.parse.urlparse(url).hostname
            if host not in pages:
                return ({"ok": False, "status": 403, "final_url": None, "bytes": 0,
                         "attempts": 3, "error": "HTTP 403", "challenge": False}, None)
            return ({"ok": True, "status": 200, "final_url": url, "bytes": len(pages[host]),
                     "attempts": 1, "error": None, "challenge": False}, pages[host])
        return fetch

    def test_fetch_failures_are_not_drift(self):
        fetcher = self.fake_fetcher({"www.techradar.com": fixture("techradar.com.html")})
        report = aw.run(rules(), fetcher, only=["techradar.com", "yahoo.com"], workers=2)
        self.assertFalse(report["drift"], report["drift_items"])
        self.assertEqual(len(report["summary"]["fetch_failed"]), 4)
        self.assertEqual(report["summary"]["with_signature"], 1)

    def test_drift_report_and_issue_body(self):
        fetcher = self.fake_fetcher({
            "www.techradar.com": fixture("techradar.com.html"),
            "www.wallpaper.com": fixture("wallpaper.com.html"),
            "finance.yahoo.com": fixture("finance.yahoo.com.html"),
        })
        report = aw.run(rules(), fetcher, workers=2)
        self.assertTrue(report["drift"])
        self.assertEqual(report["summary"]["drift_sites"], ["finance.yahoo.com", "www.wallpaper.com"])
        body = aw.issue_body(report, "https://github.com/x/y/actions/runs/1")
        self.assertTrue(body.startswith(aw.ISSUE_MARKER))
        self.assertLess(len(body), aw.ISSUE_BODY_LIMIT)
        evidence = json.loads(body.split("```json\n", 1)[1].rsplit("\n```", 1)[0])
        self.assertEqual({s["site"] for s in evidence["sites"]}, {"finance.yahoo.com", "www.wallpaper.com"})
        self.assertIn("unknown_host", body)
        self.assertNotIn(chr(0x2014), body)  # no em dashes in what people read

    def test_fetch_detects_challenge_page(self):
        class Response(io.BytesIO):
            status = 200
            headers = {}
            def geturl(self):
                return "https://www.techradar.com/"
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
        saved = aw.urllib.request.urlopen
        aw.urllib.request.urlopen = lambda *a, **k: Response(b"<title>Just a moment...</title>")
        try:
            result, body = aw.fetch("https://www.techradar.com/", attempts=1)
        finally:
            aw.urllib.request.urlopen = saved
        self.assertIsNone(body)
        self.assertFalse(result["ok"])
        self.assertTrue(result["challenge"])

    def test_main_with_fixtures_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            out, issue = os.path.join(d, "r.json"), os.path.join(d, "i.md")
            gh_out = os.path.join(d, "gh")
            os.environ["GITHUB_OUTPUT"] = gh_out
            try:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = aw.main(["--fixtures", FIXTURES, "--only", "techradar.com,yahoo.com",
                                    "--out", out, "--issue-body", issue])
            finally:
                del os.environ["GITHUB_OUTPUT"]
            self.assertEqual(code, 0)
            with open(out) as f:
                report = json.load(f)
            self.assertIn(report["drift"], (True, False))
            with open(gh_out) as f:
                self.assertIn(f"drift={'true' if report['drift'] else 'false'}", f.read())


if __name__ == "__main__":
    unittest.main()
