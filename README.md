# Blindfold Rules

The over-the-air rule lists for [Blindfold](https://github.com/hamptus), the
ad, tracker, and annoyance blocker for Safari. The app fetches these files
directly — there is no proprietary backend, and anyone can inspect exactly
what Blindfold blocks. That transparency is the point.

## Lists

| File | Feeds | Built from |
| --- | --- | --- |
| `v1/ads.json` | Ads blocker | [EasyList](https://easylist.to) + Blindfold curated rules |
| `v1/privacy.json` | Privacy blocker | [EasyPrivacy](https://easylist.to) + curated rules |
| `v1/annoyances.json` | Annoyances blocker | [Fanboy's Annoyance](https://easylist.to) (incl. EasyList Cookie + Fanboy Social) + curated rules |

Each file is a Safari content-blocker JSON array, capped under Safari's
150,000-rules-per-blocker limit, and compiled/verified with WebKit's own rule
compiler before publishing. The app re-validates every download on device
before storing it.

## How they're built

A GitHub Action rebuilds the lists daily from the upstream sources using
`tools/build_lists.py` (conversion logic in `tools/abp2safari.py`) and
publishes only if WebKit's compiler accepts the output:

```sh
python3 tools/build_lists.py --dist v1
swift tools/validate_rules.swift v1/*.json   # macOS, uses WKContentRuleListStore
```

`tools/` is a copy of the converter in the Blindfold app repo, so the published lists and the lists bundled in the app come from the same code. `tools/SOURCE` records the commit it was copied from, and the workflow refuses to build when the files no longer match `tools/SOURCE.sha256`. Never edit the synced files here; change them in the app repo and sync. This repo owns, and a sync must leave alone: `tools/lists/hotfix-ads.txt`, `tools/adshield_watch.py`, `tools/test_adshield_watch.py` and `tools/fixtures/adshield/`.

The build also runs on pull requests that change `tools/lists/**` (build and WebKit validation only, nothing is published) and on pushes to `main` that change them (a full publish, as the daily run does).

## Ad Shield drift

Ad Shield, the anti-adblock vendor behind `html-load.com` and `error-report.com`, runs on Yahoo and on about 34 Future plc sites. Blindfold stops it with hand-written rules in `tools/lists/blindfold-ads.txt`, which key on how the loader is delivered today. When the vendor rotates hosts or changes technique, those rules stop matching without any error.

The `Ad Shield drift watch` workflow (`.github/workflows/adshield-watch.yml`) runs daily at 06:30 UTC. `tools/adshield_watch.py` (standard library only) takes the watched sites and the known hosts and needles from the rules files, fetches each page with a desktop Safari user agent, and reads the Ad Shield signatures from the raw HTML: third-party loader tags with `onerror`/`onload` handlers, inline loader scripts, and the hosts their code names. The report flags drift when a page's signature vanished, a loader host is not blocked or its fallback handler not muted, an inline rule's needle no longer matches the inline loader, the loader code names a host the rules files never mention, or a page redirects to a domain no rule names. The module docstring has the exact definitions. A failed fetch is reported but is not drift.

On drift the workflow opens one issue labeled `adshield-drift` (later drift days comment on it) with a summary and the JSON evidence. On a clean day it comments "No drift today" on an open issue and never closes it. The full report is kept as a run artifact for 30 days.

```sh
python3 tools/adshield_watch.py --out report.json --issue-body issue.md
python3 -m unittest discover -s tools -p 'test_adshield_watch.py'
```

### Hotfix flow

1. Drift issue opens. Work out the change (a new host to block or mute, a new needle) and verify it.
2. Add the rule to `tools/lists/hotfix-ads.txt` in a pull request. The build workflow checks that it converts and that WebKit compiles the result. `tools/build_lists.py` merges this file into the Ads list after `blindfold-ads.txt`, and fails the build if the converter skips any rule. To acknowledge a host that needs no rule (for example a first-party CDN the inline rules already stop), name it in a comment in that file.
3. Merging to `main` publishes the new `v1/` lists right away.
4. Back-port the rule into `blindfold-ads.txt` in the app repo, sync `tools/` here, and remove it from `hotfix-ads.txt`.

## Credits

Upstream filter lists are maintained by the [EasyList](https://easylist.to)
authors and contributors and licensed under
[GPL-3.0 / CC BY-SA 3.0](https://easylist.to/pages/licence.html). Thank you —
this entire category of software stands on their work.
