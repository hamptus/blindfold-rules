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
swift tools/validate_rules.swift v1/*.json   # macOS — uses WKContentRuleListStore
```

## Credits

Upstream filter lists are maintained by the [EasyList](https://easylist.to)
authors and contributors and licensed under
[GPL-3.0 / CC BY-SA 3.0](https://easylist.to/pages/licence.html). Thank you —
this entire category of software stands on their work.
