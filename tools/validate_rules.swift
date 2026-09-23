// Validates content-blocker JSON against WebKit's real rule compiler, the
// same compiler Safari uses on iOS. Catches "one bad rule silently kills the
// whole list" before it ships.
//
// Three checks per file:
//   1. The whole list compiles.
//   2. No unscoped `ignore-previous-rules` with a match-everything url-filter.
//      WebKit compiles one happily, and it cancels every earlier rule on every
//      page (all Ads element hiding was off from 2026-06 to 2026-09 this way).
//   3. Every css-display-none rule compiles ON ITS OWN. WebKit drops a rule
//      with an invalid selector without an error and only fails when every
//      rule is gone, so a whole-list compile cannot see dead cosmetic rules.
//
// With --prune, check 3 repairs instead of failing: each dead rule is split
// into its selectors, the ones WebKit rejects are removed, and the file is
// rewritten. Upstream lists regularly carry a few invalid selectors, and one
// of them in a merged rule takes up to 99 good selectors down with it.
//
// Usage: swift tools/validate_rules.swift [--prune] <file1.json> [file2.json ...]

import Foundation
import WebKit

var arguments = Array(CommandLine.arguments.dropFirst())
let prune = arguments.first == "--prune"
if prune { arguments.removeFirst() }
let files = arguments
guard !files.isEmpty else {
    print("usage: swift tools/validate_rules.swift [--prune] <rules.json> ...")
    exit(2)
}

// A scratch store, so thousands of single-rule compiles never touch the
// default store. Removed before exit.
let scratch = FileManager.default.temporaryDirectory
    .appendingPathComponent("validate-rules-\(ProcessInfo.processInfo.processIdentifier)")
try? FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
guard let store = WKContentRuleListStore(url: scratch) else {
    print("cannot create a scratch WKContentRuleListStore")
    exit(2)
}

func compile(_ json: String, id: String) -> Error? {
    var result: Error?
    var done = false
    store.compileContentRuleList(forIdentifier: id, encodedContentRuleList: json) { _, error in
        result = error
        done = true
    }
    while !done {
        RunLoop.main.run(until: Date().addingTimeInterval(0.005))
    }
    return result
}

/// Indexes into `lists` (each a JSON rule list) that WebKit refuses to
/// compile. Many compiles run in flight, since each one is mostly round-trip
/// overhead.
func failingLists(_ lists: [String]) -> Set<Int> {
    let maxInFlight = 64
    var next = 0
    var inFlight = 0
    var failed = Set<Int>()
    var serial = 0
    while next < lists.count || inFlight > 0 {
        while inFlight < maxInFlight && next < lists.count {
            let index = next
            next += 1
            inFlight += 1
            serial += 1
            store.compileContentRuleList(forIdentifier: "one-\(serial)",
                                         encodedContentRuleList: lists[index]) { _, error in
                if error != nil { failed.insert(index) }
                inFlight -= 1
            }
        }
        RunLoop.main.run(until: Date().addingTimeInterval(0.002))
    }
    return failed
}

func encode(_ object: Any) -> String? {
    guard let data = try? JSONSerialization.data(withJSONObject: object,
                                                 options: [.withoutEscapingSlashes, .sortedKeys]) else { return nil }
    return String(data: data, encoding: .utf8)
}

let scopingKeys: Set<String> = ["if-domain", "unless-domain", "if-top-url", "unless-top-url",
                                "resource-type", "load-type", "load-context"]

func unscopedIgnores(_ rules: [[String: Any]]) -> [Int] {
    rules.indices.filter { index in
        let rule = rules[index]
        guard let action = rule["action"] as? [String: Any],
              action["type"] as? String == "ignore-previous-rules",
              let trigger = rule["trigger"] as? [String: Any] else { return false }
        if trigger.keys.contains(where: scopingKeys.contains) { return false }
        let filter = trigger["url-filter"] as? String ?? ""
        return [".*", "*", "^", ""].contains(filter) || filter.count < 8
    }
}

func selector(of rule: [String: Any]) -> String? {
    guard let action = rule["action"] as? [String: Any],
          action["type"] as? String == "css-display-none" else { return nil }
    return action["selector"] as? String
}

/// Indexes of css-display-none rules WebKit drops when compiled alone.
func deadCosmeticRules(_ rules: [[String: Any]]) -> [Int] {
    let cosmetic = rules.indices.filter { selector(of: rules[$0]) != nil }
    let lists = cosmetic.map { encode([rules[$0]]) ?? "" }
    return failingLists(lists).map { cosmetic[$0] }.sorted()
}

/// Splits a selector list on its top-level commas (not inside parens,
/// brackets or quotes, and not escaped).
func topLevelSelectors(_ list: String) -> [String] {
    var parts: [String] = []
    var current = ""
    var depth = 0
    var quote: Character?
    var escaped = false
    for ch in list {
        if escaped {
            current.append(ch)
            escaped = false
            continue
        }
        if ch == "\\" {
            current.append(ch)
            escaped = true
            continue
        }
        if let q = quote {
            current.append(ch)
            if ch == q { quote = nil }
            continue
        }
        switch ch {
        case "\"", "'":
            quote = ch
        case "(", "[":
            depth += 1
        case ")", "]":
            depth -= 1
        case "," where depth == 0:
            parts.append(current.trimmingCharacters(in: .whitespaces))
            current = ""
            continue
        default:
            break
        }
        current.append(ch)
    }
    parts.append(current.trimmingCharacters(in: .whitespaces))
    return parts.filter { !$0.isEmpty }
}

/// Removes the selectors WebKit rejects from each dead rule; drops a rule
/// left with none. Returns the repaired rules and the removed selectors.
func pruned(_ rules: [[String: Any]], dead: [Int]) -> ([[String: Any]], [String]) {
    var rules = rules
    var removed: [String] = []
    var emptied = Set<Int>()
    for index in dead {
        guard let list = selector(of: rules[index]) else { continue }
        let selectors = topLevelSelectors(list)
        let singles = selectors.map { sel -> String in
            var rule = rules[index]
            var action = rule["action"] as? [String: Any] ?? [:]
            action["selector"] = sel
            rule["action"] = action
            return encode([rule]) ?? ""
        }
        let bad = failingLists(singles)
        removed += bad.sorted().map { selectors[$0] }
        let good = selectors.indices.filter { !bad.contains($0) }.map { selectors[$0] }
        if good.isEmpty {
            emptied.insert(index)
        } else {
            var action = rules[index]["action"] as? [String: Any] ?? [:]
            action["selector"] = good.joined(separator: ", ")
            rules[index]["action"] = action
        }
    }
    return (rules.indices.filter { !emptied.contains($0) }.map { rules[$0] }, removed)
}

var failures = 0

for file in files {
    guard let data = FileManager.default.contents(atPath: file),
          let json = String(data: data, encoding: .utf8) else {
        print("✘ \(file): cannot read")
        failures += 1
        continue
    }
    if let error = compile(json, id: "whole") {
        print("✘ \(file): \(error.localizedDescription)")
        failures += 1
        continue
    }
    guard var rules = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] else {
        print("✘ \(file): not a JSON array of rules")
        failures += 1
        continue
    }

    let unscoped = unscopedIgnores(rules)
    for index in unscoped.prefix(10) {
        print("✘ \(file): rule \(index) is an unscoped ignore-previous-rules")
    }

    var dead = deadCosmeticRules(rules)
    if prune && !dead.isEmpty {
        let (repaired, removed) = pruned(rules, dead: dead)
        guard let out = encode(repaired), compile(out, id: "repaired") == nil else {
            print("✘ \(file): repaired list does not compile; left unchanged")
            failures += 1
            continue
        }
        try? out.write(toFile: file, atomically: true, encoding: .utf8)
        for sel in removed.prefix(20) {
            print("  pruned from \(file): \(sel.prefix(160))")
        }
        print("  \(file): pruned \(removed.count) invalid selectors from \(dead.count) rules")
        rules = repaired
        dead = deadCosmeticRules(rules)
    }
    for index in dead.prefix(10) {
        print("✘ \(file): rule \(index) is dropped by WebKit: \((selector(of: rules[index]) ?? "").prefix(160))")
    }
    if dead.count > 10 {
        print("✘ \(file): \(dead.count - 10) more dropped rules")
    }

    if unscoped.isEmpty && dead.isEmpty {
        print("✔ \(file) (\(rules.count) rules)")
    } else {
        failures += 1
    }
}

try? FileManager.default.removeItem(at: scratch)
exit(failures == 0 ? 0 : 1)
