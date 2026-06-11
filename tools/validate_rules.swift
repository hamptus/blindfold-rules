// Validates content-blocker JSON against WebKit's real rule compiler — the
// same compiler Safari uses on iOS. Catches "one bad rule silently kills the
// whole list" before it ships.
//
// Usage: swift tools/validate_rules.swift <file1.json> [file2.json ...]

import Foundation
import WebKit

let files = Array(CommandLine.arguments.dropFirst())
guard !files.isEmpty else {
    print("usage: swift tools/validate_rules.swift <rules.json> ...")
    exit(2)
}

var failures = 0
var remaining = files.count

for file in files {
    guard let json = try? String(contentsOfFile: file, encoding: .utf8) else {
        print("✘ \(file): cannot read")
        failures += 1
        remaining -= 1
        continue
    }
    WKContentRuleListStore.default().compileContentRuleList(
        forIdentifier: "validate-\(remaining)",
        encodedContentRuleList: json
    ) { _, error in
        if let error {
            print("✘ \(file): \(error.localizedDescription)")
            failures += 1
        } else {
            print("✔ \(file)")
        }
        remaining -= 1
    }
}

while remaining > 0 {
    RunLoop.main.run(until: Date().addingTimeInterval(0.05))
}
exit(failures == 0 ? 0 : 1)
