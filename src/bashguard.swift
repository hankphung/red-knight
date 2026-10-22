import Foundation

// PostToolUse keyword guard for Bash and Grep output. A Swift port of
// bashfilter.py,
// which stays as the reference implementation that parity-test checks against.
// Python's interpreter floor is ~36ms; this runs the whole check in ~15ms, and
// it runs on every Bash call.

let HERE = URL(fileURLWithPath: CommandLine.arguments[0])
    .resolvingSymlinksInPath().deletingLastPathComponent().path

// Grep returns its result in `content`/`filenames`, not `stdout`/`stderr`, so
// the replacement has to be shaped per tool. Set once the payload is parsed.
var grepMode = false

func fail(_ why: String) -> Never {
    emit(stdout: "[local file filter error: \(why) - output withheld. This is a filter bug, "
               + "not a real denylist match.]", response: nil)
}

func emit(stdout text: String, response: [String: Any]?) -> Never {
    var out = response ?? [:]
    if grepMode {
        out["content"] = text
        out["filenames"] = [String]()
        out["numFiles"] = 0
        out["numLines"] = 0
        out["numMatches"] = 0
    } else {
        out["stdout"] = text
        out["stderr"] = ""
    }
    let payload: [String: Any] = ["hookSpecificOutput": [
        "hookEventName": "PostToolUse", "updatedToolOutput": out,
    ]]
    if let d = try? JSONSerialization.data(withJSONObject: payload) {
        FileHandle.standardOutput.write(d)
    }
    exit(0)
}

func normBytes(_ s: String) -> [UInt8] {
    // One pass over UTF-8 bytes: lowercasing and whitespace-collapsing a large
    // output via split/joined allocates far too much.
    var out = [UInt8]()
    out.reserveCapacity(s.utf8.count)
    var pendingSpace = false
    for b in s.utf8 {
        if b == 0x20 || b == 0x09 || b == 0x0a || b == 0x0d || b == 0x0b || b == 0x0c {
            if !out.isEmpty { pendingSpace = true }
            continue
        }
        if pendingSpace { out.append(0x20); pendingSpace = false }
        out.append(b >= 0x41 && b <= 0x5a ? b + 32 : b)
    }
    return out
}

enum Rule { case text([UInt8]), regex(NSRegularExpression) }

func loadRules(_ file: String) -> [(Int, String, Rule)] {
    guard let raw = try? String(contentsOfFile: HERE + "/" + file, encoding: .utf8) else {
        return []
    }
    var out: [(Int, String, Rule)] = []
    for (i, line) in raw.components(separatedBy: .newlines).enumerated() {
        let e = line.trimmingCharacters(in: .whitespaces)
        if e.isEmpty || e.hasPrefix("#") { continue }
        if e.lowercased().hasPrefix("re:") {
            let pat = String(e.dropFirst(3)).trimmingCharacters(in: .whitespaces)
            if let rx = try? NSRegularExpression(pattern: pat, options: [.caseInsensitive]) {
                out.append((i + 1, e, .regex(rx)))
            }
        } else {
            out.append((i + 1, e, .text(normBytes(e))))
        }
    }
    return out
}

// Append the plaintext of any base64-looking run, closing `base64 -i file`.
func hasBase64Run(_ s: String) -> Bool {
    var run = 0
    for b in s.utf8 {
        let ok = (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a)
              || (b >= 0x30 && b <= 0x39) || b == 0x2b || b == 0x2f
              || b == 0x0a || b == 0x0d
        run = ok ? run + 1 : 0
        if run >= 32 { return true }
    }
    return false
}


func withDecoded(_ text: String) -> String {
    if !hasBase64Run(text) { return text }
    let capped = text.count > (1 << 20) ? String(text.prefix(1 << 20)) : text
    guard let rx = try? NSRegularExpression(pattern: "[A-Za-z0-9+/\\n\\r]{32,}={0,2}") else {
        return capped
    }
    var extra: [String] = []
    let ns = capped as NSString
    for m in rx.matches(in: capped, range: NSRange(location: 0, length: ns.length)) {
        var blob = ns.substring(with: m.range)
            .components(separatedBy: .whitespacesAndNewlines).joined()
        if blob.count < 32 { continue }
        if blob.count % 4 != 0 { blob = String(blob.prefix(blob.count - blob.count % 4)) }
        if let d = Data(base64Encoded: blob), let s = String(data: d, encoding: .utf8) {
            extra.append(s)
        }
    }
    return extra.isEmpty ? capped : capped + "\n" + extra.joined(separator: "\n")
}

func logLine(_ fields: [String: Any]) {
    var rec = fields
    let fmt = DateFormatter()
    fmt.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
    rec["ts"] = fmt.string(from: Date())
    guard let d = try? JSONSerialization.data(withJSONObject: rec),
          var line = String(data: d, encoding: .utf8) else { return }
    line += "\n"
    let path = HERE + "/log.jsonl"
    if let fh = FileHandle(forWritingAtPath: path) {
        fh.seekToEndOfFile()
        fh.write(line.data(using: .utf8)!)
        try? fh.close()
    } else {
        try? line.write(toFile: path, atomically: true, encoding: .utf8)
    }
}

// Only an explicit features.path_filter turns the path denylist on; it is off
// in every profile, so there is no profile table to replicate here.
func pathFilterEnabled() -> Bool {
    guard let d = FileManager.default.contents(atPath: HERE + "/config.json"),
          let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
          let f = o["features"] as? [String: Any] else { return false }
    return (f["path_filter"] as? Bool) ?? false
}


// A path rule is anchored for a path (\.pem$), but in a command `$` is
// end-of-command, so `cat x.pem | head` would never match. Match each
// path-shaped token separately, and the whole command too so unanchored
// literal rules still work.
let cmdToken = try! NSRegularExpression(pattern: "[^\\s;|&()<>'\"]+")

func commandTargets(_ command: String) -> [String] {
    var out = [command]
    let ns = command as NSString
    for m in cmdToken.matches(in: command, range: NSRange(location: 0, length: ns.length)) {
        let t = ns.substring(with: m.range).trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
        if t.contains("/") || t.hasPrefix(".") { out.append(t) }
    }
    return out
}


func matches(_ hay: String, _ rules: [(Int, String, Rule)]) -> ([Int], [String]) {
    let needle = normBytes(hay)
    let nd = Data(needle)
    let ns = String(decoding: nd, as: UTF8.self)
    var lines: [Int] = []; var terms: [String] = []
    for (lineno, raw, rule) in rules {
        switch rule {
        case .text(let t):
            if !t.isEmpty && nd.range(of: Data(t)) != nil { lines.append(lineno); terms.append(raw) }
        case .regex(let rx):
            if rx.firstMatch(in: ns, range: NSRange(ns.startIndex..., in: ns)) != nil {
                lines.append(lineno); terms.append(raw)
            }
        }
    }
    return (lines, terms)
}


// ---------------------------------------------------------------------------
let input = FileHandle.standardInput.readDataToEndOfFile()
guard let payload = (try? JSONSerialization.jsonObject(with: input)) as? [String: Any] else {
    exit(0)  // not a payload we understand; the tool result stands
}
guard let toolName = payload["tool_name"] as? String,
      toolName == "Bash" || toolName == "Grep" else { exit(0) }
guard let response = payload["tool_response"] as? [String: Any] else { exit(0) }
grepMode = toolName == "Grep"

let toolInput = (payload["tool_input"] as? [String: Any]) ?? [:]
let command = (toolInput["command"] as? String) ?? ""
let grepFiles = (response["filenames"] as? [String]) ?? []
let src = grepMode ? "<grep>" : "<bash>"
let subject = grepMode ? "this search" : "this command"
// Grep has no command line; the directory it searched and the files it matched
// are what stands in for one, both here and for the path rules below.
if ([command, (toolInput["path"] as? String) ?? ""] + grepFiles)
    .contains(where: { $0.contains(HERE) }) { exit(0) }  // our own files would self-trip

if pathFilterEnabled() {
    let rules = loadRules("paths.txt")
    if !rules.isEmpty {
        var lineSet: [Int: String] = [:]
        let targets = grepMode
            ? ([(toolInput["path"] as? String) ?? "", (toolInput["glob"] as? String) ?? ""]
               + grepFiles).filter { !$0.isEmpty }
            : commandTargets(command)
        for target in targets {
            let (ls, ts) = matches(target, rules)
            for (i, l) in ls.enumerated() { lineSet[l] = ts[i] }
        }
        let lines = lineSet.keys.sorted()
        let terms = lines.map { lineSet[$0]! }
        if !lines.isEmpty {
            logLine(["src": src, "decision": "deny", "kind": grepMode ? "grep-path" : "bash-path",
                     "cmd": String(command.prefix(200)), "path_lines": lines, "_terms": terms])
            let plural = lines.count == 1 ? "" : "s"
            let ls = lines.map(String.init).joined(separator: ", ")
            emit(stdout: "[blocked by the local file filter: \(subject) names a path on the "
                       + "path denylist (paths.txt line\(plural) \(ls)). The output was discarded "
                       + "and is NOT available. This is a standing denylist rule, not a judgement "
                       + "call: do not retry, do not try another command, tool or another slice of the "
                       + "same file, and do not ask the user to paste it.]",
                 response: response)
        }
    }
}

let hay = grepMode
    ? (((response["content"] as? String) ?? "") + "\n" + grepFiles.joined(separator: "\n"))
    : (((response["stdout"] as? String) ?? "") + "\n" + ((response["stderr"] as? String) ?? ""))
if hay.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { exit(0) }

let keywords = loadRules("keywords.txt")
if keywords.isEmpty { exit(0) }

let needleData = Data(normBytes(withDecoded(hay)))
// Built only when a `re:` rule exists -- bridging 190 KB to String costs more
// than every literal comparison put together.
var needleString: String { String(decoding: needleData, as: UTF8.self) }

var hitLines: [Int] = []
var hitTerms: [String] = []
for (lineno, raw, rule) in keywords {
    switch rule {
    case .text(let t):
        if !t.isEmpty && needleData.range(of: Data(t)) != nil {
            hitLines.append(lineno); hitTerms.append(raw)
        }
    case .regex(let rx):
        let s = needleString
        if rx.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil {
            hitLines.append(lineno); hitTerms.append(raw)
        }
    }
}

if !hitLines.isEmpty {
    logLine(["src": src, "decision": "deny", "kind": grepMode ? "grep" : "bash",
             "cmd": String(command.prefix(200)), "keyword_lines": hitLines, "_terms": hitTerms])
    let plural = hitLines.count == 1 ? "" : "s"
    let lines = hitLines.map(String.init).joined(separator: ", ")
    emit(stdout: "[blocked by the local file filter: \(subject)'s output matched the keyword "
               + "denylist (keywords.txt line\(plural) \(lines)). The output was discarded and "
               + "is NOT available. This is a standing denylist rule, not a judgement call: do "
               + "not retry, do not try another command or tool to read the same content, and do not ask "
               + "the user to paste it.]",
         response: response)
}
exit(0)
