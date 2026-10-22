#!/usr/bin/env python3
"""Keyword denylist for Bash and Grep output.

A PostToolUse hook. It does not try to work out which files a command reads --
that is undecidable once pipes, globs, xargs or `sh -c` are involved. It checks
what the command actually produced, and replaces the output if a denylisted term
is in it.

Grep is covered by the same rule for the same reason: a search that returns
matching lines is a file read with the uninteresting parts removed, and `-C`
turns it into an ordinary one. Its result arrives in `content`/`filenames`
rather than `stdout`/`stderr`, which is the only thing that differs here.

The command has already run by the time this fires. That is acceptable here
because the thing being prevented is *disclosure*, not a side effect: nothing
leaves the machine until the output reaches the model.
"""
import base64
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import imgfilter as F  # noqa: E402

PATH_NOTICE = ("[blocked by the local file filter: %s names a path on the path "
               "denylist (paths.txt line%s %s). The output was discarded and is NOT available. "
               "This is a standing denylist rule, not a judgement call: do not retry, do not "
               "try another command, tool or another slice of the same file, and do not ask the "
               "user to paste it.]")

NOTICE = ("[blocked by the local file filter: %s's output matched the keyword "
          "denylist (keywords.txt line%s %s). The output was discarded and is NOT available. "
          "This is a standing denylist rule, not a judgement call: do not retry, do not try "
          "another command or tool to read the same content, and do not ask the user to paste it.]")


B64_RUN = re.compile(r"[A-Za-z0-9+/\n\r]{32,}={0,2}")


def with_decoded(text):
    """Append the plaintext of any base64-looking run. Closes the most likely
    transformation (`base64 -i file`); hex, compression and anything bespoke
    still defeat output scanning -- see README."""
    extra = []
    for m in B64_RUN.finditer(text[:1 << 20]):
        blob = re.sub(r"\s", "", m.group())
        if len(blob) % 4:
            blob = blob[: len(blob) - len(blob) % 4]
        if len(blob) < 32:
            continue
        try:
            dec = base64.b64decode(blob, validate=True).decode("utf-8")
        except Exception:
            continue
        if dec.isprintable() or "\n" in dec:
            extra.append(dec)
    return text if not extra else text + "\n" + "\n".join(extra)


def replace(payload, stdout_text):
    out = dict(payload.get("tool_response") or {})
    if payload.get("tool_name") == "Grep":
        # Grep's result is rendered from these fields; stdout is not read.
        out["content"] = stdout_text
        out["filenames"] = []
        out["numFiles"] = 0
        out["numLines"] = 0
        out["numMatches"] = 0
    else:
        out["stdout"] = stdout_text
        out["stderr"] = ""
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedToolOutput": out,
    }}))
    sys.exit(0)


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    tool = payload.get("tool_name")
    if tool not in ("Bash", "Grep"):
        sys.exit(0)
    grep = tool == "Grep"
    subject = "this search" if grep else "this command"

    tr = payload.get("tool_response")
    if not isinstance(tr, dict):
        sys.exit(0)

    ti = payload.get("tool_input") or {}
    command = ti.get("command") or ""
    files = tr.get("filenames") or []
    # Grep has no command line; the directory it searched and the files it
    # matched stand in for one, both here and for the path rules below.
    if any(HERE in t for t in [command, ti.get("path") or ""] + files):
        sys.exit(0)  # inspecting the filter's own files would self-trip

    try:
        conf0 = F.load_conf()
        # Only an explicit features.path_filter turns this on: it is off in
        # every profile, so there is no profile table to replicate here.
        if (conf0.get("features") or {}).get("path_filter"):
            if grep:
                seen = {}
                for target in [ti.get("path") or "", ti.get("glob") or ""] + files:
                    if target:
                        for n, r in F.path_hits(target, conf0):
                            seen[n] = r
                phits = sorted(seen.items())
            else:
                phits = F.command_path_hits(command, conf0)
            if phits:
                F.log(dict(src="<grep>" if grep else "<bash>", decision="deny",
                           kind="grep-path" if grep else "bash-path",
                           cmd=command[:200], path_lines=[n for n, _ in phits],
                           _terms=[r for _, r in phits]))
                replace(payload, PATH_NOTICE % (
                    subject, "" if len(phits) == 1 else "s",
                    ", ".join(str(n) for n, _ in phits)))
        keywords = F.load_keywords()
        if not keywords:
            sys.exit(0)
        conf = F.load_conf()
        if grep:
            hay = "%s\n%s" % (tr.get("content") or "", "\n".join(files))
        else:
            hay = "%s\n%s" % (tr.get("stdout") or "", tr.get("stderr") or "")
        if not hay.strip():
            sys.exit(0)
        hits = F.keyword_hits([with_decoded(hay)], keywords, conf, ocr=False)
    except Exception as exc:
        # Cannot clear the output, so do not pass it on.
        replace(payload, "[local file filter error: %r - output withheld. This is a filter "
                         "bug, not a real denylist match.]" % exc)

    if hits:
        F.log(dict(src="<grep>" if grep else "<bash>", decision="deny",
                   kind="grep" if grep else "bash",
                   cmd=command[:200], keyword_lines=[n for n, _ in hits],
                   _terms=[r for _, r in hits]))
        replace(payload, NOTICE % (subject, "" if len(hits) == 1 else "s",
                                   ", ".join(str(n) for n, _ in hits)))
    sys.exit(0)


if __name__ == "__main__":
    main()
