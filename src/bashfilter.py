#!/usr/bin/env python3
"""Keyword denylist for Bash output.

A PostToolUse hook. It does not try to work out which files a command reads --
that is undecidable once pipes, globs, xargs or `sh -c` are involved. It checks
what the command actually produced, and replaces the output if a denylisted term
is in it.

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

PATH_NOTICE = ("[blocked by the local file filter: this command names a path on the path "
               "denylist (paths.txt line%s %s). The output was discarded and is NOT available. "
               "This is a standing denylist rule, not a judgement call: do not retry, do not "
               "try another command or another slice of the same file, and do not ask the user "
               "to paste it.]")

NOTICE = ("[blocked by the local file filter: this command's output matched the keyword "
          "denylist (keywords.txt line%s %s). The output was discarded and is NOT available. "
          "This is a standing denylist rule, not a judgement call: do not retry, do not try "
          "another command to read the same content, and do not ask the user to paste it.]")


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
    if payload.get("tool_name") != "Bash":
        sys.exit(0)

    tr = payload.get("tool_response")
    if not isinstance(tr, dict):
        sys.exit(0)

    command = (payload.get("tool_input") or {}).get("command") or ""
    if HERE in command:
        sys.exit(0)  # inspecting the filter's own files would self-trip

    try:
        conf0 = F.load_conf()
        # Only an explicit features.path_filter turns this on: it is off in
        # every profile, so there is no profile table to replicate here.
        if (conf0.get("features") or {}).get("path_filter"):
            phits = F.command_path_hits(command, conf0)
            if phits:
                F.log(dict(src="<bash>", decision="deny", kind="bash-path",
                           cmd=command[:200], path_lines=[n for n, _ in phits],
                           _terms=[r for _, r in phits]))
                replace(payload, PATH_NOTICE % (
                    "" if len(phits) == 1 else "s",
                    ", ".join(str(n) for n, _ in phits)))
        keywords = F.load_keywords()
        if not keywords:
            sys.exit(0)
        conf = F.load_conf()
        hay = "%s\n%s" % (tr.get("stdout") or "", tr.get("stderr") or "")
        if not hay.strip():
            sys.exit(0)
        hits = F.keyword_hits([with_decoded(hay)], keywords, conf, ocr=False)
    except Exception as exc:
        # Cannot clear the output, so do not pass it on.
        replace(payload, "[local file filter error: %r - output withheld. This is a filter "
                         "bug, not a real denylist match.]" % exc)

    if hits:
        F.log(dict(src="<bash>", decision="deny", kind="bash",
                   cmd=command[:200], keyword_lines=[n for n, _ in hits],
                   _terms=[r for _, r in hits]))
        replace(payload, NOTICE % ("" if len(hits) == 1 else "s",
                                   ", ".join(str(n) for n, _ in hits)))
    sys.exit(0)


if __name__ == "__main__":
    main()
