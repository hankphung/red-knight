#!/usr/bin/env bash
#
# Install the local file filter: compile the Swift helpers, copy the files into
# place, and merge the two hooks into ~/.claude/settings.json.
#
# Safe to re-run. Nothing outside INSTALL_DIR and SETTINGS is touched, the
# settings file is merged rather than overwritten, and a timestamped backup of
# it is kept.
#
#   ./install.sh                 install to ~/.claude/local-filter
#   INSTALL_DIR=... ./install.sh install somewhere else
#   FILTER_PYTHON=... ./install.sh  use a specific python3 (must have Pillow)
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$REPO/src"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.claude/local-filter}"
SETTINGS="${SETTINGS:-$HOME/.claude/settings.json}"

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
step "Checking prerequisites"

[ "$(uname -s)" = "Darwin" ] || die "macOS only: this uses Apple's Vision framework."

os_major="$(sw_vers -productVersion | cut -d. -f1)"
[ "$os_major" -ge 12 ] 2>/dev/null || die \
  "macOS 12 (Monterey) or newer required; found $(sw_vers -productVersion).
   VNGeneratePersonSegmentationRequest and VNDetectDocumentSegmentationRequest
   are both macOS 12 APIs."
say "  macOS $(sw_vers -productVersion)"

command -v swiftc >/dev/null 2>&1 || die \
  "swiftc not found. Install the Xcode command line tools:
       xcode-select --install"
say "  swiftc        $(command -v swiftc)"

# The hook records an absolute interpreter path, so pick one that can actually
# import Pillow rather than whatever ends up first on PATH at hook time.
PY=""
for cand in ${FILTER_PYTHON:-} "$(command -v python3 || true)" \
            /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  [ -n "$cand" ] && [ -x "$cand" ] || continue
  if "$cand" -c 'import PIL' >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  have="$(command -v python3 || echo 'none')"
  die "no python3 with Pillow found (looked at: \$FILTER_PYTHON, PATH, Homebrew, /usr/bin).
   Python 3 on PATH: $have
   Install Pillow for the interpreter you want the hook to use, e.g.
       python3 -m pip install --user Pillow
   then re-run, optionally with FILTER_PYTHON=/full/path/to/python3"
fi
PY="$("$PY" -c 'import sys; print(sys.executable)')"
say "  python3       $PY ($("$PY" -c 'import sys;print(".".join(map(str,sys.version_info[:3])))'))"
say "  Pillow        $("$PY" -c 'import PIL; print(PIL.__version__)')"

# ---------------------------------------------------------------------------
# build + copy
# ---------------------------------------------------------------------------
step "Building the Swift helpers"
mkdir -p "$INSTALL_DIR"
for s in visionscan bashguard; do
  swiftc -O -o "$INSTALL_DIR/$s" "$SRC/$s.swift"
  say "  built $INSTALL_DIR/$s"
done

step "Installing files into $INSTALL_DIR"
for f in imgfilter.py bashfilter.py allow-image parity-test visionscan.swift bashguard.swift; do
  cp "$SRC/$f" "$INSTALL_DIR/$f"
done
chmod +x "$INSTALL_DIR/imgfilter.py" "$INSTALL_DIR/bashfilter.py" \
         "$INSTALL_DIR/allow-image" "$INSTALL_DIR/parity-test"
say "  code: imgfilter.py bashfilter.py allow-image parity-test (+ the .swift sources)"

# Your tuning and your denylist are yours; never clobber them on a re-run.
kept=""
for f in config.json keywords.txt; do
  if [ -e "$INSTALL_DIR/$f" ]; then
    kept="$kept $f"
  else
    cp "$SRC/$f" "$INSTALL_DIR/$f"
    say "  seeded $f"
  fi
done
[ -n "$kept" ] && say "  kept your existing:$kept (not overwritten)"

mkdir -p "$INSTALL_DIR/cache" "$INSTALL_DIR/overrides"

# ---------------------------------------------------------------------------
# settings.json
# ---------------------------------------------------------------------------
step "Wiring hooks into $SETTINGS"

INSTALL_DIR="$INSTALL_DIR" SETTINGS="$SETTINGS" PY="$PY" "$PY" - <<'PYEOF'
import json, os, shutil, sys, time

install = os.environ["INSTALL_DIR"]
settings = os.environ["SETTINGS"]
py = os.environ["PY"]

read_hook = {
    "type": "command",
    "command": py,
    "args": [os.path.join(install, "imgfilter.py")],
    "timeout": 60,
    # Load-bearing: a filter that fails open is worse than no filter, because
    # you stop looking. If the hook errors or times out, the read is blocked.
    "onFailure": "block",
    "statusMessage": "Filtering file for sensitive content...",
}
bash_hook = {
    "type": "command",
    "command": os.path.join(install, "bashguard"),
    "timeout": 20,
    "statusMessage": "Checking output against the keyword denylist...",
}

os.makedirs(os.path.dirname(settings) or ".", exist_ok=True)
if os.path.exists(settings):
    with open(settings) as fh:
        text = fh.read()
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError as exc:
        sys.exit("error: %s is not valid JSON (%s); refusing to touch it" % (settings, exc))
    backup = "%s.bak-%s" % (settings, time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(settings, backup)
    print("  backed up -> %s" % backup)
else:
    data = {}
    backup = None
    print("  creating %s" % settings)

if not isinstance(data, dict):
    sys.exit("error: %s does not contain a JSON object; refusing to touch it" % settings)

hooks = data.setdefault("hooks", {})


def mentions_us(hook):
    """True for a hook entry that points into our install dir -- i.e. one we
    (or a previous version of this installer) put there."""
    blob = json.dumps(hook)
    return install in blob


def install_hook(event, matcher, entry, label):
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list):
        sys.exit("error: hooks.%s in %s is not a list; refusing to touch it" % (event, settings))
    group = None
    for g in groups:
        if isinstance(g, dict) and g.get("matcher") == matcher:
            group = g
            break
    if group is None:
        group = {"matcher": matcher, "hooks": []}
        groups.append(group)
    entries = group.setdefault("hooks", [])
    for i, existing in enumerate(entries):
        if isinstance(existing, dict) and mentions_us(existing):
            if existing == entry:
                print("  %s: already current, unchanged" % label)
            else:
                entries[i] = entry
                print("  %s: updated in place" % label)
            return
    entries.append(entry)
    print("  %s: added (%d other hook(s) on this matcher left alone)"
          % (label, len(entries) - 1))


install_hook("PreToolUse", "Read", read_hook, "PreToolUse/Read -> imgfilter.py")
install_hook("PostToolUse", "Bash", bash_hook, "PostToolUse/Bash -> bashguard")

with open(settings, "w") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
PYEOF

# ---------------------------------------------------------------------------
step "Done"
cat <<EOF

Installed to: $INSTALL_DIR
Hooks merged into: $SETTINGS

What changed:
  - $INSTALL_DIR now holds the filter, the two compiled Swift helpers,
    and (first install only) config.json and keywords.txt.
  - Two hooks were added to settings.json: a PreToolUse hook on Read and a
    PostToolUse hook on Bash. Any other hooks you already had were left as
    they were, and the previous settings.json was backed up alongside it.

Next:
  1. Edit $INSTALL_DIR/keywords.txt. The four shipped terms are
     placeholders; the denylist is only useful with your own markings in it.
  2. Restart Claude Code (hooks are read at startup).
  3. Check it works:  $INSTALL_DIR/parity-test

To undo:  $REPO/uninstall.sh
EOF
