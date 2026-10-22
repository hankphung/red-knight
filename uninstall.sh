#!/usr/bin/env bash
#
# Remove the local file filter's hooks from ~/.claude/settings.json, and
# optionally the installed files.
#
#   ./uninstall.sh            unhook only; leave the files (and your keywords)
#   ./uninstall.sh --purge    unhook and delete INSTALL_DIR entirely
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.claude/local-filter}"
SETTINGS="${SETTINGS:-$HOME/.claude/settings.json}"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

PY="${FILTER_PYTHON:-$(command -v python3 || true)}"
[ -n "$PY" ] || { echo "error: python3 not found; needed to edit settings.json" >&2; exit 1; }

printf '\n== Removing hooks from %s\n' "$SETTINGS"
INSTALL_DIR="$INSTALL_DIR" SETTINGS="$SETTINGS" "$PY" - <<'PYEOF'
import json, os, shutil, sys, time

install = os.environ["INSTALL_DIR"]
settings = os.environ["SETTINGS"]

if not os.path.exists(settings):
    print("  %s does not exist; nothing to remove" % settings)
    raise SystemExit(0)

with open(settings) as fh:
    text = fh.read()
try:
    data = json.loads(text) if text.strip() else {}
except ValueError as exc:
    sys.exit("error: %s is not valid JSON (%s); refusing to touch it" % (settings, exc))
if not isinstance(data, dict):
    sys.exit("error: %s does not contain a JSON object; refusing to touch it" % settings)

removed = 0
hooks = data.get("hooks")
if isinstance(hooks, dict):
    for event, groups in list(hooks.items()):
        if not isinstance(groups, list):
            continue
        for group in list(groups):
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                continue
            keep = [h for h in group["hooks"]
                    if not (isinstance(h, dict) and install in json.dumps(h))]
            dropped = len(group["hooks"]) - len(keep)
            removed += dropped
            group["hooks"] = keep
            # Only drop a group we emptied -- never one that was already empty,
            # which would be someone else's structure.
            if dropped and not keep:
                groups.remove(group)
        if not groups:
            del hooks[event]
    if not hooks:
        data.pop("hooks", None)

if not removed:
    print("  no hooks pointing at %s; settings.json left untouched" % install)
    raise SystemExit(0)

backup = "%s.bak-%s" % (settings, time.strftime("%Y%m%d-%H%M%S"))
shutil.copy2(settings, backup)
with open(settings, "w") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
print("  backed up -> %s" % backup)
print("  removed %d hook(s); every other hook and setting left as it was" % removed)
PYEOF

if [ "$PURGE" = "1" ]; then
  printf '\n== Deleting %s\n' "$INSTALL_DIR"
  if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo "  deleted (including cache/, overrides/, log.jsonl and your keywords.txt)"
  else
    echo "  not present"
  fi
else
  printf '\n%s\n' "Files left in $INSTALL_DIR (including your keywords.txt and config.json)."
  printf '%s\n' "Re-run with --purge to delete them too."
fi

printf '\n%s\n' "Restart Claude Code for the hook change to take effect."
