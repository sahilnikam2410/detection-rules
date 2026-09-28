#!/usr/bin/env bash
# Install this repo's Wazuh rules into a Wazuh manager's local_rules.xml.
#
#   sudo ./scripts/install-wazuh.sh               # validated rules only
#   sudo ./scripts/install-wazuh.sh --with-drafts # validated + draft rules
#   sudo ./scripts/install-wazuh.sh --uninstall   # remove them again
#
# Safe to re-run: the rules live between marker comments and are replaced,
# not duplicated. local_rules.xml is backed up first, the result is checked
# with wazuh-analysisd -t, and the backup is restored if the check fails.
#
# Env: OSSEC_DIR (default /var/ossec), NO_RESTART=1 to skip the restart.
set -euo pipefail

OSSEC_DIR="${OSSEC_DIR:-/var/ossec}"
RULES="$OSSEC_DIR/etc/rules/local_rules.xml"
ANALYSISD="$OSSEC_DIR/bin/wazuh-analysisd"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BEGIN="<!-- BEGIN sahilnikam2410/detection-rules -->"
END="<!-- END sahilnikam2410/detection-rules -->"

mode="validated"
case "${1:-}" in
  "") ;;
  --with-drafts) mode="all" ;;
  --uninstall) mode="uninstall" ;;
  -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac

[ -f "$RULES" ] || { echo "not found: $RULES (is this a Wazuh manager? set OSSEC_DIR)" >&2; exit 1; }
[ -w "$RULES" ] || { echo "cannot write $RULES (run with sudo)" >&2; exit 1; }

backup="$RULES.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$RULES" "$backup"
echo "backup: $backup"

# Drop any block from a previous install.
tmp="$(mktemp)"
awk -v b="$BEGIN" -v e="$END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip' "$RULES" > "$tmp"

if [ "$mode" != "uninstall" ]; then
  files=("$REPO_DIR"/wazuh/validated/*.xml)
  [ "$mode" = "all" ] && files+=("$REPO_DIR"/wazuh/drafts/*.xml)
  {
    echo "$BEGIN"
    for f in "${files[@]}"; do
      echo "<!-- ${f#"$REPO_DIR"/} -->"
      cat "$f"
    done
    echo "$END"
  } >> "$tmp"
  echo "installing ${#files[@]} file(s) ($mode)"
else
  echo "removing detection-rules block"
fi

cat "$tmp" > "$RULES"   # keep original owner and permissions
rm -f "$tmp"

if ! "$ANALYSISD" -t; then
  echo "wazuh-analysisd -t failed, restoring $backup" >&2
  cp -p "$backup" "$RULES"
  exit 1
fi
echo "wazuh-analysisd -t: OK"

if [ "${NO_RESTART:-0}" != "1" ]; then
  if command -v systemctl >/dev/null && systemctl list-units --type=service 2>/dev/null | grep -q wazuh-manager; then
    systemctl restart wazuh-manager
  else
    "$OSSEC_DIR/bin/wazuh-control" restart
  fi
  echo "wazuh-manager restarted"
fi
