#!/usr/bin/env bash
# Replace the router's PIA config right now, with the installed watchdog's
# settings and encrypted passwords (which only a systemd-run sandbox can read).
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRED_DIR=/etc/credstore.encrypted

exec systemd-run --quiet --pipe --wait --collect \
  --unit="pia-watchdog-replace-now-$$" \
  -p DynamicUser=yes -p StateDirectory=pia-watchdog -p ProtectHome=yes -p PrivateTmp=yes \
  -p "LoadCredentialEncrypted=pia_password:$CRED_DIR/pia-watchdog-pia_password" \
  -p "LoadCredentialEncrypted=router_password:$CRED_DIR/pia-watchdog-router_password" \
  /usr/bin/python3 "$REPO_DIR/watchdog/pia_watchdog.py" --config /etc/pia-watchdog/config.json --replace-now
