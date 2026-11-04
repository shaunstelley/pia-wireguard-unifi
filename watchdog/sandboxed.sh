#!/usr/bin/env bash
# Run pia_watchdog.py once with the given options, in the same sandbox as the
# installed service: its user (so the bypass network applies), its settings,
# and its encrypted passwords, which only a systemd sandbox can decrypt.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRED_DIR=/etc/credstore.encrypted
email=()  # only exists while email alerts are on
if [[ -f $CRED_DIR/pia-watchdog-smtp_password ]]; then
  email=(-p "LoadCredentialEncrypted=smtp_password:$CRED_DIR/pia-watchdog-smtp_password")
fi

exec systemd-run --quiet --pipe --wait --collect \
  --unit="pia-watchdog-manual-$$" \
  -p User=pia-watchdog -p Group=pia-watchdog -p StateDirectory=pia-watchdog \
  -p ProtectHome=yes -p PrivateTmp=yes -p "RestrictAddressFamilies=AF_INET AF_UNIX" \
  -p "LoadCredentialEncrypted=pia_password:$CRED_DIR/pia-watchdog-pia_password" \
  -p "LoadCredentialEncrypted=router_password:$CRED_DIR/pia-watchdog-router_password" \
  "${email[@]}" \
  /usr/bin/python3 "$REPO_DIR/watchdog/pia_watchdog.py" --config /etc/pia-watchdog/config.json "$@"
