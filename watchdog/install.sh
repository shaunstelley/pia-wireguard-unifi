#!/usr/bin/env bash
# Installs the PIA watchdog as a systemd timer (Debian / Raspberry Pi OS).
# Re-run it any time to change settings or passwords.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONF_DIR=/etc/pia-watchdog
CRED_DIR=/etc/credstore.encrypted
WATCHDOG="$REPO_DIR/watchdog/pia_watchdog.py"

# The service runs as a throwaway user with no access to /home.
if [[ $REPO_DIR == /home/* || $REPO_DIR == /root/* ]]; then
  echo "Clone the repo outside your home folder, e.g.:" >&2
  echo "  sudo git clone https://github.com/shaunstelley/pia-wireguard-unifi.git /opt/pia-wireguard-unifi" >&2
  exit 1
fi

ask() {  # prompt, default
  local reply
  read -rp "$1${2:+ [$2]}: " reply
  echo "${reply:-${2:-}}"
}

yes_no() {  # prompt, default y|n
  local reply
  read -rp "$1 [$([[ $2 == y ]] && echo Y/n || echo y/N)]: " reply
  reply=${reply:-$2}
  [[ ${reply,,} == y* ]]
}

store_secret() {  # credential name, prompt
  local secret
  read -rsp "$2: " secret
  echo
  printf '%s' "$secret" | systemd-creds encrypt --name="$1" - "$CRED_DIR/pia-watchdog-$1"
}

echo "Installing wireguard-tools and jq (PIA's config script needs them)..."
apt-get install -y -qq wireguard-tools jq >/dev/null

mkdir -p "$CONF_DIR" "$CRED_DIR"
chmod 700 "$CRED_DIR"

if [[ ! -f $CONF_DIR/config.json ]] || yes_no "Change the existing settings?" n; then
  router_url=$(ask "Router address" "https://192.168.1.1")
  router_user=$(ask "Router username (a local-only admin account)")
  client_name=$(ask "Name of the PIA WireGuard VPN client on the router")
  pia_user=$(ask "PIA username")
  while :; do
    region=$(ask "PIA region id (type ? to list them)")
    [[ $region == "?" ]] && { python3 "$WATCHDOG" --list-regions; continue; }
    [[ -n $region ]] && break
  done
  if yes_no "Use PIA's DNS server" y; then dns=true; else dns=false; fi
  if yes_no "Start in dry-run mode (log what it would do, change nothing)" y; then dry=true; else dry=false; fi
  jq -n \
    --arg router_url "$router_url" --arg router_username "$router_user" \
    --arg client_name "$client_name" --arg pia_username "$pia_user" --arg region_id "$region" \
    --argjson include_dns "$dns" --argjson dry_run "$dry" \
    '{router_url: $router_url, router_username: $router_username, client_name: $client_name,
      pia_username: $pia_username, region_id: $region_id, include_dns: $include_dns, dry_run: $dry_run}' \
    > "$CONF_DIR/config.json"
  echo "Saved settings to $CONF_DIR/config.json"
fi

for name in pia_password router_password; do
  label=$([[ $name == pia_password ]] && echo "PIA password" || echo "Router password")
  if [[ ! -f $CRED_DIR/pia-watchdog-$name ]] || yes_no "Replace the stored $label?" n; then
    store_secret "$name" "$label"
  fi
done

sed "s#@REPO_DIR@#$REPO_DIR#g" "$REPO_DIR/watchdog/systemd/pia-watchdog.service" > /etc/systemd/system/pia-watchdog.service
cp "$REPO_DIR/watchdog/systemd/pia-watchdog.timer" /etc/systemd/system/pia-watchdog.timer
systemctl daemon-reload
systemctl enable --now pia-watchdog.timer >/dev/null

echo "Running a first check..."
systemctl start pia-watchdog.service || true
journalctl -u pia-watchdog.service -n 5 --no-pager -o cat
echo
echo "Installed. It checks every 5 minutes. Logs: journalctl -u pia-watchdog"
