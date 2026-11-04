#!/usr/bin/env bash
# Installs the PIA watchdog as a systemd timer (Debian / Raspberry Pi OS).
# Re-run it any time to change settings or passwords.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONF_DIR=/etc/pia-watchdog
CRED_DIR=/etc/credstore.encrypted
WATCHDOG="$REPO_DIR/watchdog/pia_watchdog.py"
BYPASS_CON=pia-watchdog-bypass
BYPASS_TABLE=4100

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

# A second connection on the same cable to another VLAN, used only by the
# watchdog's user (a routing rule matches its UID), so it still reaches PIA
# when the VPN is down and its kill switch would otherwise block it.
setup_bypass() {  # vlan id
  local vlan=$1 uid parent dev
  uid=$(id -u pia-watchdog)
  parent=$(ip route show default | awk '{print $5; exit}')
  nmcli connection delete "$BYPASS_CON" >/dev/null 2>&1 || true
  nmcli connection add type vlan con-name "$BYPASS_CON" ifname "$parent.$vlan" dev "$parent" id "$vlan" \
    ipv4.method auto ipv4.route-table "$BYPASS_TABLE" ipv4.ignore-auto-dns yes \
    ipv4.routing-rules "priority 1000 uidrange $uid-$uid table $BYPASS_TABLE" \
    ipv6.method disabled >/dev/null
  echo "Connecting to VLAN $vlan..."
  if nmcli --wait 30 connection up "$BYPASS_CON" >/dev/null 2>&1; then
    dev=$(ip -4 route get 1.1.1.1 uid "$uid" | grep -o 'dev [^ ]*' | cut -d' ' -f2 || true)
    if [[ $dev == "$parent.$vlan" ]] &&
       sudo -u pia-watchdog curl -s -m 10 -o /dev/null -A curl https://serverlist.piaservers.net/vpninfo/servers/v6; then
      echo "Bypass works: the watchdog reaches PIA via VLAN $vlan ($(ip -4 -o addr show dev "$parent.$vlan" | awk '{print $4}'))."
      return 0
    fi
  fi
  nmcli connection delete "$BYPASS_CON" >/dev/null 2>&1 || true
  echo "Couldn't use VLAN $vlan (no address, or no internet through it), so it was removed again." >&2
  echo "Check that the Pi's switch port carries that VLAN, then re-run this installer." >&2
  return 1
}

echo "Installing wireguard-tools and jq (PIA's config script needs them)..."
apt-get install -y -qq wireguard-tools jq >/dev/null

mkdir -p "$CONF_DIR" "$CRED_DIR"
chmod 700 "$CRED_DIR"
id -u pia-watchdog >/dev/null 2>&1 ||
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin pia-watchdog

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
  jq -n --argjson old "$(cat "$CONF_DIR/config.json" 2>/dev/null || echo '{}')" \
    --arg router_url "$router_url" --arg router_username "$router_user" \
    --arg client_name "$client_name" --arg pia_username "$pia_user" --arg region_id "$region" \
    --argjson include_dns "$dns" --argjson dry_run "$dry" \
    '$old + {router_url: $router_url, router_username: $router_username, client_name: $client_name,
      pia_username: $pia_username, region_id: $region_id, include_dns: $include_dns, dry_run: $dry_run}' \
    > "$CONF_DIR/config.json.new"
  mv "$CONF_DIR/config.json.new" "$CONF_DIR/config.json"
  echo "Saved settings to $CONF_DIR/config.json"
fi

for name in pia_password router_password; do
  label=$([[ $name == pia_password ]] && echo "PIA password" || echo "Router password")
  if [[ ! -f $CRED_DIR/pia-watchdog-$name ]] || yes_no "Replace the stored $label?" n; then
    store_secret "$name" "$label"
  fi
done

# Email alerts go through an email account's SMTP server. The watchdog's
# traffic uses the bypass network, so they still go out when the VPN is down.
config_get() { jq -r "$1" "$CONF_DIR/config.json"; }
config_set() {  # jq filter, then jq options
  jq "${@:2}" "$1" "$CONF_DIR/config.json" > "$CONF_DIR/config.json.new"
  mv "$CONF_DIR/config.json.new" "$CONF_DIR/config.json"
}
email=$(config_get '.alert_email // empty')
if [[ -n $email ]]; then
  echo "Email alerts go to $email."
  question="Change email alerts?" default=n
else
  question="Email you when the watchdog replaces the config or something needs your attention?" default=y
fi
if yes_no "$question" "$default"; then
  email=$(ask "Send alerts to (blank to turn them off)" "$email")
  if [[ -n $email ]]; then
    old_sender=$(config_get '.smtp_username // empty')
    echo "Alerts are sent by logging in to an email account's SMTP server. For Gmail, use an app password"
    echo "(https://myaccount.google.com/apppasswords), not your normal password."
    sender=$(ask "Send from (the account that logs in)" "${old_sender:-$email}")
    server=$(ask "SMTP server" "$(config_get '.smtp_server // "smtp.gmail.com"')")
    port=
    until [[ $port =~ ^[0-9]+$ ]]; do
      port=$(ask "SMTP port (465, or 587 for STARTTLS)" "$(config_get '.smtp_port // 465')")
    done
    config_set '. + {alert_email: $email, smtp_username: $sender, smtp_server: $server, smtp_port: $port}' \
      --arg email "$email" --arg sender "$sender" --arg server "$server" --argjson port "$port"
    if [[ $sender != "$old_sender" || ! -f $CRED_DIR/pia-watchdog-smtp_password ]] ||
       yes_no "Replace the stored email password?" n; then
      store_secret smtp_password "Password for $sender"
    fi
  else
    config_set 'del(.alert_email, .smtp_username, .smtp_server, .smtp_port)'
    rm -f "$CRED_DIR/pia-watchdog-smtp_password"
    echo "Email alerts are off."
  fi
fi

current_vlan=$(nmcli -g vlan.id connection show "$BYPASS_CON" 2>/dev/null || true)
if [[ -n $current_vlan ]]; then
  echo "Bypass network: VLAN $current_vlan."
  if yes_no "Change it?" n; then
    vlan=$(ask "VLAN id of a network that isn't routed through the VPN (blank to remove the bypass)")
    if [[ -n $vlan ]]; then setup_bypass "$vlan" || true; else nmcli connection delete "$BYPASS_CON" >/dev/null; fi
  fi
else
  echo "If this machine's own network is routed through the VPN, the watchdog can't reach PIA when the"
  echo "tunnel is down. It can use a second network on the same cable that isn't routed through the VPN."
  vlan=$(ask "VLAN id of that network (blank to skip)")
  [[ -n $vlan ]] && { setup_bypass "$vlan" || true; }
fi

# systemd won't start a service whose credential file is missing, and the
# email password only exists while alerts are on.
unit_edits=(-e "s#@REPO_DIR@#$REPO_DIR#g")
[[ -f $CRED_DIR/pia-watchdog-smtp_password ]] || unit_edits+=(-e '/smtp_password/d')
sed "${unit_edits[@]}" "$REPO_DIR/watchdog/systemd/pia-watchdog.service" > /etc/systemd/system/pia-watchdog.service
cp "$REPO_DIR/watchdog/systemd/pia-watchdog.timer" /etc/systemd/system/pia-watchdog.timer
systemctl daemon-reload
systemctl enable --now pia-watchdog.timer >/dev/null

echo "Checking the router and PIA logins${email:+, and sending a test email}..."
if "$REPO_DIR/watchdog/verify.sh"; then
  echo
  echo "Installed. It checks every 5 minutes. Logs: journalctl -u pia-watchdog"
else
  echo
  echo "Installed, but a check failed (see above). Fix it, then re-run this installer, or just run:" >&2
  echo "  sudo $REPO_DIR/watchdog/verify.sh" >&2
fi
