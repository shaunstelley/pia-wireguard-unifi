#!/usr/bin/env bash
# Runs the log-only traffic probe for a few days, then emails its results and
# switches it off. It never changes the router.
#   sudo watchdog/probe-install.sh [days]   start it (default 2 days; restarts with fresh results)
#   sudo watchdog/probe-install.sh --remove  take it all out, including its results
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRED=/etc/credstore.encrypted/pia-watchdog-smtp_password
UNITS=(pia-probe.service pia-probe.timer pia-probe-report.service pia-probe-report.timer)

if [[ ${1:-} == --remove ]]; then
  systemctl disable --now pia-probe.timer pia-probe-report.timer 2>/dev/null || true
  for unit in "${UNITS[@]}"; do rm -f "/etc/systemd/system/$unit"; done
  systemctl daemon-reload
  rm -rf /var/lib/pia-probe
  userdel pia-probe 2>/dev/null || true
  echo "Traffic probe removed."
  exit 0
fi

days=${1:-2}
[[ $days =~ ^[1-9][0-9]*$ ]] || { echo "Usage: sudo $0 [days] | --remove" >&2; exit 1; }
[[ -f /etc/pia-watchdog/config.json ]] || { echo "Install the watchdog first (watchdog/install.sh)." >&2; exit 1; }
id -u pia-probe >/dev/null 2>&1 ||
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin pia-probe

report_at=$(date -u -d "+$days days" "+%Y-%m-%d %H:%M:%S UTC")
unit_edits=(-e "s#@REPO_DIR@#$REPO_DIR#g" -e "s#@REPORT_AT@#$report_at#g")
[[ -f $CRED ]] || unit_edits+=(-e '/smtp_password/d')
systemctl stop pia-probe.timer 2>/dev/null || true
for unit in "${UNITS[@]}"; do
  sed "${unit_edits[@]}" "$REPO_DIR/watchdog/systemd/$unit" > "/etc/systemd/system/$unit"
done
rm -f /var/lib/pia-probe/probe.json   # start with fresh results
systemctl daemon-reload
systemctl enable --now pia-probe.timer pia-probe-report.timer >/dev/null

email=$(jq -r '.alert_email // empty' /etc/pia-watchdog/config.json)
echo "Probing every 30 seconds until $report_at."
if [[ -n $email && -f $CRED ]]; then
  echo "The results will be emailed to $email then, and the probe switched off."
else
  echo "Email alerts are off, so the results will only be in: journalctl -u pia-probe-report"
fi
echo "Preview the report any time: sudo python3 $REPO_DIR/watchdog/probe_report.py --config /etc/pia-watchdog/config.json --dry-run"
