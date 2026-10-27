#!/usr/bin/env python3
"""Replace the router's PIA WireGuard config when it stops connecting.

Run once per invocation (a systemd timer calls it every few minutes). Secrets
come from systemd's encrypted credentials ($CREDENTIALS_DIRECTORY); see
watchdog/README.md.
"""

import argparse
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import time
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui"))
import pia_config  # noqa: E402
import router_push  # noqa: E402

DAY_SECONDS = 24 * 60 * 60
DEFAULTS = {
    "include_dns": True,
    "dry_run": True,
    "unhealthy_checks_before_replacing": 3,
    "max_replacements_per_day": 4,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 465,
    "alert_reminder_hours": 6,
}

# Run results worth an email, with their subjects. Each one opens an alert
# that's repeated every alert_reminder_hours while it lasts and closed by an
# all-clear email on the next healthy check. FAILED ones also fail the run.
ALERTS = {
    "capped": "VPN is down and the daily replacement limit is reached",
    "pia_login": "PIA login check failed",
    "no_client": "VPN client not found on the router",
    "router_error": "Problem talking to the router",
    "error": "Watchdog run failed",
    "dry_run": "VPN is down (dry run, so nothing was replaced)",
}
FAILED = {"capped", "pia_login", "no_client", "router_error", "error"}

run_log = []  # this run's messages, for the alert email


def log(message):
    run_log.append(message)
    print(message, flush=True)


def read_secret(name):
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not cred_dir:
        raise RuntimeError("No $CREDENTIALS_DIRECTORY: run this through its systemd service, not directly.")
    return (Path(cred_dir) / name).read_text(encoding="utf-8").strip()


def endpoint_ip(conf_text):
    match = re.search(r"^\s*Endpoint\s*=\s*([0-9.]+):\d+", conf_text or "", re.MULTILINE)
    return match.group(1) if match else None


def lan_ip_toward(url):
    """This machine's IP on the route to url's host (a UDP connect sends nothing)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((urlsplit(url).hostname, 443))
        return s.getsockname()[0]


def warn_if_routed_through(opener, csrf, config, client):
    try:
        my_ip = lan_ip_toward(config["router_url"])
        routed = router_push.routes_through_client(opener, csrf, config["router_url"], client, my_ip)
    except (OSError, router_push.RouterPushError) as e:
        log(f"Couldn't check whether this machine is routed through the VPN: {e}")
        return
    if routed:
        log(f"Warning: this machine ({my_ip}) is routed through {config['client_name']!r}. If the tunnel "
            "fails with the kill switch on, this machine loses internet and can't reach PIA to fix it. "
            "See watchdog/README.md.")


def load_state(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"unhealthy_checks": 0, "replacements": []}


def save_state(path, state):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


def decide(state, healthy, config, now):
    """Pure decision step: returns (action, state) with action one of
    "healthy", "waiting", "replace", "capped"."""
    state = dict(state)
    recent = [t for t in state.get("replacements", []) if now - t < DAY_SECONDS]
    state["replacements"] = recent
    if healthy:
        state["unhealthy_checks"] = 0
        return "healthy", state
    state["unhealthy_checks"] = state.get("unhealthy_checks", 0) + 1
    if state["unhealthy_checks"] < config["unhealthy_checks_before_replacing"]:
        return "waiting", state
    if len(recent) >= config["max_replacements_per_day"]:
        return "capped", state
    return "replace", state


def describe_router_error(e):
    if isinstance(e, router_push.MfaRequiredError):
        return "Router login needs a verification code. Use a local-only router account (see watchdog/README.md)."
    return f"Router: {e}"


def check_pia_login(config, state, now):
    """Confirms the stored PIA password still works. Returns an exit code."""
    try:
        pia_config.fetch_token(config["pia_username"], read_secret("pia_password"))
    except RuntimeError as e:
        log(f"{e}. Re-run the installer to update the stored PIA password.")
        return 1
    except OSError as e:
        log(f"Couldn't reach PIA to check the login: {e}")
        return 1
    state["pia_login_checked_at"] = now
    return 0


def plan_alert(state, event, now, config):
    """Pure decision step: returns (email subject or None, state). state["alert"]
    is the open alert the user was last emailed about."""
    state = dict(state)
    alert = state.pop("alert", None)
    if event == "replaced":
        state["alert"] = {"event": event, "since": now, "sent_at": now}
        return f"Switched the VPN to server {state['last_server_ip']}, checking it connects", state
    if event == "healthy":
        if alert is None:
            return None, state
        if alert["event"] == "replaced":
            return f"VPN connected on server {state.get('last_server_ip')}", state
        return f"Resolved: {ALERTS[alert['event']]}", state
    if event not in ALERTS:  # waiting: give it a few more checks
        if alert:
            state["alert"] = alert
        return None, state
    same = alert is not None and alert["event"] == event
    if same and now - alert["sent_at"] < config["alert_reminder_hours"] * 3600:
        state["alert"] = alert
        return None, state
    state["alert"] = {"event": event, "since": alert["since"] if same else now, "sent_at": now}
    return ("Still: " if same else "") + ALERTS[event], state


def send_email(config, subject, body):
    msg = EmailMessage()
    msg["Subject"] = f"PIA watchdog: {subject}"
    msg["From"] = config.get("smtp_username") or config["alert_email"]
    msg["To"] = config["alert_email"]
    msg.set_content(f"{body}\n\n(pia-watchdog on {socket.gethostname()}; logs: journalctl -u pia-watchdog)\n")
    password = read_secret("smtp_password")
    if config["smtp_server"] == "smtp.gmail.com":
        password = password.replace(" ", "")  # Gmail shows app passwords in groups of four
    context = ssl.create_default_context()
    implicit_tls = config["smtp_port"] == 465
    smtp_class = smtplib.SMTP_SSL if implicit_tls else smtplib.SMTP
    with smtp_class(config["smtp_server"], config["smtp_port"], timeout=30,
                    **({"context": context} if implicit_tls else {})) as smtp:
        if not implicit_tls:
            smtp.starttls(context=context)
        smtp.login(msg["From"], password)
        smtp.send_message(msg)


def send_alert(config, state, event, now):
    """Emails about this run's event if needed. Returns the new state; if the
    email fails, the old one, so the next run tries again."""
    if not config.get("alert_email"):
        return state
    subject, new_state = plan_alert(state, event, now, config)
    if subject is None:
        return new_state
    try:
        send_email(config, subject, "\n".join(run_log))
    except (OSError, RuntimeError) as e:
        log(f"Couldn't send the alert email: {e}")
        return state
    return new_state


def verify(config):
    """Checks both logins and reports the client's status, changing nothing."""
    ok = True
    try:
        opener, csrf = router_push.login(config["router_url"], config["router_username"], read_secret("router_password"))
        log(f"Router login OK ({config['router_username']} at {config['router_url']}).")
        client = router_push.find_wireguard_client(opener, csrf, config["router_url"], config["client_name"])
        if client is None:
            log(f"No WireGuard VPN client named {config['client_name']!r} on the router.")
            ok = False
        else:
            _, detail = router_push.wireguard_client_health(opener, csrf, config["router_url"], client)
            log(f"VPN client {config['client_name']!r}: {detail}.")
            warn_if_routed_through(opener, csrf, config, client)
    except (router_push.RouterLoginError, router_push.RouterPushError) as e:
        log(describe_router_error(e))
        ok = False
    if check_pia_login(config, {}, 0) == 0:
        log(f"PIA login OK ({config['pia_username']}).")
    else:
        ok = False
    if config.get("alert_email"):
        try:
            send_email(config, "Test email", "Email alerts work. You'll hear from the watchdog when it replaces "
                       "the VPN config, when the new one connects, and when something needs your attention.")
            log(f"Sent a test email to {config['alert_email']}.")
        except (OSError, RuntimeError) as e:
            log(f"Couldn't send the test email: {e}")
            ok = False
    return 0 if ok else 1


def check_once(config, state, now, replace_now=False):
    """Returns (event, state), event being one of "healthy", "waiting",
    "replaced", or an ALERTS key. replace_now skips the health check, the
    threshold, and dry-run mode, and replaces immediately."""
    opener, csrf = router_push.login(config["router_url"], config["router_username"], read_secret("router_password"))
    client = router_push.find_wireguard_client(opener, csrf, config["router_url"], config["client_name"])
    if client is None:
        log(f"No WireGuard VPN client named {config['client_name']!r} on the router.")
        return "no_client", state
    warn_if_routed_through(opener, csrf, config, client)

    threshold = config["unhealthy_checks_before_replacing"]
    if replace_now:
        action, detail = "replace", "replacement requested with --replace-now"
        config = {**config, "dry_run": False}
    else:
        healthy, detail = router_push.wireguard_client_health(opener, csrf, config["router_url"], client)
        action, state = decide(state, healthy, config, now)

    if action in ("healthy", "waiting"):
        log(f"Healthy: {detail}" if action == "healthy"
            else f"Unhealthy ({state['unhealthy_checks']}/{threshold}): {detail}")
        # Daily, so a changed or mistyped PIA password surfaces before it's needed.
        due = now - state.get("pia_login_checked_at", 0) >= DAY_SECONDS
        return ("pia_login" if due and check_pia_login(config, state, now) else action), state
    if action == "capped":
        log(f"Unhealthy ({detail}), but already replaced {len(state['replacements'])} time(s) "
            f"in the last 24h (max {config['max_replacements_per_day']}). Not replacing again.")
        return "capped", state

    current_ip = endpoint_ip(client.get("wireguard_client_configuration_file")) or state.get("last_server_ip")
    if config["dry_run"]:
        if check_pia_login(config, state, now):
            return "pia_login", state
        log(f"Unhealthy for {threshold} checks ({detail}). Dry run: would generate a new "
            f"{config['region_id']} config avoiding {current_ip} and update {config['client_name']!r}. "
            f"PIA login OK.")
        state["unhealthy_checks"] = 0
        return "dry_run", state

    conf, region_name, server_ip = pia_config.generate_conf(
        config["pia_username"], read_secret("pia_password"), config["region_id"],
        config["include_dns"], avoid_server_ip=current_ip,
    )
    router_push.update_wireguard_client(
        opener, csrf, config["router_url"], client, conf, f"pia-{config['region_id']}.conf"
    )
    state.update(unhealthy_checks=0, last_server_ip=server_ip, pia_login_checked_at=now)
    state["replacements"] = state.get("replacements", []) + [now]
    log(f"Replaced {config['client_name']!r} with a new {region_name} config on {server_ip} "
        f"(was {current_ip}). Unhealthy reason: {detail}")
    return "replaced", state


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, help="JSON config file (see watchdog/README.md)")
    parser.add_argument("--list-regions", action="store_true", help="print PIA region ids and exit")
    parser.add_argument("--replace-now", action="store_true",
                        help="replace the config immediately, even in dry-run mode (use watchdog/replace-now.sh)")
    parser.add_argument("--verify", action="store_true",
                        help="check the router and PIA logins, change nothing (use watchdog/verify.sh)")
    args = parser.parse_args()

    if args.list_regions:
        for r in sorted(pia_config.fetch_regions(), key=lambda r: (r.get("country") != "US", r["name"])):
            print(f"{r['id']:<28} {r['name']}")
        return 0
    if not args.config:
        parser.error("--config is required")

    config = {**DEFAULTS, **json.loads(args.config.read_text(encoding="utf-8"))}
    if args.verify:
        return verify(config)
    state_path = Path(os.environ.get("STATE_DIRECTORY", ".")) / "state.json"
    state = load_state(state_path)
    now = time.time()
    try:
        event, state = check_once(config, state, now, replace_now=args.replace_now)
    except (router_push.RouterLoginError, router_push.RouterPushError) as e:
        log(describe_router_error(e))
        event = "router_error"
    except (RuntimeError, OSError) as e:
        log(f"Error: {e}")
        event = "error"
    save_state(state_path, send_alert(config, state, event, now))
    return 1 if event in FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
