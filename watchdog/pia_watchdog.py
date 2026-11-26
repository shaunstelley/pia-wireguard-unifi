#!/usr/bin/env python3
"""Replace the router's PIA WireGuard config when it stops connecting.

Run once per invocation (a systemd timer calls it every few minutes). Secrets
come from systemd's encrypted credentials ($CREDENTIALS_DIRECTORY); see
watchdog/README.md.
"""

import argparse
import imaplib
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import time
import traceback
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui"))
import pia_config  # noqa: E402
import router_push  # noqa: E402
import region_reply  # noqa: E402

DAY_SECONDS = 24 * 60 * 60
HISTORY_DAYS = 30
DEFAULTS = {
    "include_dns": True,
    "dry_run": True,
    "unhealthy_checks_before_replacing": 3,
    "recheck_seconds": 60,
    "max_failed_replacements": 3,
    "stable_connection_minutes": 10,
    "retry_minutes_after_failed_replacements": 60,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 465,
    "alert_reminder_hours": 6,
    "router_errors_before_alert": 2,
    "region_menu_hours": 24,
}

# Run results worth an email, with their subjects. Each one opens an alert
# that's repeated every alert_reminder_hours while it lasts and closed by an
# all-clear email on the next healthy check. FAILED ones also fail the run.
ALERTS = {
    "capped": "VPN is down and new servers aren't fixing it",
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
        return {"unhealthy_checks": 0}


def save_state(path, state):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


def decide(state, healthy, config, now):
    """Pure decision step: returns (action, state) with action one of
    "healthy", "waiting", "replace", "capped"."""
    state = dict(state)
    state["replacements"] = [t for t in state.get("replacements", []) if now - t < HISTORY_DAYS * DAY_SECONDS]
    if healthy:
        state["unhealthy_checks"] = 0
        # A replacement only counts as having worked once it has held for a while.
        connected_since = state.setdefault("connected_since", now)
        if now - connected_since >= config["stable_connection_minutes"] * 60:
            state["failed_replacements"] = 0
        return "healthy", state
    state.pop("connected_since", None)
    state["unhealthy_checks"] = state.get("unhealthy_checks", 0) + 1
    if state["unhealthy_checks"] < config["unhealthy_checks_before_replacing"]:
        return "waiting", state
    retry_at = state.get("last_replacement_at", 0) + config["retry_minutes_after_failed_replacements"] * 60
    if state.get("failed_replacements", 0) >= config["max_failed_replacements"] and now < retry_at:
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


def plan_alert(state, event, now, config, messages=()):
    """Pure decision step: returns (email subject or None, state). state["alert"]
    is the open alert: what the user was last emailed about, or replacements
    still waiting to prove themselves, with their messages for the next email."""
    state = dict(state)
    alert = state.pop("alert", None)
    if event == "replaced":
        if alert and alert["event"] == "capped":  # a slow retry during an outage they know about
            state["alert"] = alert
            return None, state
        pending = alert.get("log", []) if alert and alert["event"] == "replaced" else []
        state["alert"] = {"event": event, "since": now, "sent_at": now, "log": pending + list(messages)}
        return None, state  # the next check decides what to say
    if event == "healthy":
        if alert is None:
            return None, state
        if alert["event"] == "replaced":
            return f"VPN reconnected on server {state.get('last_server_ip')}", state
        return f"Resolved: {ALERTS[alert['event']]}", state
    # A single router error is usually the router restarting, so wait for the next check.
    early_router_error = event == "router_error" and state.get("router_errors", 0) < config["router_errors_before_alert"]
    if event not in ALERTS or early_router_error:  # waiting: give it a few more checks
        if alert:
            state["alert"] = alert
        return None, state
    same = alert is not None and alert["event"] == event
    if same and now - alert["sent_at"] < config["alert_reminder_hours"] * 3600:
        state["alert"] = alert
        return None, state
    state["alert"] = {"event": event, "since": alert["since"] if same else now, "sent_at": now}
    return ("Still: " if same else "") + ALERTS[event], state


def describe_duration(seconds):
    if seconds < 2 * 60 * 60:
        return f"{round(seconds / 60)} minutes"
    if seconds < 2 * DAY_SECONDS:
        return f"{round(seconds / 3600)} hours"
    return f"{round(seconds / DAY_SECONDS)} days"


def replacement_stats(state, now):
    """How often replacements have been needed, for the alert email. Manual ones aren't counted."""
    times = sorted(state.get("replacements", []))
    counts = [f"{sum(now - t < days * DAY_SECONDS for t in times)} in the last {label}"
              for days, label in ((1, "24 hours"), (7, "7 days"), (HISTORY_DAYS, f"{HISTORY_DAYS} days"))]
    lines = [f"Replacements needed: {', '.join(counts)}."]
    if len(times) > 1:
        lines.append(f"Time between the last two: {describe_duration(times[-1] - times[-2])}. "
                     f"Average time between them: {describe_duration((times[-1] - times[0]) / (len(times) - 1))}.")
    return "\n".join(lines)


def email_account(config):
    return config.get("smtp_username") or config["alert_email"]


def email_password(config):
    password = read_secret("smtp_password")
    if config["smtp_server"] == "smtp.gmail.com":
        password = password.replace(" ", "")  # Gmail shows app passwords in groups of four
    return password


def imap_server(config):
    """Where replies to the alerts are read from, or None if that isn't set up."""
    if config.get("imap_server"):
        return config["imap_server"]
    return "imap.gmail.com" if config["smtp_server"] == "smtp.gmail.com" else None


def send_email(config, subject, body):
    """Sends an email and returns its Message-ID."""
    msg = EmailMessage()
    msg["Subject"] = f"PIA watchdog: {subject}"
    msg["From"] = email_account(config)
    msg["To"] = config["alert_email"]
    msg["Message-ID"] = make_msgid(domain=msg["From"].rsplit("@", 1)[-1])
    msg.set_content(f"{body}\n\n(pia-watchdog on {socket.gethostname()}; logs: journalctl -u pia-watchdog)\n")
    password = email_password(config)
    context = ssl.create_default_context()
    implicit_tls = config["smtp_port"] == 465
    smtp_class = smtplib.SMTP_SSL if implicit_tls else smtplib.SMTP
    with smtp_class(config["smtp_server"], config["smtp_port"], timeout=30,
                    **({"context": context} if implicit_tls else {})) as smtp:
        if not implicit_tls:
            smtp.starttls(context=context)
        smtp.login(msg["From"], password)
        smtp.send_message(msg)
    return msg["Message-ID"]


def notify(config, subject, body):
    """A one-off email, outside the alert cycle. Failures are only logged."""
    try:
        send_email(config, subject, body)
    except (OSError, RuntimeError) as e:
        log(f"Couldn't send the email: {e}")


def region_menu(config):
    """(menu text, its region ids) for the "new servers aren't fixing it"
    email, or (None, None) if there's nothing to offer."""
    try:
        regions = pia_config.fetch_regions()
        menu = region_reply.build_menu(regions, region_reply.measure(regions), config["region_id"])
    except (OSError, ValueError, KeyError) as e:
        log(f"Couldn't list other regions for the email: {e}")
        return None, None
    if not menu:
        return None, None
    current = next((r["name"] for r in regions if r["id"] == config["region_id"]), config["region_id"])
    return region_reply.menu_text(menu, current, config["region_menu_hours"]), [m[0] for m in menu]


def remember_menu(state, message_id, options, now, config):
    keep = config["region_menu_hours"] * 3600
    menus = [m for m in state.get("region_menus", []) if now - m["sent_at"] < keep]
    return {**state, "region_menus": menus + [{"message_id": message_id, "options": options, "sent_at": now}]}


def send_alert(config, state, event, now):
    """Emails about this run's event if needed. Returns the new state; if the
    email fails, the old one, so the next run tries again."""
    if not config.get("alert_email"):
        return state
    subject, new_state = plan_alert(state, event, now, config, run_log)
    if subject is None:
        return new_state
    messages = state.get("alert", {}).get("log", []) + run_log
    sections = ["\n".join(messages)]
    options = None
    if event == "capped" and imap_server(config):
        menu, options = region_menu(config)
        if menu:
            sections.append(menu)
    body = "\n\n".join(sections + [replacement_stats(state, now)])
    try:
        message_id = send_email(config, subject, body)
    except (OSError, RuntimeError) as e:
        log(f"Couldn't send the alert email: {e}")
        return state
    return remember_menu(new_state, message_id, options, now, config) if options else new_state


def with_region_override(config, state):
    """The config with the region chosen by email, unless region_id in the
    config file has changed since (a manual edit wins)."""
    override = state.get("region_override")
    if override and override.get("base") == config["region_id"]:
        return {**config, "region_id": override["id"]}
    return config


def check_region_replies(config, state, now):
    """Looks for a reply to a recent region menu. Returns (state, region id
    asked for or None). Replies that fail the sender check, or that can't be
    read as a region, are logged and skipped, and each reply is acted on once."""
    keep = config["region_menu_hours"] * 3600
    menus = [m for m in state.get("region_menus", []) if now - m["sent_at"] < keep]
    state = {k: v for k, v in state.items() if k != "region_menus"}
    if not menus:
        return state, None
    state["region_menus"] = menus
    if not config.get("alert_email") or not imap_server(config):
        return state, None
    try:
        replies = region_reply.fetch_replies(imap_server(config), email_account(config), email_password(config),
                                             config["alert_email"], min(m["sent_at"] for m in menus))
    except (OSError, imaplib.IMAP4.error) as e:
        log(f"Couldn't check for replies to the region email: {e}")
        return state, None
    seen = list(state.get("seen_replies", []))
    regions = None
    for msg in replies:
        reply_id = msg.get("Message-ID", "")
        menu_id = region_reply.answers(msg, [m["message_id"] for m in menus])
        if menu_id is None or reply_id in seen:
            continue
        seen.append(reply_id)
        state["seen_replies"] = seen[-50:]
        if not region_reply.trusted_sender(msg, config["alert_email"]):
            log(f"Ignored a reply that says it's from {config['alert_email']} but failed the sender check.")
            continue
        text = region_reply.first_line(msg)
        regions = regions if regions is not None else pia_config.fetch_regions()
        options = next(m["options"] for m in menus if m["message_id"] == menu_id)
        choice = region_reply.parse_choice(text, options, regions)
        if choice is None:
            log(f"Couldn't tell which region the reply {text!r} means.")
            notify(config, "Couldn't read your reply",
                   f"Your reply said {text!r}. Reply to the region email again with one of its numbers, "
                   "or a region's name or id. Nothing has changed.")
            continue
        return state, choice
    return state, None


def switch_region(file_config, config, state, region_id, now):
    """Switches to the region asked for by email and replaces the config right
    away. file_config is the config as written, config the one in effect."""
    state = {k: v for k, v in state.items() if k != "region_menus"}  # answered
    name = next((r["name"] for r in pia_config.fetch_regions() if r["id"] == region_id), region_id)
    if region_id == config["region_id"]:
        log(f"The reply asked for {name}, which is already in use, so nothing changed.")
        notify(config, f"Already using {name}", f"You asked for {name}, which the watchdog already uses. "
               "Nothing changed.")
        return check_once(config, state, now)
    if region_id == file_config["region_id"]:
        state.pop("region_override", None)
    else:
        state["region_override"] = {"id": region_id, "base": file_config["region_id"]}
    state["failed_replacements"] = 0
    log(f"Switching to {name}, as asked by email.")
    event, state = check_once({**config, "region_id": region_id}, state, now, replace_now=True)
    if event == "replaced":
        notify(config, f"Switched to {name}",
               f"As you asked, the VPN is now set up for {name} (server {state.get('last_server_ip')}). "
               f"You'll get an email when it connects. Reply \"{file_config['region_id']}\" to a later region "
               "email to go back to the configured region, or change region_id in the config file.")
    return event, state


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
    "paused", "replaced", or an ALERTS key. replace_now skips the health check, the
    threshold, and dry-run mode, and replaces immediately."""
    opener, csrf = router_push.login(config["router_url"], config["router_username"], read_secret("router_password"))
    client = router_push.find_wireguard_client(opener, csrf, config["router_url"], config["client_name"])
    if client is None:
        log(f"No WireGuard VPN client named {config['client_name']!r} on the router.")
        return "no_client", state
    warn_if_routed_through(opener, csrf, config, client)
    if client.get("enabled") is False and not replace_now:
        # Paused by hand in the Network app. A paused client never connects, so
        # replacing it would only burn through servers. Start fresh when it's resumed.
        log(f"VPN client {config['client_name']!r} is paused on the router, so leaving it alone.")
        state = {**state, "unhealthy_checks": 0, "failed_replacements": 0}
        state.pop("connected_since", None)
        return "paused", state

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
        log(f"Unhealthy ({detail}). The last {state.get('failed_replacements', 0)} replacements didn't stay connected "
            f"for {config['stable_connection_minutes']} minutes, so this may be more than one bad server. "
            f"Trying a new one every {config['retry_minutes_after_failed_replacements']} minutes.")
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
    state.update(unhealthy_checks=0, last_server_ip=server_ip, pia_login_checked_at=now, last_replacement_at=now,
                 failed_replacements=state.get("failed_replacements", 0) + 1)
    state.pop("connected_since", None)
    if not replace_now:
        state["replacements"] = state.get("replacements", []) + [now]
    if server_ip == current_ip:
        log(f"No other server in the region took the new key, so this reuses {server_ip}.")
    log(f"Replaced {config['client_name']!r} with a new {region_name} config on {server_ip} "
        f"(was {current_ip}). Unhealthy reason: {detail}")
    return "replaced", state


def send_region_menu(config, state, state_path):
    """Emails the region list on request. A reply to it works like one to an alert."""
    if not config.get("alert_email") or not imap_server(config):
        log("Email alerts, and replies to them, aren't set up.")
        return 1
    menu, options = region_menu(config)
    if not menu:
        log("No other regions answered, so there's nothing to offer.")
        return 1
    now = time.time()
    message_id = send_email(config, "Switch regions by replying", menu)
    save_state(state_path, remember_menu(state, message_id, options, now, config))
    log(f"Sent the region list to {config['alert_email']}.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, help="JSON config file (see watchdog/README.md)")
    parser.add_argument("--list-regions", action="store_true", help="print PIA region ids and exit")
    parser.add_argument("--replace-now", action="store_true",
                        help="replace the config immediately, even in dry-run mode (use watchdog/replace-now.sh)")
    parser.add_argument("--verify", action="store_true",
                        help="check the router and PIA logins, change nothing (use watchdog/verify.sh)")
    parser.add_argument("--send-region-menu", action="store_true",
                        help="email the region list now, to try switching by reply (use watchdog/sandboxed.sh)")
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
    file_config, config = config, with_region_override(config, state)
    if args.send_region_menu:
        return send_region_menu(config, state, state_path)
    try:
        state, choice = check_region_replies(config, state, time.time())
        if choice is not None:
            event, state = switch_region(file_config, config, state, choice, time.time())
            config = with_region_override(file_config, state)
        else:
            event, state = check_once(config, state, time.time(), replace_now=args.replace_now)
        # After a failed check, don't wait for the timer to count the next ones.
        while event == "waiting" and config["recheck_seconds"]:
            time.sleep(config["recheck_seconds"])
            event, state = check_once(config, state, time.time())
    except (router_push.RouterLoginError, router_push.RouterPushError) as e:
        log(describe_router_error(e))
        event = "router_error"
    except (RuntimeError, OSError) as e:
        log(f"Error: {e}")
        event = "error"
    except Exception:  # a bug, but the alert still has to go out
        log(f"Unexpected error:\n{traceback.format_exc()}")
        event = "error"
    state = dict(state)
    if event == "router_error":
        state["router_errors"] = state.get("router_errors", 0) + 1
    else:
        state.pop("router_errors", None)
    save_state(state_path, send_alert(config, state, event, time.time()))
    return 1 if event in FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
