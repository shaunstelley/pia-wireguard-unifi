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
import socket
import sys
import time
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
}


def log(message):
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


def check_once(config, state, now, replace_now=False):
    """Returns (exit_code, state). replace_now skips the health check, the
    threshold, and dry-run mode, and replaces immediately."""
    opener, csrf = router_push.login(config["router_url"], config["router_username"], read_secret("router_password"))
    client = router_push.find_wireguard_client(opener, csrf, config["router_url"], config["client_name"])
    if client is None:
        log(f"No WireGuard VPN client named {config['client_name']!r} on the router.")
        return 1, state
    warn_if_routed_through(opener, csrf, config, client)

    threshold = config["unhealthy_checks_before_replacing"]
    if replace_now:
        action, detail = "replace", "replacement requested with --replace-now"
        config = {**config, "dry_run": False}
    else:
        healthy, detail = router_push.wireguard_client_health(opener, csrf, config["router_url"], client)
        action, state = decide(state, healthy, config, now)

    if action == "healthy":
        log(f"Healthy: {detail}")
        return 0, state
    if action == "waiting":
        log(f"Unhealthy ({state['unhealthy_checks']}/{threshold}): {detail}")
        return 0, state
    if action == "capped":
        log(f"Unhealthy ({detail}), but already replaced {len(state['replacements'])} time(s) "
            f"in the last 24h (max {config['max_replacements_per_day']}). Not replacing again.")
        return 1, state

    current_ip = endpoint_ip(client.get("wireguard_client_configuration_file")) or state.get("last_server_ip")
    if config["dry_run"]:
        pia_config.fetch_token(config["pia_username"], read_secret("pia_password"))
        log(f"Unhealthy for {threshold} checks ({detail}). Dry run: would generate a new "
            f"{config['region_id']} config avoiding {current_ip} and update {config['client_name']!r}. "
            f"PIA login OK.")
        state["unhealthy_checks"] = 0
        return 0, state

    conf, region_name, server_ip = pia_config.generate_conf(
        config["pia_username"], read_secret("pia_password"), config["region_id"],
        config["include_dns"], avoid_server_ip=current_ip,
    )
    router_push.update_wireguard_client(
        opener, csrf, config["router_url"], client, conf, f"pia-{config['region_id']}.conf"
    )
    state.update(unhealthy_checks=0, last_server_ip=server_ip)
    state["replacements"] = state.get("replacements", []) + [now]
    log(f"Replaced {config['client_name']!r} with a new {region_name} config on {server_ip} "
        f"(was {current_ip}). Unhealthy reason: {detail}")
    return 0, state


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, help="JSON config file (see watchdog/README.md)")
    parser.add_argument("--list-regions", action="store_true", help="print PIA region ids and exit")
    parser.add_argument("--replace-now", action="store_true",
                        help="replace the config immediately, even in dry-run mode (use watchdog/replace-now.sh)")
    args = parser.parse_args()

    if args.list_regions:
        for r in sorted(pia_config.fetch_regions(), key=lambda r: (r.get("country") != "US", r["name"])):
            print(f"{r['id']:<28} {r['name']}")
        return 0
    if not args.config:
        parser.error("--config is required")

    config = {**DEFAULTS, **json.loads(args.config.read_text(encoding="utf-8"))}
    state_path = Path(os.environ.get("STATE_DIRECTORY", ".")) / "state.json"
    state = load_state(state_path)
    try:
        code, state = check_once(config, state, time.time(), replace_now=args.replace_now)
    except (router_push.RouterLoginError, router_push.RouterPushError, RuntimeError) as e:
        if isinstance(e, router_push.MfaRequiredError):
            log("Router login needs a verification code. Use a local-only router account (see watchdog/README.md).")
        else:
            log(f"Error: {e}")
        return 1
    save_state(state_path, state)
    return code


if __name__ == "__main__":
    sys.exit(main())
