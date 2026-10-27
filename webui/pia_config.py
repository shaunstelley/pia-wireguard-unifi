"""Generate a PIA WireGuard config. Shared by the web UI and the watchdog."""

import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONNECT_SCRIPT = REPO_ROOT / "connect_to_wireguard_with_token.sh"

SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
# Cloudflare (in front of both PIA hosts) answers Python's default
# "Python-urllib/3.x" User-Agent with a 403; curl's passes.
USER_AGENT = "curl/8.7.1"


def fetch_regions():
    req = urllib.request.Request(SERVERLIST_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as resp:
        first_line = resp.read().decode("utf-8").splitlines()[0]
    data = json.loads(first_line)
    return [r for r in data["regions"] if r.get("servers", {}).get("wg")]


def _multipart_body(fields):
    boundary = uuid.uuid4().hex
    lines = []
    for name, value in fields.items():
        lines += [f"--{boundary}", f'Content-Disposition: form-data; name="{name}"', "", value]
    lines += [f"--{boundary}--", ""]
    return "\r\n".join(lines).encode("utf-8"), f"multipart/form-data; boundary={boundary}"


def fetch_token(username, password):
    body, content_type = _multipart_body({"username": username, "password": password})
    req = urllib.request.Request(
        TOKEN_URL,
        data=body,
        method="POST",
        headers={"Content-Type": content_type, "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"PIA login failed: HTTP {e.code}")
    token = data.get("token")
    if not token:
        raise RuntimeError("PIA login failed: invalid username or password")
    return token


def _write_conf(token, server, include_dns):
    fd, conf_path = tempfile.mkstemp(prefix="pia-", suffix=".conf")
    os.close(fd)
    try:
        env = dict(os.environ)
        env.update(
            {
                "PIA_TOKEN": token,
                "WG_SERVER_IP": server["ip"],
                "WG_HOSTNAME": server["cn"],
                "PIA_CONNECT": "false",
                "PIA_DNS": "true" if include_dns else "false",
                "PIA_CONF_PATH": conf_path,
            }
        )
        result = subprocess.run(
            ["bash", str(CONNECT_SCRIPT)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout or "unknown error")
        return Path(conf_path).read_text(encoding="utf-8")
    finally:
        Path(conf_path).unlink(missing_ok=True)


def generate_conf(username, password, region_id, include_dns, avoid_server_ip=None):
    """Returns (conf_text, region_name, server_ip). Tries each of the region's
    WireGuard servers in turn, starting with any that isn't avoid_server_ip."""
    region = next((r for r in fetch_regions() if r["id"] == region_id), None)
    if region is None:
        raise RuntimeError(f"Unknown region: {region_id}")

    token = fetch_token(username, password)
    servers = region["servers"]["wg"]
    ordered = [s for s in servers if s["ip"] != avoid_server_ip] + [s for s in servers if s["ip"] == avoid_server_ip]
    errors = []
    for server in ordered:
        try:
            return _write_conf(token, server, include_dns), region["name"], server["ip"]
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            errors.append(f"{server['ip']}: {e}")
    raise RuntimeError("Config generation failed on every server in the region:\n" + "\n".join(errors))
