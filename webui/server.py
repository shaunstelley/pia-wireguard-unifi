#!/usr/bin/env python3
"""Local web UI for generating a PIA WireGuard client config (no manual editing needed)."""

import json
import re
import shlex
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

import router_push
from pia_config import fetch_regions, generate_conf

PORT = 8765
# How long a router login session (opener + CSRF token) is reused for
# without asking to log in again. Kept short since it's live auth material
# for the router; exists at all only because an SSO account's MFA code is
# one-time-use, so each router call after connecting can't log in afresh.
ROUTER_SESSION_TTL_SECONDS = 600
ALLOWED_HOSTS = {f"localhost:{PORT}", f"127.0.0.1:{PORT}"}
ALLOWED_ORIGINS = {f"http://{host}" for host in ALLOWED_HOSTS}
# Same default as get_region.sh's MAX_LATENCY=0.05 (50ms) — a server slower than
# this is treated as unreachable rather than just "slow". User-adjustable in the UI.
DEFAULT_LATENCY_MS = 50
MIN_LATENCY_MS = 1
MAX_LATENCY_MS = 10000
INDEX_HTML = Path(__file__).resolve().parent / "index.html"
VALIDATE_HELPER = Path(__file__).resolve().parent / "validate_helper.sh"


def measure_latency(ip, port=443, timeout_ms=DEFAULT_LATENCY_MS):
    """TCP-connect latency, in ms. Same idea as get_region.sh's printServerLatency:
    a raw connect time to the region's meta server, no auth or PIA login involved."""
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout_ms / 1000):
            return round((time.monotonic() - start) * 1000)
    except OSError:
        return None


def fetch_regions_with_latency(timeout_ms=DEFAULT_LATENCY_MS):
    regions = fetch_regions()
    with ThreadPoolExecutor(max_workers=40) as pool:
        latencies = list(
            pool.map(lambda r: measure_latency(r["servers"]["meta"][0]["ip"], timeout_ms=timeout_ms), regions)
        )
    result = [
        {
            "id": r["id"],
            "name": r["name"],
            "country": r.get("country"),
            "port_forward": r.get("port_forward", False),
            "latency_ms": latency,
        }
        for r, latency in zip(regions, latencies)
    ]
    result.sort(key=lambda r: (r["latency_ms"] is None, r["latency_ms"]))
    return result


def run_admin(args, timeout=90):
    """Run a command with macOS admin privileges via the native GUI/Touch ID
    authorization dialog, instead of a terminal `sudo` prompt. The password is
    handled entirely by macOS's own Security Server — it never passes through
    this process, the browser, or any HTTP request."""
    shell_cmd = " ".join(shlex.quote(str(a)) for a in args)
    as_escaped = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')
    script = f'do shell script "{as_escaped}" with administrator privileges'
    return subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=timeout)


def validate_conf(conf_text):
    """Bring conf_text up as a real local WireGuard interface, force a packet
    so the lazy WireGuard handshake actually happens, confirm it via `wg show
    latest-handshakes`, then always tear the interface back down. This is the
    only way to actually prove a config connects — there's no way to check a
    handshake without establishing one. The whole sequence runs as one script
    (validate_helper.sh) behind a single admin-privileges prompt."""
    # wg-quick requires the config's basename (minus .conf) to be a valid
    # interface name: 1-15 chars matching [a-zA-Z0-9_=+.-]. "pia-" + 8 hex
    # chars (12 total) fits with room to spare — a mkstemp-style random
    # suffix on a "pia-validate-" prefix does not (21+ chars).
    iface = "pia-" + uuid.uuid4().hex[:8]
    conf_path = str(Path(tempfile.gettempdir()) / f"{iface}.conf")
    Path(conf_path).write_text(conf_text, encoding="utf-8")
    try:
        result = run_admin(["bash", str(VALIDATE_HELPER), conf_path, iface])
        if "User canceled" in (result.stderr or ""):
            return False, "Cancelled — the admin authorization prompt was dismissed."
        if result.returncode != 0:
            return False, "wg-quick up failed:\n" + (result.stderr or result.stdout or "unknown error")

        match = re.search(r"^\S+\t(\d+)\s*$", result.stdout, re.MULTILINE)
        handshake_ts = int(match.group(1)) if match else 0
        warning = next((l for l in result.stdout.splitlines() if l.startswith("WARNING")), None)

        if handshake_ts > 0:
            age = time.time() - handshake_ts
            message = f"Handshake confirmed ({age:.1f}s ago) — this config connects."
            return True, message + (f"\n{warning}" if warning else "")
        message = "wg-quick came up but no handshake was seen — the server may not be responding."
        return False, message + (f"\n{warning}" if warning else "")
    finally:
        Path(conf_path).unlink(missing_ok=True)


# In-memory only, single-user localhost tool -- never written to disk. Holds
# at most one session (a fresh login replaces it). Guarded by a lock since
# ThreadingHTTPServer handles requests concurrently.
_router_session_lock = threading.Lock()
_router_session = None  # {"opener", "csrf_token", "base_url", "expires_at"}


def _stash_router_session(opener, csrf_token, base_url):
    global _router_session
    with _router_session_lock:
        _router_session = {
            "opener": opener,
            "csrf_token": csrf_token,
            "base_url": base_url,
            "expires_at": time.time() + ROUTER_SESSION_TTL_SECONDS,
        }


def _get_router_session():
    with _router_session_lock:
        if _router_session and _router_session["expires_at"] > time.time():
            return _router_session
        return None


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, content_type="text/plain; charset=utf-8", extra_headers=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _refuse_foreign_request(self, post):
        # Stops other sites' pages (and DNS rebinding) from using this server and its stashed router session.
        # JSON-only POSTs force a CORS preflight, which this server never answers.
        reason = None
        if self.headers.get("Host") not in ALLOWED_HOSTS:
            reason = "Unexpected Host header."
        elif post:
            origin = self.headers.get("Origin")
            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if origin is not None and origin not in ALLOWED_ORIGINS:
                reason = "Cross-origin request refused."
            elif content_type != "application/json":
                reason = "Expected Content-Type: application/json."
        if reason:
            self._send(403, reason)
            return True
        return False

    def do_GET(self):
        if self._refuse_foreign_request(post=False):
            return
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            self._send(200, INDEX_HTML.read_text(encoding="utf-8"), "text/html; charset=utf-8")
        elif parsed.path == "/api/regions":
            try:
                params = parse_qs(parsed.query)
                try:
                    timeout_ms = float(params.get("maxLatencyMs", [DEFAULT_LATENCY_MS])[0])
                except ValueError:
                    timeout_ms = DEFAULT_LATENCY_MS
                timeout_ms = max(MIN_LATENCY_MS, min(timeout_ms, MAX_LATENCY_MS))
                payload = json.dumps(fetch_regions_with_latency(timeout_ms))
                self._send(200, payload, "application/json")
            except Exception as e:
                self._send(502, f"Could not fetch region list: {e}")
        elif parsed.path == "/api/router/targets":
            self._handle_router_targets()
        else:
            self._send(404, "Not found")

    def _send_needs_login(self):
        self._send(
            200,
            json.dumps({"ok": False, "needsLogin": True, "message": "Connect to the router first (step 2) — the session may have expired."}),
            "application/json",
        )

    def _handle_router_targets(self):
        # Networks + devices available to route through a WireGuard client,
        # for the "route traffic through this VPN" picker.
        session = _get_router_session()
        if session is None:
            self._send_needs_login()
            return
        try:
            networks = router_push.list_networks(session["opener"], session["csrf_token"], session["base_url"])
            devices = router_push.list_devices(session["opener"], session["csrf_token"], session["base_url"])
            self._send(200, json.dumps({"ok": True, "networks": networks, "devices": devices}), "application/json")
        except router_push.RouterPushError as e:
            self._send(200, json.dumps({"ok": False, "message": str(e)}), "application/json")

    def do_POST(self):
        if self._refuse_foreign_request(post=True):
            return
        if self.path == "/api/generate":
            self._handle_generate()
        elif self.path == "/api/router/login":
            self._handle_router_login()
        elif self.path == "/api/router/push/preview":
            self._handle_router_push(apply=False)
        elif self.path == "/api/router/push/apply":
            self._handle_router_push(apply=True)
        else:
            self._send(404, "Not found")

    def _handle_generate(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            conf, region_name, _server_ip = generate_conf(
                body["username"],
                body["password"],
                body["region"],
                bool(body.get("includeDns", True)),
            )
            test = None
            if body.get("test", True):
                # Test the exact file we're about to hand back — not a separately
                # generated twin — so a pass/fail actually describes this artifact.
                test_ok, test_message = validate_conf(conf)
                test = {"ok": test_ok, "message": test_message}
            payload = json.dumps(
                {
                    "conf": conf,
                    "filename": f"pia-{body['region']}.conf",
                    "regionName": region_name,
                    "test": test,
                }
            )
            self._send(200, payload, "application/json")
        except Exception as e:
            self._send(400, json.dumps({"error": str(e)}), "application/json")

    def _handle_router_login(self):
        # Doesn't change router config by itself. On success, stashes the
        # session in memory so listing targets and pushing don't need a fresh
        # login each (an SSO account's MFA code is one-time-use).
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            router_url = body["routerUrl"]
            try:
                opener, csrf_token = router_push.login(
                    router_url,
                    body["username"],
                    body["password"],
                    mfa_token=body.get("mfaToken", ""),
                )
                _stash_router_session(opener, csrf_token, router_url)
                result = {"ok": True, "message": f"Connected to {router_url}."}
            except router_push.MfaRequiredError as e:
                result = {"ok": False, "mfaRequired": True, "message": str(e)}
            except router_push.RouterLoginError as e:
                result = {"ok": False, "message": str(e)}
            self._send(200, json.dumps(result), "application/json")
        except Exception as e:
            self._send(400, json.dumps({"error": str(e)}), "application/json")

    def _route_targets_from_request(self, route):
        # {"type": "NETWORK"|"CLIENT", "id"|"mac": ...} (as the UI sends it)
        # -> router_push's {"type": ..., "network_id"|"client_mac": ...}
        targets = []
        for t in (route or {}).get("targets", []):
            if t.get("type") == "NETWORK":
                targets.append({"type": "NETWORK", "network_id": t["id"]})
            elif t.get("type") == "CLIENT":
                targets.append({"type": "CLIENT", "client_mac": t["mac"]})
        return targets

    def _handle_router_push(self, apply):
        # apply=False returns the exact request(s) that apply=True would send,
        # built by the same functions, for the UI's "request details" view.
        # `route` is optional: when present, the new client also gets a
        # trafficroutes entry for the given networks/devices.
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            session = _get_router_session()
            if session is None:
                self._send_needs_login()
                return

            conf = body["conf"]
            filename = body["filename"]
            name = body.get("name") or filename
            targets = self._route_targets_from_request(body.get("route"))
            base_url = session["base_url"].rstrip("/")

            if not apply:
                client_payload = router_push.build_wireguard_client_payload(conf, filename, name)
                preview = {
                    "method": "POST",
                    "url": f"{base_url}/proxy/network/api/s/default/rest/networkconf",
                    "body": client_payload,
                }
                route_preview = None
                if targets:
                    route_payload = router_push.build_traffic_route_payload(
                        name, "<new client's id, assigned by the router>", targets
                    )
                    route_preview = {
                        "method": "POST",
                        "url": f"{base_url}/proxy/network/v2/api/site/default/trafficroutes",
                        "body": route_payload,
                    }
                result = {"ok": True, "preview": preview, "routePreview": route_preview}
            else:
                try:
                    created = router_push.apply_wireguard_client(
                        session["opener"], session["csrf_token"], session["base_url"], conf, filename, name
                    )
                    result = {"ok": True, "message": f"Added to router as \"{created.get('name')}\".", "entry": created}
                    if targets:
                        try:
                            route = router_push.apply_traffic_route(
                                session["opener"], session["csrf_token"], session["base_url"], name, created["_id"], targets
                            )
                            result["message"] += f" Routed {len(targets)} network(s)/device(s) through it."
                            result["route"] = route
                        except router_push.RouterPushError as e:
                            result["routeError"] = str(e)
                            result["message"] += f" But routing failed: {e}"
                except router_push.RouterPushError as e:
                    result = {"ok": False, "message": str(e)}
            self._send(200, json.dumps(result), "application/json")
        except Exception as e:
            self._send(400, json.dumps({"error": str(e)}), "application/json")


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"PIA config generator running at http://127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
