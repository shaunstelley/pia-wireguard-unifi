"""UniFi Network app (local controller) API client for pushing a generated
WireGuard config to a Dream Router's native VPN Client feature.

Both the auth flow (login) and the add-VPN-client call are confirmed
against a real Dream Router running UniFi OS, via two real HAR captures
(see HANDOFF.md). Neither matched the earlier reverse-engineered
github.com/tmcpro/unifi-network-api spec this was first based on:

- Login is POST /api/auth/login (not /api/login), needs a priming GET
  first (see login()'s docstring), and can require a second request with
  an MFA code for an SSO-linked account.
- Adding a WireGuard client is POST .../api/s/{site}/rest/networkconf --
  note this is the *older* REST-collection API style
  (/proxy/network/api/s/{site}/rest/{collection}), not the v2 API style
  seen for login and for listing VPN users (/proxy/network/v2/api/site/
  {site}/...). UniFi's Network app apparently mixes both per feature.
  The captured payload is refreshingly simple: the entire generated
  .conf text goes verbatim into wireguard_client_configuration_file --
  no need to parse out individual WireGuard fields.
"""

import http.cookiejar
import json
import ssl
import urllib.error
import urllib.request


class RouterLoginError(RuntimeError):
    pass


class RouterPushError(RuntimeError):
    pass


class MfaRequiredError(RouterLoginError):
    """Login needs a second call to login() with mfa_token set. authenticators
    is the account's enrolled MFA methods, as the server reported them, so a
    caller can decide what to prompt for. This client only actually drives
    a numeric-code method (email or TOTP, sent as the `token` field) -- not
    WebAuthn/passkey, which needs real browser credential-manager UI."""

    def __init__(self, message, authenticators=None):
        super().__init__(message)
        self.authenticators = authenticators or []


def login(base_url, username, password, mfa_token="", verify_tls=False, timeout=10):
    """Authenticate to the router's local Network app (UniFi OS console).

    Returns (opener, csrf_token): an urllib opener carrying the session
    cookie for use on subsequent requests, and the CSRF token string to send
    as a header on mutating calls. username/password/mfa_token are used only
    for this one request; this function does not persist them anywhere.

    Raises MfaRequiredError if the account needs a second call with
    mfa_token set (e.g. to a one-time code emailed to the account) -- call
    login() again with the same username/password plus that code.
    """
    base_url = base_url.rstrip("/")
    jar = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    if not verify_tls:
        # A Dream Router's local UI serves a self-signed cert by default --
        # there's no public CA to verify a LAN-only address against.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )

    # A bare login POST with no prior session gets rejected with a plain 401
    # rather than reaching the actual credential/MFA check -- confirmed via
    # a real captured login, whose request already carried a JSESSIONID
    # cookie set by an earlier, uncaptured page load. Prime one first.
    try:
        with opener.open(f"{base_url}/", timeout=timeout) as resp:
            resp.read()
    except urllib.error.HTTPError:
        # Set-Cookie is still processed on a non-2xx response, so this
        # doesn't mean priming failed.
        pass
    except urllib.error.URLError as e:
        raise RouterLoginError(f"Could not reach router at {base_url}: {e.reason}") from e

    body = json.dumps(
        {
            "username": username,
            "password": password,
            "token": mfa_token,
            "rememberMe": True,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/auth/login",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "*/*"},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            headers = resp.headers
            resp.read()
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        if payload.get("code") == "MFA_AUTH_REQUIRED":
            raise MfaRequiredError(
                "This account needs a verification code to finish logging in "
                "(check your email for a one-time code, then try again with it).",
                authenticators=payload.get("data", {}).get("authenticators", []),
            ) from e
        message = payload.get("message") or f"HTTP {e.code}"
        raise RouterLoginError(f"Login failed: {message}") from e
    except urllib.error.URLError as e:
        raise RouterLoginError(f"Could not reach router at {base_url}: {e.reason}") from e

    if status != 200:
        raise RouterLoginError(f"Login failed: HTTP {status}")

    # Seen as both x-csrf-token and x-updated-csrf-token on a real login
    # response (same value at login time; a mutating call's response may
    # only carry x-updated-csrf-token if the token rotates -- watch for
    # that header on every subsequent response and use its value going
    # forward instead of the one returned here).
    csrf_token = headers.get("X-Csrf-Token") or headers.get("X-Updated-Csrf-Token")
    if not csrf_token:
        for cookie in jar:
            if "csrf" in cookie.name.lower():
                csrf_token = cookie.value
                break
    if not csrf_token:
        raise RouterLoginError(
            "Login succeeded (HTTP 200) but no CSRF token was found in the response "
            "headers or cookies."
        )

    return opener, csrf_token


def _authed_request(opener, csrf_token, url, method="GET", body=None, timeout=15):
    """Shared plumbing for every authenticated call after login(): same
    headers, same error handling (HTTP errors surfaced with the router's own
    message when it has one, not just a bare status code)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json, text/plain, */*", "X-Csrf-Token": csrf_token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            payload_err = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload_err = {}
        message = payload_err.get("meta", {}).get("msg") or payload_err.get("message") or f"HTTP {e.code}"
        raise RouterPushError(f"Request to {url} failed: {message}") from e
    except urllib.error.URLError as e:
        raise RouterPushError(f"Could not reach {url}: {e.reason}") from e
    return json.loads(raw) if raw else {}


def list_networks(opener, csrf_token, base_url, site="default", timeout=15):
    """Networks available as a traffic-route target (type NETWORK).

    Not captured directly from a real UI action -- neither capture that
    created a route happened to include the request that lists networks for
    the picker (it was presumably already loaded from an earlier page). The
    inference this was built on turned out right, confirmed on a real
    router: GET on the same /rest/networkconf collection the client-create
    POSTs to does list every network, following the well-documented
    UniFi legacy-REST convention.

    Excludes two purposes that aren't real routing targets: "vpn-client"
    (WireGuard clients themselves -- what you route *through*, not *to*)
    and "wan" (the uplink itself -- confirmed via a real router returning
    one named "Internet 1"; routing traffic to your own WAN doesn't mean
    anything as a traffic-route target).
    """
    base_url = base_url.rstrip("/")
    result = _authed_request(opener, csrf_token, f"{base_url}/proxy/network/api/s/{site}/rest/networkconf")
    entries = result.get("data", [])
    return [
        {"id": e.get("_id"), "name": e.get("name"), "purpose": e.get("purpose")}
        for e in entries
        if e.get("purpose") not in ("vpn-client", "wan")
    ]


def find_wireguard_client(opener, csrf_token, base_url, name, site="default"):
    """The router's WireGuard VPN client entry with this name (its full
    networkconf record), or None."""
    base_url = base_url.rstrip("/")
    result = _authed_request(opener, csrf_token, f"{base_url}/proxy/network/api/s/{site}/rest/networkconf")
    return next(
        (e for e in result.get("data", [])
         if e.get("purpose") == "vpn-client" and e.get("vpn_type") == "wireguard-client" and e.get("name") == name),
        None,
    )


def wireguard_client_health(opener, csrf_token, base_url, client, site="default"):
    """(healthy, detail). Healthy only when the router reports the client as
    exactly "CONNECTED" — any other status, or no entry, counts as unhealthy."""
    base_url = base_url.rstrip("/")
    result = _authed_request(opener, csrf_token, f"{base_url}/proxy/network/v2/api/site/{site}/vpn/connections")
    conn = next((c for c in result.get("connections", []) if c.get("network_id") == client["_id"]), None)
    if conn is None:
        return False, "the router lists no connection for this client"
    detail = f"status {conn.get('status')}, server {conn.get('remote_ip')}"
    if conn.get("notes"):
        detail += f", notes: {conn['notes']}"
    return conn.get("status") == "CONNECTED", detail


def update_wireguard_client(opener, csrf_token, base_url, client, conf_text, filename, site="default"):
    """Swap a new config into an existing client, keeping its _id so traffic
    routes that point at it stay attached. Mirrors the Network app's own edit:
    the full record goes back with only the config fields changed, minus
    ip_subnet, which the router derives from the config."""
    base_url = base_url.rstrip("/")
    body = {k: v for k, v in client.items() if k != "ip_subnet"}
    body.update(wireguard_client_configuration_file=conf_text, wireguard_client_configuration_filename=filename)
    result = _authed_request(
        opener, csrf_token, f"{base_url}/proxy/network/api/s/{site}/rest/networkconf/{client['_id']}",
        method="PUT", body=body,
    )
    if result.get("meta", {}).get("rc") != "ok":
        raise RouterPushError(f"Updating VPN client failed: {result.get('meta')}")
    return result["data"][0]


def routes_through_client(opener, csrf_token, base_url, client, device_ip, site="default"):
    """Whether the device with this LAN IP is sent through the client by an
    enabled traffic route, either directly or via its whole network."""
    base_url = base_url.rstrip("/")
    routes = _authed_request(opener, csrf_token, f"{base_url}/proxy/network/v2/api/site/{site}/trafficroutes")
    targets = [t for r in routes if r.get("enabled") and r.get("network_id") == client["_id"]
               for t in r.get("target_devices", [])]
    if not targets:
        return False
    devices = _authed_request(
        opener, csrf_token,
        f"{base_url}/proxy/network/v2/api/site/{site}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true",
    )
    me = next((d for d in devices if d.get("ip") == device_ip), None)
    if me is None:
        return False
    return any(
        (t.get("type") == "CLIENT" and t.get("client_mac") == me.get("mac"))
        or (t.get("type") == "NETWORK" and t.get("network_id") == me.get("network_id"))
        for t in targets
    )


def list_devices(opener, csrf_token, base_url, site="default", timeout=15):
    """Active LAN clients/devices available as a traffic-route target (type
    CLIENT). Captured directly from a real "route by device" action:
    GET /proxy/network/v2/api/site/default/clients/active?includeTrafficUsage=true&includeUnifiDevices=true
    """
    base_url = base_url.rstrip("/")
    url = f"{base_url}/proxy/network/v2/api/site/{site}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true"
    result = _authed_request(opener, csrf_token, url)
    entries = result if isinstance(result, list) else result.get("data", [])
    return [
        {
            "mac": e.get("mac"),
            "name": e.get("display_name") or e.get("hostname") or e.get("mac"),
            "network_name": e.get("network_name"),
            "is_wired": e.get("is_wired"),
        }
        for e in entries
    ]


def build_traffic_route_payload(description, network_id, targets):
    """The exact body shape captured from two real actions: routing by
    network and routing by device. `network_id` is the *WireGuard client's*
    own id (from apply_wireguard_client()'s result), not a LAN network --
    that's what ties this route to that specific client. `targets` is a
    list of {"type": "NETWORK", "network_id": ...} and/or
    {"type": "CLIENT", "client_mac": ...} entries -- both confirmed real
    shapes, and the field is a list so mixing both kinds in one route is
    presumably fine, though only one kind at a time has actually been
    tested."""
    return {
        "description": description,
        "enabled": True,
        "network_id": network_id,
        "domains": [],
        "ip_addresses": [],
        "target_devices": targets,
        "ip_ranges": [],
        "matching_target": "INTERNET",
        "next_hop": "",
        "kill_switch_enabled": True,
        "regions": [],
    }


def apply_traffic_route(opener, csrf_token, base_url, description, network_id, targets, site="default", timeout=15):
    """Actually create the traffic route. Returns the created route (its
    own _id, plus the fields sent)."""
    base_url = base_url.rstrip("/")
    payload = build_traffic_route_payload(description, network_id, targets)
    result = _authed_request(
        opener,
        csrf_token,
        f"{base_url}/proxy/network/v2/api/site/{site}/trafficroutes",
        method="POST",
        body=payload,
    )
    if not result.get("_id"):
        raise RouterPushError(f"Creating traffic route failed: {result}")
    return result


def build_wireguard_client_payload(conf_text, filename, name):
    """The exact body shape captured from a real "Add WireGuard VPN Client"
    action. Shared by preview (display only) and apply (actually sent) so
    what's previewed is guaranteed to be what gets sent -- same principle
    as validate_conf() testing the literal artifact it hands back."""
    return {
        "enabled": True,
        "purpose": "vpn-client",
        "vpn_type": "wireguard-client",
        "name": name,
        "wireguard_client_configuration_file": conf_text,
        "wireguard_client_configuration_filename": filename,
        "wireguard_client_mode": "file",
        "interface_mtu_enabled": False,
        "mss_clamp_mss": 1380,
        "mss_clamp": "auto",
        "mss_clamp_ipv6": "auto",
    }


def apply_wireguard_client(opener, csrf_token, base_url, conf_text, filename, name, site="default", timeout=15):
    """Actually add the WireGuard VPN Client entry. opener/csrf_token come
    from a prior login() call on the same session. Returns the created
    entry (includes the router's own _id, wireguard_id, ip_subnet, etc.)."""
    base_url = base_url.rstrip("/")
    payload = build_wireguard_client_payload(conf_text, filename, name)
    result = _authed_request(
        opener,
        csrf_token,
        f"{base_url}/proxy/network/api/s/{site}/rest/networkconf",
        method="POST",
        body=payload,
    )
    # This endpoint's older-style REST envelope (meta.rc/data) differs from
    # apply_traffic_route()'s flat v2-style response -- both confirmed real,
    # not a bug.
    if result.get("meta", {}).get("rc") != "ok":
        raise RouterPushError(f"Adding VPN client failed: {result.get('meta')}")
    return result["data"][0]
