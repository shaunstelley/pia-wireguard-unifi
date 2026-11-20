# Local web UI

Generates a PIA WireGuard config you can download and use with anything that imports WireGuard configs. Optionally, it also adds the config to a UniFi router (tested on a Dream Router) as a VPN client, and routes chosen networks or devices through it.

## Setup (macOS)

    brew install jq wireguard-tools

curl and python3 already ship with macOS.

## Run

Double-click `launch-webui.command` in the repo root. It starts the server and opens the page. Or from a terminal:

    python3 webui/server.py

then open http://localhost:8765. Close the Terminal window (or press Ctrl+C) to stop it.

## Steps

1. **Generate config**: PIA login, region, and optionally a local test that briefly brings the tunnel up on this Mac to confirm it handshakes (macOS asks for your password or Touch ID). **Download .conf** saves the file if you want it.
2. **Connect to router**: router address and admin login. Use a local-only account (see [Router account](#router-account)) to skip Ubiquiti's emailed verification code. A Ubiquiti SSO-linked account works too, but asks for that code every time.
3. **Add to router**: name the entry, optionally tick networks or devices to send through the VPN (with the kill switch on, the router's default), then **Add to router**. "Show request details" shows the exact requests before they're sent.

## Router account

Signing in with your Ubiquiti (SSO) account triggers an emailed verification code on every connect. A local-only admin account signs in against the router itself, so there's no code. In the UniFi console:

1. Open **Admins & Users** and add a new admin.
2. Tick **Restrict to local access only**, then set a username and password.
3. Give it admin rights for the **Network** app only. It needs to add VPN clients and traffic routes, so view-only isn't enough, and it needs nothing in the other apps.

It's protected by its password alone, but it only works from inside your network.

## Privacy

- The server listens on `127.0.0.1` only, and refuses requests from other websites open in your browser: it checks the `Host` and `Origin` headers and only accepts JSON posts, so another page can't use the router session.
- PIA and router passwords are used for the one request that needs them and are never logged or written to disk.
- The router session is kept in memory for 10 minutes, so steps 2 and 3 don't need a second MFA code.
- The browser remembers the router address and both usernames (in localStorage), never passwords.

### Saving passwords

Let Safari save them to the Passwords app (iCloud Keychain), then autofill with Touch ID. Both logins are for the same site (`localhost:8765`), so you'll see two saved entries there; pick the matching one when autofilling. If Safari doesn't offer to save after you log in, add them yourself in the Passwords app with the website `localhost`.
