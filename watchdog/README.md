# PIA watchdog

Keeps your router's PIA WireGuard VPN client connected without you stepping in. Every 5 minutes it asks the router for the client's status, the same status the Network app shows. Anything other than **Connected** counts as a failed check. After 3 failed checks in a row, it generates a fresh config for the same PIA region (trying a different server in that region first) and swaps it into the **existing** router entry. Networks and devices you route through that client stay attached.

It runs on an always-on Linux machine on the router's network, such as a Raspberry Pi with Raspberry Pi OS or Debian 12. It's not meant for the Mac.

## Before installing

- **Make sure the watchdog can reach PIA when the VPN is down.** If its machine's network is routed through the PIA client with the kill switch on, it loses internet exactly when the tunnel fails. The easiest fix is a [bypass network](#bypass-network), which the installer can set up. Moving the machine to a network that isn't routed through the VPN also works. The watchdog checks this on every run and logs a warning if it's routed through the client.
- **Use a local-only router account** (see [webui/README.md](../webui/README.md#router-account)). An SSO-linked account needs an emailed code on every login, which a background job can't provide.
- **The VPN client must already exist on the router**, for example added with the web UI. The watchdog only updates it; it never creates or deletes clients.

## Install

On the Pi:

```bash
sudo git clone https://github.com/shaunstelley/pia-wireguard-unifi.git /opt/pia-wireguard-unifi
sudo /opt/pia-wireguard-unifi/watchdog/install.sh
```

The installer adds `wireguard-tools` and `jq`, asks for your settings and the two passwords, sets up a systemd timer, and runs a first check. It starts in **dry-run mode**: it logs what it would do but never changes the router. Watch the logs for a day or so:

```bash
journalctl -u pia-watchdog -f
```

To go live, re-run the installer, answer **y** to "Change the existing settings?", and **n** to dry-run mode. Or set `"dry_run": false` in `/etc/pia-watchdog/config.json`.

## Bypass network

If the watchdog's machine sits on a network that's routed through the VPN, the installer can add a second connection on the same cable to another of your router's networks: one that has internet access and isn't routed through the VPN. It asks for that network's VLAN id. Only the watchdog's own traffic uses it; everything else on the machine (other services, its address, remote access) stays exactly as it was. The switch port must carry that VLAN, which UniFi ports do by default.

The installer tests it before relying on it: the machine must get an address on that network, and the watchdog's traffic must reach PIA through it. If either check fails, it removes the connection again, so nothing changes.

To check it later:

```bash
ip route get 1.1.1.1 uid "$(id -u pia-watchdog)"
```

This should show the VLAN interface (e.g. `eth0.2`), not your main one.

## Replace the config right now

To swap in a fresh config immediately, whatever the current status (also a good way to test the whole thing once):

```bash
sudo /opt/pia-wireguard-unifi/watchdog/replace-now.sh
```

This works even in dry-run mode. It isn't blocked by the daily limit, but it does count toward it.

## How the passwords are stored

The PIA password and router password are encrypted with `systemd-creds` and stored in `/etc/credstore.encrypted/`. The installer pipes them straight into the encryption, so they never touch disk in plaintext. They're decrypted only while the watchdog runs, into a private in-memory location that only the watchdog can read. The watchdog runs as its own system user (`pia-watchdog`), which has no login, no home folder, and no access to yours.

**Limits:** a Pi has no hardware security chip, so the decryption key is on the same SD card. This protects against copies leaking (backups, a stray file, other users on the Pi). It doesn't protect against someone with the whole SD card or root on the Pi. Keep SSH key-only, and use a PIA password you don't use anywhere else.

## Settings

`/etc/pia-watchdog/config.json`:

| Key | Meaning |
|---|---|
| `router_url` | Router address, e.g. `https://192.168.1.1` |
| `router_username` | The local-only router account |
| `client_name` | Name of the WireGuard VPN client on the router |
| `pia_username` | PIA username |
| `region_id` | PIA region to generate configs for (`watchdog/pia_watchdog.py --list-regions` lists them) |
| `include_dns` | Use PIA's DNS server in the config (default `true`) |
| `dry_run` | Log only, change nothing (default `true`) |
| `unhealthy_checks_before_replacing` | Failed checks in a row before replacing (default `3`, i.e. 15 minutes) |
| `max_replacements_per_day` | Safety cap; past it the service reports a failure instead of replacing again (default `4`) |

## Updating and removing

```bash
sudo git -C /opt/pia-wireguard-unifi pull
```

To remove it completely:

```bash
sudo systemctl disable --now pia-watchdog.timer
sudo rm /etc/systemd/system/pia-watchdog.service /etc/systemd/system/pia-watchdog.timer
sudo rm -r /etc/pia-watchdog /etc/credstore.encrypted/pia-watchdog-*
sudo systemctl daemon-reload
sudo nmcli connection delete pia-watchdog-bypass   # only if you set up the bypass network
sudo userdel pia-watchdog
```

## Tests

```bash
python3 -m unittest discover -s watchdog
```
