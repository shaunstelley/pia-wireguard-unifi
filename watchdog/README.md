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

## Check the logins

The PIA password is only needed when a replacement happens, so a normal check doesn't prove it works. To confirm both logins and see the client's status, changing nothing:

```bash
sudo /opt/pia-wireguard-unifi/watchdog/verify.sh
```

The installer runs this at the end. The watchdog also re-checks the PIA login once a day, so a changed password shows up as a failed run in the logs well before an outage needs it.

## Email alerts

The installer can set up an email for whenever the watchdog does something or needs you:

| When | Subject |
|---|---|
| It swaps in a new config | Switched the VPN to server *X*, checking it connects |
| The next check sees it connected | VPN connected on server *X* |
| It can't fix things: the daily limit is reached, the PIA login fails, the router can't be reached, the VPN client is missing | What's wrong, with that run's log |
| A problem clears up | Resolved: *what was wrong* |
| Dry-run mode only: the VPN is down and it would have replaced the config | VPN is down (dry run, so nothing was replaced) |

A problem that lasts doesn't email on every 5-minute check: you get one email when it starts, a reminder every 6 hours (`alert_reminder_hours`), and a "Resolved" email when it's fixed.

The emails go out through an email account's SMTP server, sent by the watchdog itself. With the [bypass network](#bypass-network) they still go out while the VPN is down. That's when you need them, and when anything else on a network routed through the VPN (Home Assistant, for example) is cut off too.

To turn them on, re-run the installer and answer **y** to the email question. For Gmail:

1. Your Google account needs 2-Step Verification on.
2. Create an app password at <https://myaccount.google.com/apppasswords> (name it e.g. "PIA watchdog").
3. Give the installer that 16-letter app password, not your normal password. It's encrypted like the other two.

An app password can do anything with the mailbox, not just send. If you'd rather the Pi not hold the keys to your main inbox, create a separate Gmail account just for sending, and enter your own address as the one to send alerts to.

The installer sends a test email at the end, and so does `verify.sh` whenever you run it. If the test email arrives but your phone doesn't notify you, check the mail app's notification settings for that inbox.

## Replace the config right now

To swap in a fresh config immediately, whatever the current status (also a good way to test the whole thing once):

```bash
sudo /opt/pia-wireguard-unifi/watchdog/replace-now.sh
```

This works even in dry-run mode. It isn't blocked by the daily limit, but it does count toward it.

## How the passwords are stored

The PIA password, router password, and email password (if alerts are on) are encrypted with `systemd-creds` and stored in `/etc/credstore.encrypted/`. The installer pipes them straight into the encryption, so they never touch disk in plaintext. They're decrypted only while the watchdog runs, into a private in-memory location that only the watchdog can read. The watchdog runs as its own system user (`pia-watchdog`), which has no login, no home folder, and no access to yours.

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
| `alert_email` | Where to send [email alerts](#email-alerts); leave it out to turn them off |
| `smtp_username` | The email account that sends them (default: `alert_email`) |
| `smtp_server` | Its SMTP server (default `smtp.gmail.com`) |
| `smtp_port` | `465` for TLS (default), or `587` for STARTTLS |
| `alert_reminder_hours` | How often to repeat an alert while a problem lasts (default `6`) |

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
