"""Switching regions by replying to the watchdog's email.

When new servers aren't fixing the VPN, the alert email lists a few regions:
Texas ones first, then the fastest few others, with how long each took to
answer from here. A reply naming one (by number, region id, or name) switches
the watchdog to that region. See "Switch regions by email" in watchdog/README.md.
"""

import email
import email.policy
import imaplib
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from email.utils import parseaddr

TEXAS_WORDS = ("texas", "houston", "dallas")
OTHER_OPTIONS = 3
# What people call a region, where it isn't its PIA name ("US Texas" is Dallas).
ALIASES = {"dallas": "us_south_west"}


def connect_ms(ip, port=1337, timeout=2.0):
    """Milliseconds to open a TCP connection to a PIA server's API port, or None."""
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except OSError:
        return None
    return round((time.monotonic() - start) * 1000)


def measure(regions, connect=connect_ms):
    """{region id: ms or None}, timing each region's first WireGuard server."""
    with ThreadPoolExecutor(max_workers=16) as pool:
        times = list(pool.map(lambda r: connect(r["servers"]["wg"][0]["ip"]), regions))
    return {r["id"]: t for r, t in zip(regions, times)}


def is_texas(region):
    return any(word in region["name"].lower() for word in TEXAS_WORDS)


def build_menu(regions, latency, current_id):
    """[(region id, name, ms)]: US regions that answered, except the current
    one. Texas regions first, fastest first, then the fastest few others."""
    usable = [r for r in regions
              if r.get("country") == "US" and r["id"] != current_id and latency.get(r["id"]) is not None]
    by_speed = sorted(usable, key=lambda r: latency[r["id"]])
    texas = [r for r in by_speed if is_texas(r)]
    others = [r for r in by_speed if not is_texas(r)][:OTHER_OPTIONS]
    return [(r["id"], r["name"], latency[r["id"]]) for r in texas + others]


def menu_text(menu, current_name, hours):
    lines = [f"To switch from {current_name} to another region, reply to this email with its number:"]
    lines += [f"  {i}. {name} ({ms} ms)" for i, (_, name, ms) in enumerate(menu, 1)]
    lines += ["",
              "Or reply with any region's name or id (pia_watchdog.py --list-regions lists them).",
              f"Only the first line of your reply counts. The watchdog checks for replies every few minutes "
              f"for the next {hours} hours."]
    return "\n".join(lines)


def first_line(msg):
    """The first line of the reply's own text, above the quoted email."""
    part = msg.get_body(preferencelist=("plain",))
    text = part.get_content() if part is not None else ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(">") or re.match(r"^On .* wrote:$", line):
            break
        if line:
            return line
    return ""


def parse_choice(text, options, regions):
    """The region id a reply asks for, or None. options are the menu's ids, in order."""
    answer = re.sub(r"[.!]+$", "", text.strip().lower())
    if re.fullmatch(r"\d+", answer):
        n = int(answer)
        return options[n - 1] if 1 <= n <= len(options) else None
    if answer in ALIASES:
        return ALIASES[answer]
    for r in regions:
        name = r["name"].lower()
        if answer in (r["id"].lower(), name, name.removeprefix("us ")):
            return r["id"]
    return None


def trusted_sender(msg, expected_address):
    """Whether the reply is really from expected_address: the From line alone can
    be forged, so the receiving server's sender check (DMARC, or DKIM signed by
    the address's own domain) must have passed too. Only the topmost
    Authentication-Results header counts, since the receiving server adds it last."""
    address = parseaddr(msg.get("From", ""))[1].lower()
    if address != expected_address.lower():
        return False
    results = msg.get_all("Authentication-Results") or []
    if not results:
        return False
    domain = address.rsplit("@", 1)[1]
    top = re.sub(r"\s+", " ", str(results[0]).lower())
    return ("dmarc=pass" in top and f"header.from={domain}" in top) or f"dkim=pass header.i=@{domain}" in top


def answers(msg, message_ids):
    """Which of message_ids this message replies to, or None."""
    refs = f"{msg.get('In-Reply-To', '')} {msg.get('References', '')}"
    return next((m for m in message_ids if m in refs), None)


def fetch_replies(server, username, password, sender, since):
    """Messages from sender since the given time (newest last), read-only."""
    with imaplib.IMAP4_SSL(server, 993, timeout=30) as imap:
        imap.login(username, password)
        imap.select("INBOX", readonly=True)
        date = time.strftime("%d-%b-%Y", time.gmtime(since))
        _, data = imap.search(None, "FROM", f'"{sender}"', "SINCE", date)
        messages = []
        for num in data[0].split()[-20:]:
            _, parts = imap.fetch(num, "(BODY.PEEK[])")
            raw = next(p[1] for p in parts if isinstance(p, tuple))
            messages.append(email.message_from_bytes(raw, policy=email.policy.default))
        return messages
