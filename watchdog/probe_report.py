#!/usr/bin/env python3
"""Email what the traffic probe found, compared with the watchdog's router checks.

Its systemd timer runs this once, when the probe's time is up, as the watchdog's
user (so the email goes out through the bypass network); its unit then switches
the probe off. To preview the report at any time, as root:
    python3 watchdog/probe_report.py --config /etc/pia-watchdog/config.json --dry-run
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pia_watchdog as wd

PROBE_STATE = Path(os.environ.get("PROBE_STATE", "/var/lib/pia-probe/probe.json"))
PROBE_SECONDS = 30
# A check this long after an outage ends can still show the router catching up.
CHECK_WINDOW_AFTER = 60


def when(t):
    return time.strftime("%b %d %H:%M:%S GMT", time.gmtime(t))


def span(seconds):
    seconds = round(seconds)
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min {seconds % 60} s"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"


def parse_checks(journal_lines):
    """journalctl -o json lines -> [(time, kind, message)] for the watchdog's check results."""
    kinds = (("Healthy:", "connected"), ("Unhealthy", "not connected"), ("Replaced", "replaced"),
             ("Router:", "router unreachable"))
    checks = []
    for line in journal_lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            continue
        kind = next((k for prefix, k in kinds if message.startswith(prefix)), None)
        if kind:
            checks.append((int(entry["__REALTIME_TIMESTAMP"]) / 1e6, kind, message))
    return checks


def read_checks(since):
    out = subprocess.run(["journalctl", "-u", "pia-watchdog", "-o", "json", "--no-pager",
                          "--since", f"@{int(since)}"], capture_output=True, text=True, check=False)
    return parse_checks(out.stdout.splitlines())


def describe_outage(outage, checks, now):
    """Returns (text, verdict), verdict being one of "too short", "router noticed",
    "router said connected", "router unreachable"."""
    start = outage["first_failed"]
    end = outage["recovered"] or now
    during = [c for c in checks if start <= c[0] <= end + CHECK_WINDOW_AFTER]
    length = f"lasted {span(end - start)}" if outage["recovered"] else f"still going after {span(end - start)}"
    lines = [f"{when(start)}, {length} ({outage['failed_probes']} failed probes)"]
    if during:
        lines.append("   Watchdog checks: " + ", ".join(f"+{span(t - start)} {kind}" for t, kind, _ in during))
    kinds = {kind for _, kind, _ in during}
    if not during:
        verdict = "too short"
        lines.append("   No watchdog check during it.")
    elif kinds & {"not connected", "replaced"}:
        verdict = "router noticed"
        first = next(t for t, kind, _ in during if kind in ("not connected", "replaced"))
        lines.append(f"   The router showed it by +{span(first - start)}.")
    elif kinds == {"router unreachable"}:
        verdict = "router unreachable"
        lines.append("   The router itself couldn't be reached, e.g. restarting.")
    else:
        verdict = "router said connected"
        lines.append("   The router said CONNECTED the whole time.")
    return "\n".join(lines), verdict


def summarize(probe, checks, now):
    start, last = probe["started_at"], probe.get("last_run_at", probe["started_at"])
    expected = round((last - start) / PROBE_SECONDS) + 1
    outages = probe.get("outages", [])
    gaps = probe.get("gaps", [])
    failed = sum(o["failed_probes"] for o in outages)
    lines = [
        f"Traffic probe results, {when(start)} to {when(last)} ({span(last - start)}).",
        "",
        f"Probes: {probe['runs']:,} of about {expected:,} expected. Traffic got through on {probe['runs'] - failed:,}.",
        f"Outages (neither site answered): {len(outages)}",
        f"Times only the first site failed: {probe.get('first_site_failed', 0)}",
        f"Gaps with no probes for over 90 s (machine down or stuck): {len(gaps)}",
    ]
    if not checks or checks[0][0] > start + 600:
        lines.append("Note: the watchdog's log only goes back to "
                     f"{when(checks[0][0]) if checks else 'now'} (the machine keeps it in memory, so a restart "
                     "erases it), so earlier outages can't be compared with the router's status.")
    verdicts = []
    if outages:
        lines += ["", "Outages:"]
        for i, outage in enumerate(outages, 1):
            text, verdict = describe_outage(outage, checks, now)
            verdicts.append(verdict)
            lines.append(f"{i}. {text}")
    if gaps:
        lines += ["", "Gaps:"] + [f"- {when(g['from'])} to {when(g['to'])} ({span(g['to'] - g['from'])})" for g in gaps]
    lines += [
        "", "What it means for probe-triggered checks:",
        f"- Outages the router showed at a check during them: {verdicts.count('router noticed')}",
        f"- Outages where the router said CONNECTED throughout: {verdicts.count('router said connected')}"
        " (it either lagged or missed them; the probe would have caught these)",
        f"- Outages too short for a 5-minute check to see: {verdicts.count('too short')}",
        f"- Outages while the router was unreachable: {verdicts.count('router unreachable')}",
        "",
        "The probe has been switched off; its data stays in /var/lib/pia-probe/probe.json.",
        "Next: come back to Claude Code and finish the traffic probe (watchdog/README.md, \"Traffic probe\").",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true", help="print the report instead of emailing it")
    args = parser.parse_args()
    config = {**wd.DEFAULTS, **json.loads(args.config.read_text(encoding="utf-8"))}
    probe = json.loads(PROBE_STATE.read_text(encoding="utf-8"))
    body = summarize(probe, read_checks(probe["started_at"]), time.time())
    if args.dry_run or not config.get("alert_email"):
        print(body)
        return 0
    try:
        wd.send_email(config, "Traffic probe results, time to finish the project", body)
    except (OSError, RuntimeError) as e:
        print(f"Couldn't send the report email: {e}", file=sys.stderr)
        return 1  # the unit retries
    print(f"Emailed the report to {config['alert_email']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
