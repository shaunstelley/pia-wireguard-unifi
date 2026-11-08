#!/usr/bin/env python3
"""Log-only check that internet traffic gets through the VPN.

A systemd timer runs this every 30 seconds as its own user, so its traffic takes
this machine's normal route through the VPN (the watchdog's user takes the
bypass network instead). It never talks to the router or changes anything: it
only records outages in $STATE_DIRECTORY/probe.json, which probe_report.py
summarizes. See watchdog/README.md, "Traffic probe".
"""

import json
import os
import time
import urllib.request
from pathlib import Path

# Two unrelated sites, so one site's own trouble doesn't count as an outage.
URLS = ("https://1.1.1.1/cdn-cgi/trace", "https://www.google.com/generate_204")
TIMEOUT_SECONDS = 5
GAP_SECONDS = 90  # no run for this long means the probe (or the machine) wasn't running


def reachable(url):
    req = urllib.request.Request(url, headers={"User-Agent": "pia-traffic-probe"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return resp.status < 400
    except OSError:  # URLError, timeouts and TLS errors are all OSErrors
        return False


def record(state, results, now):
    """Pure step: results holds one bool per URL, tried in order until one worked."""
    state = dict(state)
    state.setdefault("started_at", now)
    last_run = state.get("last_run_at")
    if last_run is not None and now - last_run > GAP_SECONDS:
        state["gaps"] = state.get("gaps", []) + [{"from": last_run, "to": now}]
    state["runs"] = state.get("runs", 0) + 1
    state["last_run_at"] = now
    ok = any(results)
    if ok and not results[0]:
        state["first_site_failed"] = state.get("first_site_failed", 0) + 1
    outages = list(state.get("outages", []))
    current = outages[-1] if outages and outages[-1]["recovered"] is None else None
    if ok:
        state["last_ok_at"] = now
        if current:
            outages[-1] = {**current, "recovered": now}
    elif current:
        outages[-1] = {**current, "failed_probes": current["failed_probes"] + 1}
    else:
        outages.append({"last_ok": state.get("last_ok_at"), "first_failed": now,
                        "recovered": None, "failed_probes": 1})
    state["outages"] = outages
    return state


def main():
    path = Path(os.environ.get("STATE_DIRECTORY", ".")) / "probe.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        state = {}
    results = []
    for url in URLS:
        results.append(reachable(url))
        if results[-1]:
            break
    before = state.get("outages", [])
    state = record(state, results, time.time())
    # Log only changes, so the journal isn't filled with a line every 30 seconds.
    if len(state["outages"]) > len(before):
        print("Traffic isn't getting through: neither site answered.", flush=True)
    elif before and before[-1]["recovered"] is None and state["outages"][-1]["recovered"] is not None:
        print(f"Traffic is getting through again after {state['outages'][-1]['failed_probes']} failed probes.",
              flush=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
