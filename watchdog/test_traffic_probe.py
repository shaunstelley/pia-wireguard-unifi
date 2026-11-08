"""Run with: python3 -m unittest discover -s watchdog"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import probe_report as pr
import traffic_probe as tp

T0 = 1_800_000_000.0


def run(results_per_probe, start=T0, every=30):
    state = {}
    for i, results in enumerate(results_per_probe):
        state = tp.record(state, results, start + i * every)
    return state


class RecordTests(unittest.TestCase):
    def test_counts_runs_and_stays_quiet_while_traffic_flows(self):
        state = run([[True]] * 3)
        self.assertEqual((state["runs"], state["outages"], state["started_at"]), (3, [], T0))

    def test_an_outage_opens_and_closes(self):
        state = run([[True], [False, False], [False, False], [True]])
        self.assertEqual(state["outages"], [{"last_ok": T0, "first_failed": T0 + 30,
                                             "recovered": T0 + 90, "failed_probes": 2}])

    def test_the_second_site_answering_isnt_an_outage(self):
        state = run([[False, True]])
        self.assertEqual((state["outages"], state["first_site_failed"]), ([], 1))

    def test_records_gaps_when_the_probe_didnt_run(self):
        state = tp.record(run([[True]]), [True], T0 + 600)
        self.assertEqual(state["gaps"], [{"from": T0, "to": T0 + 600}])

    def test_main_saves_state_and_logs_only_changes(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"STATE_DIRECTORY": d}), \
             mock.patch.object(tp, "reachable", return_value=False), mock.patch("builtins.print") as out:
            tp.main()
            tp.main()
        self.assertEqual(out.call_count, 1)
        self.assertIn("isn't getting through", out.call_args.args[0])


def journal(t, message):
    return json.dumps({"__REALTIME_TIMESTAMP": str(int(t * 1e6)), "MESSAGE": message})


class ReportTests(unittest.TestCase):
    def test_reads_the_watchdogs_check_results(self):
        lines = [journal(T0, "Healthy: status CONNECTED, server 1.2.3.4"),
                 journal(T0 + 60, "Unhealthy (1/3): status CONNECTING"),
                 journal(T0 + 61, "Couldn't check whether this machine is routed through the VPN"),
                 journal(T0 + 120, "Router: Could not reach router"), "not json"]
        self.assertEqual([(t, k) for t, k, _ in pr.parse_checks(lines)],
                         [(T0, "connected"), (T0 + 60, "not connected"), (T0 + 120, "router unreachable")])

    def outage(self, minutes, recovered=True):
        return {"last_ok": T0 - 30, "first_failed": T0, "failed_probes": minutes * 2,
                "recovered": T0 + minutes * 60 if recovered else None}

    def test_verdicts(self):
        cases = [
            ([], "too short"),
            ([(T0 + 60, "connected", ""), (T0 + 200, "not connected", "")], "router noticed"),
            ([(T0 + 60, "connected", "")], "router said connected"),
            ([(T0 + 60, "router unreachable", "")], "router unreachable"),
        ]
        for checks, verdict in cases:
            text, got = pr.describe_outage(self.outage(5), checks, T0 + 3600)
            self.assertEqual(got, verdict, checks)
        self.assertIn("showed it by +3 min 20 s", pr.describe_outage(self.outage(5), cases[1][0], T0)[0])

    def test_an_outage_still_going_at_report_time(self):
        text, _ = pr.describe_outage(self.outage(5, recovered=False), [], T0 + 600)
        self.assertIn("still going after 10 min 0 s", text)

    def test_summary(self):
        probe = run([[True], [False, False], [False, False], [True], [False, True]])
        probe = tp.record(probe, [True], T0 + 600)
        checks = [(T0, "connected", ""), (T0 + 40, "not connected", "")]
        text = pr.summarize(probe, checks, T0 + 700)
        for expected in ("Probes: 6 of about 21 expected. Traffic got through on 4.",
                         "Outages (neither site answered): 1", "Times only the first site failed: 1",
                         "Gaps with no probes for over 90 s (machine down or stuck): 1",
                         "Outages the router showed at a check during them: 1",
                         "come back to Claude Code and finish the traffic probe"):
            self.assertIn(expected, text)
        self.assertNotIn("Note:", text)

    def test_says_when_the_watchdog_log_is_missing(self):
        text = pr.summarize(run([[True]] * 2), [], T0 + 60)
        self.assertIn("the watchdog's log only goes back to now", text)

    def test_emails_the_report(self):
        with tempfile.TemporaryDirectory() as d:
            state, config = Path(d, "probe.json"), Path(d, "config.json")
            state.write_text(json.dumps(run([[True]] * 2)))
            config.write_text(json.dumps({"alert_email": "me@example.com"}))
            with mock.patch.object(pr, "PROBE_STATE", state), mock.patch.object(pr, "read_checks", return_value=[]), \
                 mock.patch.object(pr.wd, "send_email") as send, mock.patch("builtins.print"), \
                 mock.patch("sys.argv", ["probe_report.py", "--config", str(config)]):
                self.assertEqual(pr.main(), 0)
                send.side_effect = OSError("refused")
                self.assertEqual(pr.main(), 1)
        self.assertEqual(send.call_args.args[1], "Traffic probe results, time to finish the project")


if __name__ == "__main__":
    unittest.main()
