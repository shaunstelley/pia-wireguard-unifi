"""Run with: python3 -m unittest discover watchdog"""

import email
import email.policy
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pia_watchdog as wd
import region_reply as rr


def region(rid, name, country="US"):
    return {"id": rid, "name": name, "country": country, "servers": {"wg": [{"ip": f"ip-{rid}"}]}}


REGIONS = [
    region("us_houston", "US Houston"),
    region("us_south_west", "US Texas"),
    region("us_denver", "US Denver"),
    region("us_atlanta", "US Atlanta"),
    region("us_las_vegas", "US Las Vegas"),
    region("us_chicago", "US Chicago"),
    region("us_seattle", "US Seattle"),
    region("mx", "Mexico", country="MX"),
]
LATENCY = {"us_houston": 30, "us_south_west": 25, "us_denver": 60, "us_atlanta": 50, "us_las_vegas": 70,
           "us_chicago": 45, "us_seattle": None, "mx": 10}
PASS = ("mx.google.com; dkim=pass header.i=@gmail.com header.s=20230601; "
        "spf=pass smtp.mailfrom=me@gmail.com; dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com")


def reply(body="2", sender="me@gmail.com", in_reply_to="<menu-1@gmail.com>", auth=(PASS,), message_id="<r1@x>"):
    headers = [f"Authentication-Results: {a}" for a in auth]
    headers += [f"From: Me <{sender}>", f"In-Reply-To: {in_reply_to}", f"Message-ID: {message_id}",
                "Subject: Re: PIA watchdog", "Content-Type: text/plain; charset=utf-8"]
    return email.message_from_string("\n".join(headers) + "\n\n" + body + "\n", policy=email.policy.default)


class MenuTests(unittest.TestCase):
    def test_texas_first_then_the_fastest_others(self):
        menu = rr.build_menu(REGIONS, LATENCY, "us_houston")
        self.assertEqual([m[0] for m in menu], ["us_south_west", "us_chicago", "us_atlanta", "us_denver"])

    def test_both_texas_regions_when_neither_is_current(self):
        menu = rr.build_menu(REGIONS, LATENCY, "us_denver")
        self.assertEqual([m[0] for m in menu][:2], ["us_south_west", "us_houston"])

    def test_leaves_out_unreachable_and_non_us_regions(self):
        ids = [m[0] for m in rr.build_menu(REGIONS, LATENCY, "us_houston")]
        self.assertNotIn("us_seattle", ids)
        self.assertNotIn("mx", ids)

    def test_text_numbers_the_options_with_their_times(self):
        text = rr.menu_text([("us_south_west", "US Texas", 25)], "US Houston", 24)
        self.assertIn("from US Houston", text)
        self.assertIn("1. US Texas (25 ms)", text)

    def test_measure_times_each_regions_first_server(self):
        times = rr.measure(REGIONS[:2], connect=lambda ip: {"ip-us_houston": 30}.get(ip))
        self.assertEqual(times, {"us_houston": 30, "us_south_west": None})


class ParseTests(unittest.TestCase):
    OPTIONS = ["us_south_west", "us_chicago"]

    def parse(self, text):
        return rr.parse_choice(text, self.OPTIONS, REGIONS)

    def test_numbers(self):
        self.assertEqual(self.parse("2"), "us_chicago")
        self.assertEqual(self.parse(" 1. "), "us_south_west")
        self.assertIsNone(self.parse("3"))
        self.assertIsNone(self.parse("0"))

    def test_names_ids_and_aliases(self):
        self.assertEqual(self.parse("Houston"), "us_houston")
        self.assertEqual(self.parse("us denver"), "us_denver")
        self.assertEqual(self.parse("us_atlanta"), "us_atlanta")
        self.assertEqual(self.parse("Dallas!"), "us_south_west")
        self.assertEqual(self.parse("texas"), "us_south_west")

    def test_anything_else_is_not_a_choice(self):
        self.assertIsNone(self.parse("yes please"))
        self.assertIsNone(self.parse(""))

    def test_first_line_ignores_the_quoted_email(self):
        msg = reply("\n  3  \nthanks\n\nOn Thu, Nov 26, 2026 at 11:00 AM Watchdog wrote:\n> 1. US Texas")
        self.assertEqual(rr.first_line(msg), "3")
        self.assertEqual(rr.first_line(reply("On Thu, Nov 26 Watchdog wrote:\n> 1. US Texas")), "")


class SenderTests(unittest.TestCase):
    def test_passing_check_from_the_right_address(self):
        self.assertTrue(rr.trusted_sender(reply(), "me@gmail.com"))
        self.assertTrue(rr.trusted_sender(reply(), "Me@Gmail.com"))

    def test_dkim_from_the_senders_domain_is_enough(self):
        auth = "mx.google.com; dkim=pass header.i=@gmail.com header.s=x; spf=softfail"
        self.assertTrue(rr.trusted_sender(reply(auth=(auth,)), "me@gmail.com"))

    def test_forged_or_unchecked_senders_are_refused(self):
        self.assertFalse(rr.trusted_sender(reply(sender="someone@gmail.com"), "me@gmail.com"))
        self.assertFalse(rr.trusted_sender(reply(auth=()), "me@gmail.com"))
        failed = "mx.google.com; dkim=fail header.i=@gmail.com; dmarc=fail header.from=gmail.com"
        self.assertFalse(rr.trusted_sender(reply(auth=(failed,)), "me@gmail.com"))
        other_domain = "mx.google.com; dkim=pass header.i=@evil.example; dmarc=pass header.from=evil.example"
        self.assertFalse(rr.trusted_sender(reply(auth=(other_domain,)), "me@gmail.com"))

    def test_only_the_topmost_result_counts(self):
        forged_lower = ("mx.google.com; dmarc=fail header.from=gmail.com", PASS)
        self.assertFalse(rr.trusted_sender(reply(auth=forged_lower), "me@gmail.com"))

    def test_answers_matches_in_reply_to_or_references(self):
        self.assertEqual(rr.answers(reply(), ["<menu-0@gmail.com>", "<menu-1@gmail.com>"]), "<menu-1@gmail.com>")
        self.assertIsNone(rr.answers(reply(in_reply_to="<other@x>"), ["<menu-1@gmail.com>"]))


EMAIL_CONFIG = {**wd.DEFAULTS, "router_url": "https://router", "router_username": "watchdog",
                "client_name": "PIA VPN", "pia_username": "p1", "region_id": "us_houston",
                "alert_email": "me@gmail.com", "smtp_username": "watchdog@gmail.com"}
NOW = 1_000_000.0
MENU = {"message_id": "<menu-1@gmail.com>", "options": ["us_south_west", "us_chicago"], "sent_at": NOW - 600}


class WatchdogReplyTests(unittest.TestCase):
    def setUp(self):
        self.creds = tempfile.TemporaryDirectory()
        Path(self.creds.name, "smtp_password").write_text("abcd efgh\n")
        env = mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": self.creds.name})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(self.creds.cleanup)
        patcher = mock.patch.multiple(wd, log=mock.DEFAULT, notify=mock.DEFAULT, send_email=mock.DEFAULT)
        self.mocks = patcher.start()
        self.addCleanup(patcher.stop)
        regions = mock.patch.object(wd.pia_config, "fetch_regions", return_value=REGIONS)
        regions.start()
        self.addCleanup(regions.stop)

    def logged(self):
        return " ".join(str(c.args[0]) for c in self.mocks["log"].call_args_list)

    def check(self, replies, state=None):
        with mock.patch.object(wd.region_reply, "fetch_replies", return_value=replies) as fetch:
            result = wd.check_region_replies(EMAIL_CONFIG, state or {"region_menus": [MENU]}, NOW)
        self.fetch = fetch
        return result

    def test_a_trusted_reply_picks_a_region(self):
        state, choice = self.check([reply("2")])
        self.assertEqual(choice, "us_chicago")
        self.assertEqual(state["seen_replies"], ["<r1@x>"])
        self.fetch.assert_called_once_with("imap.gmail.com", "watchdog@gmail.com", "abcdefgh", "me@gmail.com",
                                           MENU["sent_at"])

    def test_untrusted_replies_are_ignored(self):
        state, choice = self.check([reply("2", auth=())])
        self.assertIsNone(choice)
        self.assertIn("failed the sender check", self.logged())

    def test_a_reply_is_only_acted_on_once(self):
        state, choice = self.check([reply("2")], {"region_menus": [MENU], "seen_replies": ["<r1@x>"]})
        self.assertIsNone(choice)

    def test_an_unreadable_reply_gets_an_email_back(self):
        _, choice = self.check([reply("maybe later")])
        self.assertIsNone(choice)
        self.assertEqual(self.mocks["notify"].call_args.args[1], "Couldn't read your reply")

    def test_replies_to_other_emails_are_skipped(self):
        _, choice = self.check([reply("2", in_reply_to="<other@x>")])
        self.assertIsNone(choice)

    def test_no_recent_menu_means_no_inbox_check(self):
        old = {**MENU, "sent_at": NOW - 25 * 3600}
        state, choice = self.check([reply("2")], {"region_menus": [old]})
        self.assertIsNone(choice)
        self.assertNotIn("region_menus", state)
        self.fetch.assert_not_called()

    def test_inbox_errors_dont_stop_the_check(self):
        with mock.patch.object(wd.region_reply, "fetch_replies", side_effect=OSError("no route")):
            state, choice = wd.check_region_replies(EMAIL_CONFIG, {"region_menus": [MENU]}, NOW)
        self.assertIsNone(choice)
        self.assertIn("Couldn't check for replies", self.logged())

    def test_switching_overrides_the_region_and_replaces_now(self):
        state = {"region_menus": [MENU], "failed_replacements": 3}
        with mock.patch.object(wd, "check_once", return_value=("replaced", {"last_server_ip": "1.2.3.4"})) as check:
            event, _ = wd.switch_region(EMAIL_CONFIG, EMAIL_CONFIG, state, "us_south_west", NOW)
        self.assertEqual(event, "replaced")
        config, passed_state, _ = check.call_args.args
        self.assertEqual(config["region_id"], "us_south_west")
        self.assertTrue(check.call_args.kwargs["replace_now"])
        self.assertEqual(passed_state["region_override"], {"id": "us_south_west", "base": "us_houston"})
        self.assertEqual(passed_state["failed_replacements"], 0)
        self.assertNotIn("region_menus", passed_state)
        self.assertEqual(self.mocks["notify"].call_args.args[1], "Switched to US Texas")

    def test_switching_back_to_the_configured_region_drops_the_override(self):
        current = wd.with_region_override(EMAIL_CONFIG, {"region_override": {"id": "us_denver", "base": "us_houston"}})
        state = {"region_override": {"id": "us_denver", "base": "us_houston"}}
        with mock.patch.object(wd, "check_once", return_value=("replaced", {})) as check:
            wd.switch_region(EMAIL_CONFIG, current, state, "us_houston", NOW)
        self.assertNotIn("region_override", check.call_args.args[1])

    def test_asking_for_the_current_region_changes_nothing(self):
        with mock.patch.object(wd, "check_once", return_value=("healthy", {})) as check:
            wd.switch_region(EMAIL_CONFIG, EMAIL_CONFIG, {}, "us_houston", NOW)
        self.assertNotIn("replace_now", check.call_args.kwargs)
        self.assertEqual(self.mocks["notify"].call_args.args[1], "Already using US Houston")

    def test_override_applies_until_the_config_file_changes(self):
        state = {"region_override": {"id": "us_denver", "base": "us_houston"}}
        self.assertEqual(wd.with_region_override(EMAIL_CONFIG, state)["region_id"], "us_denver")
        edited = {**EMAIL_CONFIG, "region_id": "us_atlanta"}
        self.assertEqual(wd.with_region_override(edited, state)["region_id"], "us_atlanta")

    def test_the_capped_email_carries_the_menu_and_remembers_it(self):
        self.mocks["send_email"].return_value = "<menu-2@gmail.com>"
        with mock.patch.object(wd, "region_menu", return_value=("MENU TEXT", ["us_south_west"])):
            state = wd.send_alert(EMAIL_CONFIG, {}, "capped", NOW)
        body = self.mocks["send_email"].call_args.args[2]
        self.assertIn("MENU TEXT", body)
        self.assertTrue(body.rstrip().endswith("days."))  # the stats stay last
        self.assertEqual(state["region_menus"],
                         [{"message_id": "<menu-2@gmail.com>", "options": ["us_south_west"], "sent_at": NOW}])

    def test_other_alerts_have_no_menu(self):
        with mock.patch.object(wd, "region_menu") as menu:
            wd.send_alert(EMAIL_CONFIG, {}, "pia_login", NOW)
        menu.assert_not_called()


if __name__ == "__main__":
    unittest.main()
