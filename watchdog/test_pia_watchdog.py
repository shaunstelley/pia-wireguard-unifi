"""Run with: python3 -m unittest discover watchdog"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pia_watchdog as wd

CONFIG = {**wd.DEFAULTS, "router_url": "https://router", "router_username": "watchdog",
          "client_name": "PIA US Texas", "pia_username": "p1234567", "region_id": "us_south_west"}
CLIENT = {"_id": "abc", "name": "PIA US Texas",
          "wireguard_client_configuration_file": "[Peer]\nEndpoint = 209.87.164.32:1337\n"}
NOW = 1_000_000.0


class DecideTests(unittest.TestCase):
    def test_healthy_resets_the_count(self):
        action, state = wd.decide({"unhealthy_checks": 2, "replacements": []}, True, CONFIG, NOW)
        self.assertEqual((action, state["unhealthy_checks"]), ("healthy", 0))

    def test_waits_until_the_threshold(self):
        action, state = wd.decide({"unhealthy_checks": 0, "replacements": []}, False, CONFIG, NOW)
        self.assertEqual((action, state["unhealthy_checks"]), ("waiting", 1))

    def test_replaces_at_the_threshold(self):
        action, _ = wd.decide({"unhealthy_checks": 2, "replacements": []}, False, CONFIG, NOW)
        self.assertEqual(action, "replace")

    def test_caps_replacements_per_day_and_forgets_old_ones(self):
        recent = [NOW - 60] * 4
        self.assertEqual(wd.decide({"unhealthy_checks": 2, "replacements": recent}, False, CONFIG, NOW)[0], "capped")
        old = [NOW - wd.DAY_SECONDS - 1] * 4
        action, state = wd.decide({"unhealthy_checks": 2, "replacements": old}, False, CONFIG, NOW)
        self.assertEqual((action, state["replacements"]), ("replace", []))


class EndpointTests(unittest.TestCase):
    def test_reads_the_server_ip(self):
        self.assertEqual(wd.endpoint_ip(CLIENT["wireguard_client_configuration_file"]), "209.87.164.32")
        self.assertIsNone(wd.endpoint_ip(None))


class GenerateConfTests(unittest.TestCase):
    REGION = {"id": "us_south_west", "name": "US Texas",
              "servers": {"wg": [{"ip": "1.1.1.1", "cn": "a"}, {"ip": "2.2.2.2", "cn": "b"}]}}

    def run_generate(self, write_conf, avoid=None):
        pc = wd.pia_config
        with mock.patch.object(pc, "fetch_regions", return_value=[self.REGION]), \
             mock.patch.object(pc, "fetch_token", return_value="token"), \
             mock.patch.object(pc, "_write_conf", side_effect=write_conf) as write:
            result = pc.generate_conf("u", "p", "us_south_west", True, avoid_server_ip=avoid)
        return result, [c.args[1]["ip"] for c in write.call_args_list]

    def test_tries_other_servers_before_the_one_to_avoid(self):
        result, tried = self.run_generate(lambda token, server, dns: "CONF", avoid="1.1.1.1")
        self.assertEqual((result, tried), (("CONF", "US Texas", "2.2.2.2"), ["2.2.2.2"]))

    def test_falls_back_when_a_server_refuses(self):
        def write(token, server, dns):
            if server["ip"] == "2.2.2.2":
                raise RuntimeError("Server did not return OK")
            return "CONF"
        result, tried = self.run_generate(write, avoid="1.1.1.1")
        self.assertEqual((result[2], tried), ("1.1.1.1", ["2.2.2.2", "1.1.1.1"]))


class CheckOnceTests(unittest.TestCase):
    def setUp(self):
        self.creds = tempfile.TemporaryDirectory()
        for name in ("pia_password", "router_password"):
            Path(self.creds.name, name).write_text("secret\n")
        env = mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": self.creds.name})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(self.creds.cleanup)
        self.rp = mock.patch.multiple(
            wd.router_push,
            login=mock.Mock(return_value=("opener", "csrf")),
            find_wireguard_client=mock.Mock(return_value=CLIENT),
            wireguard_client_health=mock.Mock(return_value=(False, "status DISCONNECTED")),
            update_wireguard_client=mock.Mock(),
            routes_through_client=mock.Mock(return_value=False),
        )
        self.rp.start()
        self.addCleanup(self.rp.stop)
        patcher = mock.patch.multiple(wd, log=mock.DEFAULT, lan_ip_toward=mock.Mock(return_value="192.168.11.151"))
        self.mocks = patcher.start()
        self.addCleanup(patcher.stop)
        token = mock.patch.object(wd.pia_config, "fetch_token", return_value="token")
        self.fetch_token = token.start()
        self.addCleanup(token.stop)

    def logged(self):
        return " ".join(str(c.args[0]) for c in self.mocks["log"].call_args_list)

    def test_dry_run_checks_pia_login_but_changes_nothing(self):
        with mock.patch.object(wd.pia_config, "generate_conf") as generate:
            code, state = wd.check_once(CONFIG, {"unhealthy_checks": 2, "replacements": []}, NOW)
        self.assertEqual(code, 0)
        self.fetch_token.assert_called_once_with("p1234567", "secret")
        generate.assert_not_called()
        wd.router_push.update_wireguard_client.assert_not_called()
        self.assertEqual(state["replacements"], [])

    def test_replaces_avoiding_the_current_server(self):
        config = {**CONFIG, "dry_run": False}
        with mock.patch.object(wd.pia_config, "generate_conf",
                               return_value=("NEW CONF", "US Texas", "209.87.164.40")) as generate:
            code, state = wd.check_once(config, {"unhealthy_checks": 2, "replacements": []}, NOW)
        self.assertEqual(code, 0)
        self.assertEqual(generate.call_args.kwargs["avoid_server_ip"], "209.87.164.32")
        wd.router_push.update_wireguard_client.assert_called_once_with(
            "opener", "csrf", "https://router", CLIENT, "NEW CONF", "pia-us_south_west.conf")
        self.assertEqual((state["replacements"], state["last_server_ip"]), ([NOW], "209.87.164.40"))

    def test_missing_client_is_an_error(self):
        wd.router_push.find_wireguard_client.return_value = None
        code, _ = wd.check_once(CONFIG, {"unhealthy_checks": 0, "replacements": []}, NOW)
        self.assertEqual(code, 1)

    def test_replace_now_ignores_dry_run_and_health(self):
        with mock.patch.object(wd.pia_config, "generate_conf", return_value=("NEW", "US Texas", "2.2.2.2")):
            code, state = wd.check_once(CONFIG, {"unhealthy_checks": 0, "replacements": []}, NOW, replace_now=True)
        self.assertEqual((code, state["replacements"]), (0, [NOW]))
        wd.router_push.wireguard_client_health.assert_not_called()
        wd.router_push.update_wireguard_client.assert_called_once()

    def test_warns_when_this_machine_is_routed_through_the_client(self):
        wd.router_push.routes_through_client.return_value = True
        wd.router_push.wireguard_client_health.return_value = (True, "status CONNECTED")
        wd.check_once(CONFIG, {"unhealthy_checks": 0, "replacements": []}, NOW)
        self.assertIn("is routed through 'PIA US Texas'", self.logged())

    def test_checks_the_pia_login_once_a_day_while_healthy(self):
        wd.router_push.wireguard_client_health.return_value = (True, "status CONNECTED")
        code, state = wd.check_once(CONFIG, {"unhealthy_checks": 0, "replacements": []}, NOW)
        self.assertEqual((code, state["pia_login_checked_at"]), (0, NOW))
        self.fetch_token.reset_mock()
        code, _ = wd.check_once(CONFIG, state, NOW + 300)
        self.assertEqual(code, 0)
        self.fetch_token.assert_not_called()

    def test_a_rejected_pia_password_fails_the_run(self):
        wd.router_push.wireguard_client_health.return_value = (True, "status CONNECTED")
        self.fetch_token.side_effect = RuntimeError("PIA login failed: HTTP 401")
        code, state = wd.check_once(CONFIG, {"unhealthy_checks": 0, "replacements": []}, NOW)
        self.assertEqual(code, 1)
        self.assertNotIn("pia_login_checked_at", state)
        self.assertIn("update the stored PIA password", self.logged())

    def test_verify_reports_both_logins(self):
        wd.router_push.wireguard_client_health.return_value = (True, "status CONNECTED, server 1.2.3.4")
        self.assertEqual(wd.verify(CONFIG), 0)
        self.assertIn("Router login OK", self.logged())
        self.assertIn("PIA login OK", self.logged())

    def test_verify_still_checks_pia_when_the_router_fails(self):
        wd.router_push.login.side_effect = wd.router_push.RouterLoginError("Login failed: HTTP 401")
        self.fetch_token.side_effect = RuntimeError("PIA login failed: HTTP 401")
        self.assertEqual(wd.verify(CONFIG), 1)
        self.assertIn("Router: Login failed", self.logged())
        self.assertIn("PIA login failed", self.logged())

    def test_unreachable_pia_is_not_called_a_password_problem(self):
        wd.router_push.wireguard_client_health.return_value = (True, "status CONNECTED")
        self.fetch_token.side_effect = OSError("timed out")
        code, _ = wd.check_once(CONFIG, {"unhealthy_checks": 0, "replacements": []}, NOW)
        self.assertEqual(code, 1)
        self.assertIn("Couldn't reach PIA", self.logged())
        self.assertNotIn("password", self.logged())


class RouterCallTests(unittest.TestCase):
    """Fake router responses shaped like the real ones captured from a Dream Router."""
    CLIENT_ID = "6adff10fb4f6b2b9a549482d"
    DEFAULT_NET = "6a87c0526b64167f50ec41b4"

    def call(self, fn, responses, *args):
        with mock.patch.object(wd.router_push, "_authed_request", side_effect=responses) as req:
            return fn("opener", "csrf", "https://router", *args), req

    def test_health_reads_the_clients_status(self):
        client = {"_id": self.CLIENT_ID}
        conn = {"network_id": self.CLIENT_ID, "status": "CONNECTED", "remote_ip": "209.87.164.34", "notes": []}
        (healthy, _), _ = self.call(wd.router_push.wireguard_client_health, [{"connections": [conn]}], client)
        self.assertTrue(healthy)
        (healthy, detail), _ = self.call(
            wd.router_push.wireguard_client_health, [{"connections": [{**conn, "status": "DISCONNECTED"}]}], client)
        self.assertEqual((healthy, detail), (False, "status DISCONNECTED, server 209.87.164.34"))
        (healthy, _), _ = self.call(wd.router_push.wireguard_client_health, [{"connections": []}], client)
        self.assertFalse(healthy)

    def test_update_puts_the_record_back_with_only_the_config_changed(self):
        client = {"_id": self.CLIENT_ID, "name": "PIA US Texas", "wireguard_id": 4, "ip_subnet": "10.0.0.1/32",
                  "wireguard_client_configuration_file": "OLD", "wireguard_client_configuration_filename": "old.conf"}
        _, req = self.call(wd.router_push.update_wireguard_client, [{"meta": {"rc": "ok"}, "data": [{}]}],
                           client, "NEW", "pia-us_south_west.conf")
        url, body = req.call_args.args[2], req.call_args.kwargs["body"]
        self.assertTrue(url.endswith(f"/rest/networkconf/{self.CLIENT_ID}"))
        self.assertEqual(req.call_args.kwargs["method"], "PUT")
        self.assertEqual(body, {"_id": self.CLIENT_ID, "name": "PIA US Texas", "wireguard_id": 4,
                                "wireguard_client_configuration_file": "NEW",
                                "wireguard_client_configuration_filename": "pia-us_south_west.conf"})

    def test_detects_a_device_routed_via_its_network(self):
        routes = [{"enabled": True, "network_id": self.CLIENT_ID,
                   "target_devices": [{"type": "NETWORK", "network_id": self.DEFAULT_NET}]}]
        devices = [{"ip": "192.168.11.151", "mac": "e4:5f:01:7d:84:ca", "network_id": self.DEFAULT_NET}]
        client = {"_id": self.CLIENT_ID}
        routed, _ = self.call(wd.router_push.routes_through_client, [routes, devices], client, "192.168.11.151")
        self.assertTrue(routed)
        other_device = [{"type": "CLIENT", "client_mac": "aa:bb:cc:dd:ee:ff"}]
        routed, _ = self.call(wd.router_push.routes_through_client,
                              [[{**routes[0], "target_devices": other_device}], devices], client, "192.168.11.151")
        self.assertFalse(routed)


if __name__ == "__main__":
    unittest.main()
