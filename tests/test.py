import collections
import ipaddress
import os
import sys
import unittest
from typing import Callable, List
from assertpy import assert_that
from mock.mock import call, patch

from dynamicdns.backend import DynamicBackend


def _get_test_config_filename(filename: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)


class DynamicBackendTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.clear()
        self.mock_sys_patcher = patch("dynamicdns.backend.sys")
        self.mock_sys = self.mock_sys_patcher.start()

        real_std_error_write: Callable[[str], int] = sys.stderr.write
        self.mock_sys.stderr.write = real_std_error_write

        import dynamicdns

        dynamicdns.backend._is_debug = lambda: True

    def tearDown(self) -> None:
        sys.stderr.flush()

        self.mock_sys_patcher.stop()         

    def _run_backend(self) -> None:
        backend = self._create_backend()
        backend.run()

    def _run_backend_without_whitelist(self) -> None:
        backend = self._create_backend()
        backend.whitelisted_ranges = []
        backend.run()

    def _send_commands(self, *commands: List[str]) -> None:
        commands_to_send = ["HELO\t5\n"]

        for command in commands:
            commands_to_send.append("\t".join(command) + "\n")

        commands_to_send.append("END\n")

        self.mock_sys.stdin.readline.side_effect = commands_to_send

    def _assert_expected_responses(self, *responses: List[str]) -> None:
        calls = [
            call("OK"),
            call("\t"),
            call("ns53.me backend - We are good"),
            call("\n"),
        ]

        for response in responses:
            tab_separated = ["\t"] * (len(response) * 2 - 1)
            tab_separated[0::2] = response
            tab_separated.append("\n")

            calls.extend([call(response_item) for response_item in tab_separated])

        calls.extend(
            [
                call("END"),
                call("\n"),
            ]
        )

        self.mock_sys.stdout.write.assert_has_calls(calls)
        assert_that(self.mock_sys.stdout.write.call_count).is_equal_to(len(calls))

        assert_that(self.mock_sys.stdout.flush.call_count).is_equal_to(
            len(responses) + 2
        )

    @staticmethod
    def _create_backend() -> DynamicBackend:
        backend = DynamicBackend()
        backend.id = "22"
        backend.soa = "MY_SOA"
        backend.ip_address = "127.0.0.33"
        backend.ttl = "200"
        backend.name_servers = collections.OrderedDict(
            [
                ("ns1.ns53.me", "127.0.0.54"),
                ("ns2.ns53.me", "127.0.0.55"),
            ]
        )
        backend.tld = ".me"
        backend.domain = "ns53.me"
        backend.whitelisted_ranges = [
            # This allows us to test that the blacklist works even when the IPs are
            # part of whitelisted ranges
            ipaddress.IPv4Network("100.64.1.0/24"),
            ipaddress.IPv4Network("100.65.1.0/24"),
        ]
        backend.blacklisted_ips = ["100.64.0.1"]
        return backend

    @staticmethod
    def _configure_backend(filename: str = "backend_test.conf") -> DynamicBackend:
        backend = DynamicBackend()
        backend.configure(_get_test_config_filename(filename))
        return backend
    
    def test_backend_responds_to_A_request_2octed_with_valid_ip(self) -> None:
        self._send_commands(["Q", "apps.f1.ns53.me", "IN", "A", "1", "100.64.1.100"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "0", "1", "apps.f1.ns53.me", "IN", "A", "200", "22", "100.64.1.100"],
            ["DATA", "0", "1", "apps.f1.ns53.me", "IN", "NS", "200", "22", "ns1.ns53.me"],
            ["DATA", "0", "1", "apps.f1.ns53.me", "IN", "NS", "200", "22", "ns2.ns53.me"],
        )           

    def test_backend_responds_to_A_request_3octed_with_valid_ip(self) -> None:
        self._send_commands(["Q", "app5.f1.ns53.me", "IN", "A", "1", "100.64.1.5"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "0", "1", "app5.f1.ns53.me", "IN", "A", "200", "22", "100.64.1.5"],
            ["DATA", "0", "1", "app5.f1.ns53.me", "IN", "NS", "200", "22", "ns1.ns53.me"],
            ["DATA", "0", "1", "app5.f1.ns53.me", "IN", "NS", "200", "22", "ns2.ns53.me"],
        )             

    def test_backend_responds_to_A_request_4octed_with_valid_ip(self) -> None:
        self._send_commands(["Q", "app5.f1.d65.ns53.me", "IN", "A", "1", "100.65.1.5"])

        self._run_backend()

        self._assert_expected_responses(
            ["DATA", "0", "1", "app5.f1.d65.ns53.me", "IN", "A", "200", "22", "100.65.1.5"],
            ["DATA", "0", "1", "app5.f1.d65.ns53.me", "IN", "NS", "200", "22", "ns1.ns53.me"],
            ["DATA", "0", "1", "app5.f1.d65.ns53.me", "IN", "NS", "200", "22", "ns2.ns53.me"],
        )              

if __name__ == '__main__':
    unittest.main()    