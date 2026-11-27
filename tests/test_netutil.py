"""Tests for artex_antidote._netutil.

Offline and deterministic. Covers valid IPv4/IPv6 (including full-form),
junk input, CIDR strings (networks, not addresses), and the no-stripping
contract: whitespace handling stays at the call sites that already had it.
"""

import unittest

from artex_antidote._netutil import is_valid_ip, valid_ip


class ValidIpTests(unittest.TestCase):
    def test_valid_ipv4_returns_address(self):
        addr = valid_ip("203.0.113.7")
        self.assertIsNotNone(addr)
        self.assertEqual(str(addr), "203.0.113.7")

    def test_valid_ipv6_returns_address(self):
        addr = valid_ip("2001:db8::1")
        self.assertIsNotNone(addr)
        self.assertEqual(str(addr), "2001:db8::1")

    def test_full_form_ipv6_returns_address(self):
        addr = valid_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertIsNotNone(addr)
        self.assertEqual(str(addr), "2001:db8::1")

    def test_junk_returns_none(self):
        self.assertIsNone(valid_ip("not-an-ip"))

    def test_empty_string_returns_none(self):
        self.assertIsNone(valid_ip(""))

    def test_cidr_is_not_an_address(self):
        self.assertIsNone(valid_ip("203.0.113.0/24"))

    def test_whitespace_is_not_stripped(self):
        # Stripping stays at the call sites that already did it (origin,
        # allowlist); the helper itself mirrors ipaddress.ip_address exactly.
        self.assertIsNone(valid_ip(" 203.0.113.7 "))


class IsValidIpTests(unittest.TestCase):
    def test_valid_ipv4_true(self):
        self.assertTrue(is_valid_ip("192.0.2.1"))

    def test_valid_ipv6_true(self):
        self.assertTrue(is_valid_ip("2001:db8::1"))

    def test_junk_false(self):
        self.assertFalse(is_valid_ip("999.1.2.3"))

    def test_cidr_false(self):
        self.assertFalse(is_valid_ip("10.0.0.0/8"))

    def test_whitespace_not_stripped_false(self):
        self.assertFalse(is_valid_ip(" 192.0.2.1"))


if __name__ == "__main__":
    unittest.main()
