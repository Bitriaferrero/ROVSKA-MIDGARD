"""Tests de alcance y perfiles."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from midgard import profiles, scope


class ScopeTests(unittest.TestCase):
    def test_private_network_allowed(self):
        net = scope.validate("192.168.88.0/24")
        self.assertEqual(str(net), "192.168.88.0/24")

    def test_single_private_ip(self):
        net = scope.validate("10.1.2.3")
        self.assertEqual(str(net.network_address), "10.1.2.3")

    def test_public_denied_without_authorization(self):
        with self.assertRaises(scope.ScopeError):
            scope.validate("8.8.8.8")

    def test_public_denied_with_flag_but_without_env(self):
        with mock.patch.dict(os.environ, {"MIDGARD_ALLOW_PUBLIC": "0"}):
            with self.assertRaises(scope.ScopeError):
                scope.validate("8.8.8.8", authorized=True)

    def test_public_allowed_with_flag_and_env(self):
        with mock.patch.dict(os.environ, {"MIDGARD_ALLOW_PUBLIC": "1"}):
            net = scope.validate("8.8.8.8/32", authorized=True)
            self.assertEqual(str(net.network_address), "8.8.8.8")

    def test_public_range_too_broad(self):
        with mock.patch.dict(os.environ, {"MIDGARD_ALLOW_PUBLIC": "1"}):
            with self.assertRaises(scope.ScopeError):
                scope.validate("8.8.0.0/16", authorized=True)
            with self.assertRaises(scope.ScopeError):
                scope.validate("0.0.0.0/0", authorized=True)

    def test_hostname_rejected(self):
        with self.assertRaises(scope.ScopeError):
            scope.validate("example.com")

    def test_injection_rejected(self):
        with self.assertRaises(scope.ScopeError):
            scope.validate("192.168.1.1; rm -rf /")
        with self.assertRaises(scope.ScopeError):
            scope.validate("-sS 192.168.1.1")


class ProfileTests(unittest.TestCase):
    def test_all_profiles_load(self):
        items = profiles.load_all()
        for expected in ("discovery", "quick", "web", "infra", "router", "full", "custom"):
            self.assertIn(expected, items)

    def test_unknown_profile(self):
        with self.assertRaises(profiles.ProfileError):
            profiles.get("no-existe")


if __name__ == "__main__":
    unittest.main()
