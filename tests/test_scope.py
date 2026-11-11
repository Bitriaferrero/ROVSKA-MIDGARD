#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests del control de alcance."""

from __future__ import annotations

import unittest

from rovvska.config import Settings
from rovvska.scope import ScopeError, check_target, expand_hosts


class ScopeTests(unittest.TestCase):
    def test_private_cidr_allowed(self) -> None:
        decision = check_target("192.168.1.0/24", Settings())
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.public)
        self.assertEqual(decision.host_count, 256)

    def test_public_blocked_by_default(self) -> None:
        decision = check_target("8.8.8.8", Settings())
        self.assertFalse(decision.allowed)
        self.assertIn("público", decision.reason)

    def test_public_requires_authorization(self) -> None:
        settings = Settings(allow_public=True)
        self.assertFalse(check_target("8.8.8.8", settings, authorization=False).allowed)
        self.assertTrue(check_target("8.8.8.8", settings, authorization=True).allowed)

    def test_allowed_cidrs(self) -> None:
        settings = Settings(allow_public=True, allowed_cidrs=("203.0.113.0/24",))
        self.assertTrue(check_target("203.0.113.0/24", settings, authorization=True).allowed)
        self.assertFalse(check_target("198.51.100.0/24", settings, authorization=True).allowed)

    def test_max_hosts(self) -> None:
        decision = check_target("10.0.0.0/16", Settings(max_hosts=64))
        self.assertFalse(decision.allowed)
        self.assertIn("máximo", decision.reason)

    def test_invalid_target(self) -> None:
        with self.assertRaises(ScopeError):
            check_target("192.168.1.1; rm -rf /", Settings())
        with self.assertRaises(ScopeError):
            check_target("", Settings())

    def test_expand_hosts(self) -> None:
        hosts = expand_hosts("10.0.0.0/30")
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(expand_hosts("10.0.0.5"), ["10.0.0.5"])


if __name__ == "__main__":
    unittest.main()
