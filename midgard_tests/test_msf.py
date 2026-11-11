"""Tests del plan de Metasploit: solo módulos auxiliary."""

from __future__ import annotations

import unittest

from midgard import msf, nmap


def _host(ip: str = "192.168.88.1") -> nmap.Host:
    return nmap.Host(
        ip=ip,
        ports=[
            nmap.Port(port=22, proto="tcp", state="open", service="ssh"),
            nmap.Port(port=80, proto="tcp", state="open", service="http"),
        ],
    )


class MsfPlanTests(unittest.TestCase):
    def test_generated_plan_only_uses_auxiliary(self) -> None:
        rc = msf.build_rc([_host()], "run-1")
        self.assertTrue(msf.validate_rc(rc))
        modules = [
            line.split(maxsplit=1)[1]
            for line in rc.splitlines()
            if line.strip().startswith("use ")
        ]
        self.assertTrue(modules)
        self.assertTrue(all(module.startswith("auxiliary/") for module in modules))

    def test_exploit_module_is_rejected(self) -> None:
        with self.assertRaises(msf.RCSafetyError):
            msf.validate_rc("use exploit/multi/handler\n")

    def test_post_module_is_rejected(self) -> None:
        with self.assertRaises(msf.RCSafetyError):
            msf.validate_rc("use post/multi/gather/env\n")

    def test_payload_and_sessions_are_rejected(self) -> None:
        with self.assertRaises(msf.RCSafetyError):
            msf.validate_rc("set PAYLOAD linux/x64/meterpreter/reverse_tcp\n")
        with self.assertRaises(msf.RCSafetyError):
            msf.validate_rc("sessions -i 1\n")

    def test_comments_and_empty_timeouts_are_allowed(self) -> None:
        rc = "# comentario\nsetg THREADS 4\nsetg ConnectTimeout 5\nuse auxiliary/scanner/ssh/ssh_version\nrun\nexit -y\n"
        self.assertTrue(msf.validate_rc(rc))

    def test_empty_rc_is_rejected(self) -> None:
        with self.assertRaises(msf.RCSafetyError):
            msf.validate_rc("   \n")


if __name__ == "__main__":
    unittest.main()
