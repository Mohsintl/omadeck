"""`omadeck restart`: one command instead of two systemd unit names."""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from omarchy_voice import cli  # noqa: E402


def _systemctl(installed: set[str], failing: set[str] = frozenset()):
    """A fake subprocess.run for `systemctl --user cat|restart <unit>`."""
    calls: list[list[str]] = []

    def run(argv, **kwargs):
        calls.append(argv)
        verb, unit = argv[2], argv[3]
        if verb == "cat":
            return SimpleNamespace(returncode=0 if unit in installed else 1, stderr="")
        if unit in failing:
            return SimpleNamespace(returncode=1, stderr="Job failed")
        return SimpleNamespace(returncode=0, stderr="")

    return run, calls


class RestartTests(unittest.TestCase):
    def _restart(self, installed, failing=frozenset()):
        run, calls = _systemctl(installed, failing)
        out = io.StringIO()
        with mock.patch.object(cli.shutil, "which", return_value="/usr/bin/systemctl"), \
             mock.patch.object(cli.subprocess, "run", side_effect=run), \
             contextlib.redirect_stdout(out):
            code = cli.cmd_restart(None, None)
        restarted = [c[3] for c in calls if c[2] == "restart"]
        return code, restarted, out.getvalue()

    def test_restarts_both_services(self):
        code, restarted, _ = self._restart({"omarchy-voice.service", "omadeck.service"})
        self.assertEqual(code, 0)
        self.assertEqual(restarted, ["omarchy-voice.service", "omadeck.service"])

    def test_skips_a_service_that_was_never_installed(self):
        code, restarted, _ = self._restart({"omadeck.service"})
        self.assertEqual(code, 0)
        self.assertEqual(restarted, ["omadeck.service"])

    def test_nothing_installed_says_how_to_install(self):
        code, restarted, out = self._restart(set())
        self.assertEqual(code, 1)
        self.assertEqual(restarted, [])
        self.assertIn("install.sh", out)

    def test_a_failed_restart_is_reported(self):
        code, _, out = self._restart({"omarchy-voice.service", "omadeck.service"},
                                     failing={"omadeck.service"})
        self.assertEqual(code, 1)
        self.assertIn("Job failed", out)

    def test_the_parser_knows_restart(self):
        args = cli.build_parser().parse_args(["restart"])
        self.assertIs(args.func, cli.cmd_restart)


class KillPortCommandTests(unittest.TestCase):
    """`omadeck kill-port N` is what Hyprland runs for the phone's Kill buttons."""

    def _run(self, reply):
        out = io.StringIO()
        with mock.patch("omarchy_voice.mobile_bridge.kill_port", return_value=reply) as kp, \
             mock.patch("omarchy_voice.feedback.write_log") as log, \
             contextlib.redirect_stdout(out):
            code = cli.cmd_kill_port(SimpleNamespace(port=3000), None)
        return code, kp, log, out.getvalue()

    def test_it_kills_without_handing_off_again(self):
        code, kp, log, out = self._run("Killed python3 on port 3000.")
        self.assertEqual(code, 0)
        kp.assert_called_once_with(3000, hand_off=False)
        self.assertIn("kill-port 3000: Killed python3", log.call_args.args[0])
        self.assertIn("Killed python3", out)

    def test_a_failure_exits_non_zero(self):
        code, *_ = self._run("Tried to stop port 3000, but something is still listening.")
        self.assertEqual(code, 1)

    def test_the_parser_knows_kill_port(self):
        args = cli.build_parser().parse_args(["kill-port", "3000"])
        self.assertIs(args.func, cli.cmd_kill_port)
        self.assertEqual(args.port, 3000)


if __name__ == "__main__":
    unittest.main()
