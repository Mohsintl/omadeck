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


class UpdateTests(unittest.TestCase):
    """`omadeck update`: pull the source checkout, reinstall, restart."""

    def setUp(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.prefix = Path(tmp.name) / "prefix"
        self.source = Path(tmp.name) / "omadeck"
        (self.prefix / "src" / "omarchy_voice").mkdir(parents=True)
        self.source.mkdir()
        (self.source / "install.sh").write_text("#!/bin/sh\n")
        patcher = mock.patch.object(cli, "__file__", str(self.prefix / "src" / "omarchy_voice" / "cli.py"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _update(self, dirty="", pull_rc=0, install_rc=0, heads=("abc1234", "def5678")):
        calls = []
        heads = list(heads)

        def run(argv, **kwargs):
            calls.append(argv)
            if argv[0] == "/usr/bin/git":
                sub = argv[3:]
                if sub[:1] == ["status"]:
                    return SimpleNamespace(returncode=0, stdout=dirty, stderr="")
                if sub == ["rev-parse", "--short", "HEAD"]:
                    return SimpleNamespace(returncode=0, stdout=heads.pop(0) + "\n", stderr="")
                if sub == ["rev-parse", "--abbrev-ref", "HEAD"]:
                    return SimpleNamespace(returncode=0, stdout="main\n", stderr="")
                if sub[:1] == ["pull"]:
                    return SimpleNamespace(returncode=pull_rc)
                return SimpleNamespace(returncode=0, stdout="true\n", stderr="")
            if argv[0] == "bash":
                return SimpleNamespace(returncode=install_rc)
            return SimpleNamespace(returncode=0)

        out = io.StringIO()
        with mock.patch("omarchy_voice.cli.shutil.which", return_value="/usr/bin/git"), \
             mock.patch("omarchy_voice.cli.subprocess.run", side_effect=run), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = cli.cmd_update(SimpleNamespace(), None)
        return code, out.getvalue(), calls

    def _mark_source(self):
        (self.prefix / "source").write_text(str(self.source) + "\n")

    def test_it_pulls_reinstalls_and_restarts_in_that_order(self):
        self._mark_source()
        code, out, calls = self._update()
        self.assertEqual(code, 0)
        steps = [c for c in calls if c[:4] == ["/usr/bin/git", "-C", str(self.source), "pull"]
                 or c[0] == "bash" or c[-1] == "restart"]
        self.assertEqual(steps, [
            ["/usr/bin/git", "-C", str(self.source), "pull", "--ff-only"],
            ["bash", str(self.source / "install.sh"), "--update"],
            [str(self.prefix.resolve() / "bin" / "omarchy-voice"), "restart"],
        ])
        self.assertIn("abc1234 -> def5678", out)

    def test_uncommitted_changes_stop_it_before_anything_runs(self):
        self._mark_source()
        code, out, calls = self._update(dirty=" M src/omarchy_voice/mobile_bridge.py\n")
        self.assertEqual(code, 1)
        self.assertIn("not committed", out)
        self.assertIn("mobile_bridge.py", out)
        self.assertFalse([c for c in calls if "pull" in c or c[0] == "bash"])

    def test_a_failed_pull_installs_nothing(self):
        self._mark_source()
        code, out, calls = self._update(pull_rc=1)
        self.assertEqual(code, 1)
        self.assertFalse([c for c in calls if c[0] == "bash" or c[-1] == "restart"])

    def test_a_failed_install_does_not_restart(self):
        self._mark_source()
        code, out, calls = self._update(install_rc=1)
        self.assertEqual(code, 1)
        self.assertFalse([c for c in calls if c[-1] == "restart"])

    def test_an_install_from_before_this_command_says_to_run_install_once(self):
        code, out, calls = self._update()
        self.assertEqual(code, 1)
        self.assertIn("Run ./install.sh", out)
        self.assertEqual(calls, [])


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
