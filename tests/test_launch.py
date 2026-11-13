"""Apps started from the phone run as the session, not inside the service sandbox."""

import json
import shlex
import unittest
from types import SimpleNamespace
from unittest import mock

from omarchy_voice import tools
from omarchy_voice.tools import Executor


class LaunchInSessionTests(unittest.TestCase):
    def _run(self, cmd, sandboxed, eval_reply="ok", eval_rc=0, hyprctl=True):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=eval_rc, stdout=eval_reply + "\n", stderr="")

        popen = mock.MagicMock()
        popen.return_value.communicate.side_effect = __import__("subprocess").TimeoutExpired(cmd, 0.5)
        with mock.patch.object(tools, "_in_service_sandbox", return_value=sandboxed), \
             mock.patch("omarchy_voice.tools.shutil.which", return_value="/usr/bin/hyprctl" if hyprctl else None), \
             mock.patch("omarchy_voice.tools.subprocess.run", side_effect=run), \
             mock.patch("omarchy_voice.tools.subprocess.Popen", popen), \
             mock.patch("omarchy_voice.tools.threading.Thread"):
            result = Executor._run_command(cmd, timeout=10, grace=0.5)
        return result, calls, popen

    def test_under_the_sandbox_hyprland_starts_the_terminal(self):
        result, calls, popen = self._run(["omarchy", "launch", "terminal"], sandboxed=True)
        self.assertTrue(result.ok)
        self.assertEqual(len(calls), 1)
        argv = calls[0]
        self.assertEqual(argv[:2], ["hyprctl", "eval"])
        self.assertEqual(argv[2], f"hl.exec_cmd({json.dumps('omarchy launch terminal')})")
        popen.assert_not_called()

    def test_arguments_are_quoted_for_the_shell(self):
        _, calls, _ = self._run(["omarchy", "launch", "terminal", "btop; rm -rf ~"], sandboxed=True)
        inner = json.loads(calls[0][2][len("hl.exec_cmd("):-1])
        self.assertEqual(shlex.split(inner), ["omarchy", "launch", "terminal", "btop; rm -rf ~"])

    def test_outside_the_sandbox_it_starts_the_app_itself(self):
        result, calls, popen = self._run(["omarchy", "launch", "terminal"], sandboxed=False)
        self.assertTrue(result.ok)
        self.assertEqual(calls, [])
        popen.assert_called_once()

    def test_when_hyprland_refuses_it_still_starts_the_app(self):
        result, calls, popen = self._run(["omarchy", "launch", "terminal"], sandboxed=True,
                                         eval_reply="error: no such function")
        self.assertTrue(result.ok)
        popen.assert_called_once()

    def test_without_hyprctl_it_starts_the_app_itself(self):
        _, calls, popen = self._run(["omarchy", "launch", "terminal"], sandboxed=True, hyprctl=False)
        self.assertEqual(calls, [])
        popen.assert_called_once()

    def test_queries_never_go_through_hyprland(self):
        calls = []
        with mock.patch.object(tools, "_in_service_sandbox", return_value=True), \
             mock.patch("omarchy_voice.tools.subprocess.run", side_effect=lambda *a, **k: calls.append(a)), \
             mock.patch("omarchy_voice.tools.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = ("[]", "")
            popen.return_value.returncode = 0
            Executor._run_command(["hyprctl", "-j", "clients"], timeout=5)
        self.assertEqual(calls, [])


class SandboxDetectionTests(unittest.TestCase):
    def tearDown(self):
        tools._SANDBOXED = None

    def _detect(self, status):
        tools._SANDBOXED = None
        with mock.patch("builtins.open", mock.mock_open(read_data=status)):
            return tools._in_service_sandbox()

    def test_no_new_privs_set_means_sandboxed(self):
        self.assertTrue(self._detect("Name:\tpython3\nNoNewPrivs:\t1\nSeccomp:\t0\n"))

    def test_no_new_privs_clear_means_not(self):
        self.assertFalse(self._detect("Name:\tpython3\nNoNewPrivs:\t0\n"))

    def test_no_proc_means_not(self):
        tools._SANDBOXED = None
        with mock.patch("builtins.open", side_effect=OSError):
            self.assertFalse(tools._in_service_sandbox())


if __name__ == "__main__":
    unittest.main()
