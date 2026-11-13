"""`omadeck log` says what actually ran, not just what was asked."""

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


class LogDetailTests(unittest.TestCase):
    def setUp(self):
        self.lines = []
        patcher = mock.patch("omarchy_voice.mobile_bridge.write_log", side_effect=self.lines.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_command_is_logged_with_its_exit_code_and_error(self):
        from omarchy_voice.mobile_bridge import _run
        failed = SimpleNamespace(returncode=1, stdout="", stderr="no players found\n")
        with mock.patch("omarchy_voice.mobile_bridge.subprocess.run", return_value=failed):
            _run(["playerctl", "play-pause"], capture_output=True, text=True)
        self.assertEqual(len(self.lines), 1)
        self.assertRegex(self.lines[0],
                         r"^exec    playerctl play-pause -> exit 1 \(\d+ ms\): no players found$")

    def test_typed_text_is_counted_not_copied(self):
        from omarchy_voice.mobile_bridge import _run
        done = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch("omarchy_voice.mobile_bridge.subprocess.run", return_value=done):
            _run(["wtype", "--", "hunter2"], capture_output=True, text=True)
        self.assertNotIn("hunter2", self.lines[0])
        self.assertIn("wtype -- '<7 chars>'", self.lines[0])

    def test_a_command_that_cannot_start_is_logged_and_still_raises(self):
        from omarchy_voice.mobile_bridge import _run
        with mock.patch("omarchy_voice.mobile_bridge.subprocess.run",
                        side_effect=FileNotFoundError("omarchy-shell")):
            with self.assertRaises(FileNotFoundError):
                _run(["omarchy-shell", "media", "playPause"])
        self.assertIn("omarchy-shell media playPause -> FileNotFoundError", self.lines[0])

    def test_phone_buttons_log_the_action_and_its_result(self):
        from omarchy_voice.mobile_bridge import _quick_command
        with mock.patch("omarchy_voice.tools.Executor.call",
                        return_value=SimpleNamespace(ok=False, output="no such workspace")):
            _quick_command("next workspace")
        self.assertIn('action  hypr_dispatch({"lua": "hl.dsp.focus({ workspace = \\"e+1\\" })"})',
                      self.lines)
        self.assertIn("result  hypr_dispatch: failed: no such workspace", self.lines)


class ExecutorLogTests(unittest.TestCase):
    def test_every_executor_command_is_logged(self):
        from omarchy_voice.tools import Executor, Result
        lines = []
        with mock.patch("omarchy_voice.feedback.write_log", side_effect=lines.append), \
             mock.patch.object(Executor, "_run_command",
                               return_value=Result(False, "unknown route")):
            Executor._shell(["omarchy", "launch", "nothing"])
        self.assertRegex(lines[0],
                         r"^exec    omarchy launch nothing -> failed \(\d+ ms\): unknown route$")


class LogFileTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_the_log_is_private_to_the_user(self):
        from omarchy_voice import feedback
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "state" / "session.log"
            with mock.patch.object(feedback, "LOG_FILE", log):
                feedback.write_log("phone   test")
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertTrue(log.read_text().endswith("  phone   test\n"))


if __name__ == "__main__":
    unittest.main()
