"""install.sh --quick: the two-minute path to a paired phone.

Runs the real installer in a throwaway HOME with fake hyprctl, systemctl,
pacman and sudo that only log their arguments, so nothing on the machine is
touched. Linux only (CI): it needs bash and the coreutils the installer uses.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bash"),
                     "runs the installer under bash on Linux")
class QuickInstallTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.t = Path(self._tmp.name)
        self.home = self.t / "home"
        (self.home / ".config/omarchy").mkdir(parents=True)
        (self.home / ".config/hypr").mkdir(parents=True)
        self.bindings = self.home / ".config/hypr/bindings.lua"
        self.bindings.write_text("-- existing\n")
        fake = self.t / "fake"
        fake.mkdir()
        self.calls = self.t / "calls.log"
        for name in ("hyprctl", "systemctl", "pacman", "sudo"):
            script = fake / name
            script.write_text(f'#!/bin/sh\necho "{name} $*" >> "{self.calls}"\nexit 0\n')
            script.chmod(0o755)
        # ss that prints nothing: the deck "is not listening", so the installer
        # must explain instead of starting a foreground bridge and hanging.
        (fake / "ss").write_text("#!/bin/sh\nexit 0\n")
        (fake / "ss").chmod(0o755)
        self.env = {**os.environ, "HOME": str(self.home), "PREFIX": str(self.t / "prefix"),
                    "BINDIR": str(self.t / "bin"),
                    "PATH": f"{fake}:{self.t / 'bin'}:{os.environ['PATH']}"}

    def tearDown(self):
        self._tmp.cleanup()

    def run_install(self, *args, stdin=""):
        return subprocess.run(["bash", str(ROOT / "install.sh"), *args], input=stdin,
                              capture_output=True, text=True, env=self.env, timeout=60)

    def test_quick_installs_the_deck_without_asking(self):
        result = self.run_install("--quick")          # stdin is empty: any question would read EOF
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text()
        self.assertIn("systemctl --user enable omadeck.service", calls)
        self.assertIn("systemctl --user restart omadeck.service", calls)
        self.assertNotIn("omarchy-voice.service", calls)            # no voice daemon
        self.assertFalse((self.home / ".config/omarchy/plugins").exists())
        self.assertEqual(self.bindings.read_text(), "-- existing\n")  # no keybinding
        self.assertIn("yes (--quick)", result.stdout)
        self.assertIn("omadeck mobile", result.stdout)
        self.assertNotIn("OPENAI_API_KEY is not set", result.stdout + result.stderr)

    def test_the_full_install_still_asks_and_respects_no(self):
        result = self.run_install(stdin="n\n" * 20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.calls.exists())  # every question answered no
        self.assertIn("Pair a phone with: omadeck mobile", result.stdout)

    def test_an_unknown_option_is_refused(self):
        result = self.run_install("--nope")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown option", result.stderr)


if __name__ == "__main__":
    unittest.main()
