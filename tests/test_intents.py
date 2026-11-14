import unittest
from types import SimpleNamespace
from unittest import mock

from omarchy_voice import intents
from omarchy_voice.intents import (binding_commands, clean, drop_articles, is_address_bar,
                                   match_binding, parse_binding_records, volume_level,
                                   volume_step)


class CleanTests(unittest.TestCase):
    def test_wake_word_politeness_and_punctuation_go(self):
        self.assertEqual(clean("Hey Oma, could you turn the volume up please."),
                         "turn the volume up")
        self.assertEqual(clean("Can you please open the terminal for me?"), "open the terminal")

    def test_spoken_numbers_become_digits(self):
        self.assertEqual(clean("Go to workspace three"), "go to workspace 3")
        self.assertEqual(clean("volume to forty five percent"), "volume to 45%")
        self.assertEqual(clean("set volume to a hundred"), "set volume to 100")

    def test_articles_drop_for_a_second_try(self):
        self.assertEqual(drop_articles("close the window"), "close window")


class VolumeTests(unittest.TestCase):
    def test_levels(self):
        for said, level in [("volume to max", 100), ("max volume", 100),
                            ("turn the volume all the way up", 100),
                            ("set the volume to 50%", 50), ("volume 30", 30),
                            ("volume to half", 50), ("turn it down to 20", 20),
                            ("volume at minimum", 0), ("volume to 250", 100)]:
            with self.subTest(said):
                self.assertEqual(volume_level(clean(said)), level)

    def test_plain_up_and_down_are_not_levels(self):
        for said in ("volume up", "volume down", "turn it up", "mute"):
            with self.subTest(said):
                self.assertIsNone(volume_level(clean(said)))

    def test_steps(self):
        for said, step in [("turn the volume up", "raise"), ("turn it up a bit", "raise"),
                           ("make it louder", "raise"), ("turn down the volume", "lower"),
                           ("quieter", "lower"), ("volume up by 10", "+10"),
                           ("lower the volume by 15 percent", "-15")]:
            with self.subTest(said):
                self.assertEqual(volume_step(clean(said)), step)


class AddressBarTests(unittest.TestCase):
    def test_phrasings(self):
        for said in ("focus the address bar", "go to the URL bar", "click on the search bar",
                     "address bar", "select the browser's address bar"):
            with self.subTest(said):
                self.assertTrue(is_address_bar(clean(said)))
        self.assertFalse(is_address_bar(clean("open github")))


RECORDS = "\n".join([
    "SUPER + RETURN                      → Terminal\texec\tomarchy-launch-terminal",
    "SUPER SHIFT + B                     → Browser\texec\tomarchy-launch-browser",
    "SUPER SHIFT ALT + B                 → Browser (private)\texec\tomarchy-launch-browser --private",
    "SUPER + T                           → Toggle window floating/tiling\tlua\thl.dsp.window.float({ action = \"toggle\" })",
    "SUPER CTRL + N                      → Toggle nightlight\texec\tomarchy-toggle-nightlight",
    "SUPER + LEFT                        → Focus on left window\tlua\thl.dsp.focus({ direction = \"l\" })",
    "SUPER + PRINT                       → Color picker\texec\thyprpicker -a",
    "SUPER ALT + PRINT                   → Screenrecording\texec\tomarchy-menu screenrecord",
    "SUPER + ESCAPE                      → Power menu\texec\tomarchy-menu system",
    "SUPER SHIFT + W                     → Close all windows\texec\tomarchy-close-all",
    "SUPER + K                           → Show key bindings\texec\tomarchy-menu-keybindings",
    "SUPER CTRL + L                      → Lock system\texec\tomarchy-lock-screen",
])


class BindingTests(unittest.TestCase):
    rows = parse_binding_records(RECORDS)

    def said(self, text):
        row = match_binding(clean(text), self.rows)
        return row["action"] if row else None

    def test_records_parse(self):
        self.assertEqual(len(self.rows), 12)
        self.assertEqual(self.rows[0], {"chords": "SUPER + RETURN", "action": "Terminal",
                                        "dispatcher": "exec", "arg": "omarchy-launch-terminal"})

    def test_descriptions_match_the_way_people_say_them(self):
        for text, action in [("open the terminal", "Terminal"),
                             ("terminal", "Terminal"),
                             ("browser", "Browser"),
                             ("open a private browser", "Browser (private)"),
                             ("toggle window floating", "Toggle window floating/tiling"),
                             ("turn on the night light", "Toggle nightlight"),
                             ("focus left window", "Focus on left window"),
                             ("open the colour picker", "Color picker"),
                             ("start screen recording", "Screenrecording"),
                             ("show keyboard shortcuts", "Show key bindings"),
                             ("lock the screen", "Lock system"),
                             ("power menu", "Power menu")]:
            with self.subTest(text):
                self.assertEqual(self.said(text), action)

    def test_risky_rows_and_unknown_words_do_not_match(self):
        self.assertIsNone(self.said("close all windows"))
        self.assertIsNone(self.said("open my github notifications"))
        self.assertIsNone(self.said("the"))

    def test_rows_run_the_way_the_menu_runs_them(self):
        exec_row = {"dispatcher": "exec", "arg": "omarchy-launch-browser --private"}
        self.assertEqual(binding_commands(exec_row)[0],
                         ["hyprctl", "dispatch",
                          'hl.dsp.exec_cmd("omarchy-launch-browser --private")'])
        lua_row = {"dispatcher": "lua", "arg": 'hl.dsp.focus({ direction = "l" })'}
        self.assertEqual(binding_commands(lua_row),
                         [["hyprctl", "dispatch", 'hl.dsp.focus({ direction = "l" })']])
        self.assertEqual(binding_commands({"dispatcher": "killactive", "arg": ""}),
                         [["hyprctl", "dispatch", "killactive"]])


class QuickCommandTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        patches = [
            mock.patch("omarchy_voice.mobile_bridge.write_log"),
            mock.patch("omarchy_voice.tools.Executor.call",
                       side_effect=lambda name, args: self.calls.append((name, args))
                       or SimpleNamespace(ok=True, output="")),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_volume_to_max_is_one_exact_step(self):
        from omarchy_voice.mobile_bridge import _quick_command
        pactl = SimpleNamespace(returncode=0, stdout="Volume: front-left: 19661 /  30% / -31 dB")
        with mock.patch("omarchy_voice.mobile_bridge._run", return_value=pactl):
            reply = _quick_command("Hey Oma, volume to max please.")
        self.assertEqual(reply, "Volume set to 100%.")
        self.assertEqual(self.calls, [("omarchy_cli", {"command": "audio output volume +70"})])

    def test_volume_level_without_a_reading_goes_through_zero(self):
        from omarchy_voice.mobile_bridge import _quick_command
        with mock.patch("omarchy_voice.mobile_bridge._run", side_effect=FileNotFoundError):
            _quick_command("set the volume to 40 percent")
        self.assertEqual([c[1]["command"] for c in self.calls],
                         ["audio output volume -100", "audio output volume +40"])

    def test_turn_the_volume_up_is_a_step(self):
        from omarchy_voice.mobile_bridge import _quick_command
        self.assertEqual(_quick_command("Could you turn the volume up?"), "Volume raised.")
        self.assertEqual(self.calls, [("omarchy_cli", {"command": "audio output volume raise"})])

    def test_a_keybinding_description_runs_its_row(self):
        from omarchy_voice import mobile_bridge
        rows = parse_binding_records(RECORDS)
        done = SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(mobile_bridge, "_omarchy_bindings", return_value=rows), \
             mock.patch.object(mobile_bridge, "_run", return_value=done) as run:
            reply = mobile_bridge._quick_command("turn on the night light")
        self.assertEqual(reply, "Toggle nightlight.")
        run.assert_called_once_with(
            ["hyprctl", "dispatch", 'hl.dsp.exec_cmd("omarchy-toggle-nightlight")'],
            capture_output=True, text=True, timeout=5)

    def test_typed_text_keeps_its_case(self):
        from omarchy_voice import mobile_bridge
        with mock.patch.object(mobile_bridge, "_type_text", return_value=(True, "")) as typed:
            mobile_bridge._quick_command("Hey Oma, type Hello World")
        typed.assert_called_once_with("Hello World", enter=False)

    def test_open_ended_requests_still_go_to_the_ai(self):
        from omarchy_voice import mobile_bridge
        with mock.patch.object(mobile_bridge, "_omarchy_bindings", return_value=[]):
            self.assertIsNone(mobile_bridge._quick_command(
                "open my github notifications and read the first one"))


if __name__ == "__main__":
    unittest.main()
