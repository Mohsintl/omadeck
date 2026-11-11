"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import textwrap
import subprocess
import sys
from pathlib import Path

from . import __version__, capabilities, config as cfg, realtime as realtime_mod
from .planner import Planner
from .session import daemon_running, send_control
from .tools import Executor

LISTEN_ACTIONS = ("toggle", "start", "stop", "quit", "confirm", "cancel", "say")


def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m" if sys.stdout.isatty() else text


def _tick(ok: bool) -> str:
    return "\033[32m✓\033[0m" if ok and sys.stdout.isatty() else ("✓" if ok else "✗")


# --- commands ---------------------------------------------------------------

def cmd_say(args, config) -> int:
    """One command, typed instead of spoken. The whole pipeline minus the mic."""
    text = " ".join(args.text)
    print(f'{_bold("heard")}   {text}')

    if daemon_running():
        reply = send_control(f"say {text}")
        print(f'{_bold("reply")}   {reply}')
        return 0

    local_cfg = _get_local_engine_cfg(config)
    if local_cfg.get("engine") == "local":
        from .feedback import Feedback
        from .local_engine import LocalPlanner
        executor = Executor(config)
        planner = LocalPlanner(config, executor, Feedback(config))
        reply = planner.think(text)
        print(f'{_bold("reply")}   {reply}')
        return 0

    executor = Executor(config)
    planner = Planner(config, executor)
    turn = planner.think(text)
    for action in turn.actions:
        print(f'{_bold("action")}  {action}')
    if turn.error:
        print(f'{_bold("error")}   {turn.error}')
    extra = ""
    if turn.tokens:
        extra = (f", {turn.tokens.get('in', 0)} in / {turn.tokens.get('out', 0)} out")
    print(f'{_bold("reply")}   {turn.reply}   \033[2m({turn.elapsed:.1f}s{extra})\033[0m')
    if executor.pending:
        held = executor.describe(*executor.pending)
        if sys.stdin.isatty() and not args.no_confirm:
            print(f'\n{_bold("holding")} {held}')
            if input("        run it? [y/N] ").strip().lower().startswith("y"):
                outcome = executor.run_pending()
                print(f'{_bold("reply")}   {outcome.output or "Done."}')
                return 0 if outcome.ok else 1
            print("        cancelled")
        else:
            print(f'\n{_bold("waiting")} confirm to run: {held}')
        return 0
    return 0 if not turn.error else 1


def _get_local_engine_cfg(config) -> dict:
    """Read [local] section from config.toml without touching Config dataclass."""
    try:
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomllib  # type: ignore[no-redef]
            except ImportError:
                import tomli as tomllib  # type: ignore[no-redef]
        cfg_file = cfg.CONFIG_DIR / "config.toml"
        if cfg_file.exists():
            with cfg_file.open("rb") as fh:
                return tomllib.load(fh).get("local", {})
    except Exception:
        pass
    return {}


def cmd_run(args, config) -> int:
    local_cfg = _get_local_engine_cfg(config)
    if local_cfg.get("engine") == "local":
        from . import local_engine
        return local_engine.run(config)
    return realtime_mod.run(config)


def cmd_listen(args, config) -> int:
    command = args.action
    if args.action == "say":
        if not args.words:
            print("error: listen say needs some text", file=sys.stderr)
            return 1
        command = "say " + " ".join(args.words)
    try:
        print(send_control(command))
    except (ConnectionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


# The voice daemon kept its original unit name; the phone page has its own.
SERVICES = (("omarchy-voice.service", "voice"), ("omadeck.service", "phone page"))


def cmd_restart(args, config) -> int:
    """Restart both services, so nobody has to remember the unit names."""
    if not shutil.which("systemctl"):
        print("error: systemctl not found", file=sys.stderr)
        return 1
    restarted = failed = 0
    for unit, label in SERVICES:
        installed = subprocess.run(["systemctl", "--user", "cat", unit],
                                   capture_output=True, text=True).returncode == 0
        if not installed:
            continue
        result = subprocess.run(["systemctl", "--user", "restart", unit],
                                capture_output=True, text=True)
        if result.returncode == 0:
            restarted += 1
            print(f"  {_tick(True)} restarted {label} ({unit})")
        else:
            failed += 1
            print(f"  {_tick(False)} {label} ({unit}): {result.stderr.strip()}")
    if not restarted and not failed:
        print("No OmaDeck services are installed. Run ./install.sh, or start one by "
              "hand with: omadeck run  /  omadeck mobile")
        return 1
    return 1 if failed else 0


def cmd_kill_port(args, config) -> int:
    """Stop what listens on a port. The phone's Kill buttons run this through
    Hyprland, outside the service sandbox that hides the process."""
    from .feedback import write_log
    from .mobile_bridge import kill_port
    if not 1 <= args.port <= 65535:
        print("error: port must be 1-65535", file=sys.stderr)
        return 1
    reply = kill_port(args.port, hand_off=False)
    write_log(f"result  kill-port {args.port}: {reply}")
    print(reply)
    return 0 if reply.startswith(("Killed", "No process")) else 1


def cmd_status(args, config) -> int:
    state = {"status": "stopped", "text": "", "icon": "󰍭"}
    if cfg.STATE_FILE.exists():
        try:
            state = json.loads(cfg.STATE_FILE.read_text())
        except json.JSONDecodeError:
            pass
    if not daemon_running():
        state["status"] = "stopped"
        state["icon"] = "󰍭"
        state["class"] = "stopped"
        state["text"] = ""
    if args.json:
        print(json.dumps(state))
    else:
        print(f'{state["icon"]}  {state["status"]}'
              + (f'  —  {state["text"]}' if state.get("text") else ""))
    return 0


def cmd_manifest(args, config) -> int:
    print(capabilities.manifest(refresh=args.refresh))
    if args.refresh:
        print("\n# The desktop right now\n", file=sys.stderr)
    return 0


def cmd_doctor(args, config) -> int:
    print(_bold(f"omadeck {__version__}\n"))

    print(_bold("openai"))
    key = bool(os.environ.get(config.api_key_env))
    print(f"  {_tick(key)} {config.api_key_env}"
          + ("" if key else f"  (put it in {cfg.ENV_FILE})"))
    print(f"  → planner model {config.planner_model} (`omadeck say`)")
    print(f"  → realtime model {config.realtime_model}, voice {config.realtime_voice}")
    if cfg.ENV_FILE.exists():
        mode = cfg.ENV_FILE.stat().st_mode & 0o777
        print(f"  {_tick(mode & 0o077 == 0)} {cfg.ENV_FILE} mode {mode:o}")
    else:
        print(f"  {_tick(False)} {cfg.ENV_FILE} missing")
    if cfg.SAFETY_ID_FILE.exists():
        print(f"  {_tick(True)} per-install safety identifier at {cfg.SAFETY_ID_FILE}")

    print(_bold("\nears"))
    problems = realtime_mod.check_ready(config)
    if problems:
        for problem in problems:
            print(f"  {_tick(False)} {problem}")
    else:
        print(f"  {_tick(True)} websockets, API key, and PipeWire tools all present")
    print(f"  → OpenAI Realtime (speech to speech), "
          f"{config.realtime_turn_detection}, toggle-only")
    print("  ! while listening is on, room audio streams continuously to OpenAI.")
    print("    It starts off, and only SUPER + SHIFT + V turns it on. Toggling")
    print("    off kills the recorder, so nothing is captured while muted.")
    source = config.device or realtime_mod.default_source()
    print(f"  default input: {source or '(none)'}")
    print(f"  output:        {realtime_mod.default_sink() or '(none)'}")
    if config.barge_in:
        risk = realtime_mod.echo_risk(config)
        print(f"  {_tick(not risk)} barge_in is on — you can interrupt her mid-sentence")
        if risk:
            for line in textwrap.wrap(risk, 72):
                print(f"    {line}")
    else:
        print("  → the microphone is held shut while she speaks, so her own voice")
        print("    cannot come back in as yours. Set barge_in = true (headphones,")
        print("    or PipeWire echo-cancel) to interrupt her mid-sentence.")

    print(_bold("\nhands"))
    for tool in ("hyprctl", "omarchy", "wtype", "notify-send", "uwsm-app"):
        print(f"  {_tick(bool(shutil.which(tool)))} {tool}")
    print(f"  shell tool: {'enabled' if config.allow_shell else 'disabled'}"
          f", {len(config.deny_patterns)} deny rules"
          f", {len(config.confirm_patterns)} confirm rules")
    if config.unknown_keys:
        print(f"  {_tick(False)} unknown config keys (ignored): {', '.join(config.unknown_keys)}")
    for key in config.retired_keys:
        # A setting that used to work is a different problem from a typo, and
        # deserves the reason rather than being lumped in with misspellings.
        print(f"  {_tick(False)} `{key}` no longer does anything — {cfg.RETIRED_KEYS[key]}")

    print(_bold("\nmanifest"))
    manifest = capabilities.manifest()
    versions = capabilities.system_versions()
    print(f"  {_tick(True)} {len(manifest)} chars, built from Omarchy {versions['omarchy']}")
    broken = capabilities.verify_essentials()
    if broken:
        print(f"  {_tick(False)} {len(broken)} common action(s) no longer resolve to an omarchy route:")
        for item in broken:
            print(f"      {item}")
    else:
        print(f"  {_tick(True)} all {len(capabilities.ESSENTIALS)} common actions resolve")
    broken_hypr = capabilities.verify_hypr_essentials()
    if broken_hypr:
        print(f"  {_tick(False)} {len(broken_hypr)} dispatcher example(s) no longer exist:")
        for item in broken_hypr:
            print(f"      {item}")
    else:
        print(f"  {_tick(True)} all {len(capabilities.HYPR_ESSENTIALS)} dispatcher examples exist")
    print(f"  cache: {cfg.CACHE_DIR}")

    print(_bold("\ndaemon"))
    running = daemon_running()
    print(f"  {_tick(running)} {'running' if running else 'not running'}"
          f"  ({cfg.SOCKET_PATH})")
    hard = [p for p in problems if "audio input" not in p and "loopback" not in p]
    return 1 if hard else 0


def cmd_log(args, config) -> int:
    if not cfg.LOG_FILE.exists():
        print("no log yet")
        return 0
    if args.follow:
        subprocess.run(["tail", "-f", str(cfg.LOG_FILE)])
    else:
        lines = cfg.LOG_FILE.read_text().splitlines()
        print("\n".join(lines[-args.lines:]))
    return 0


def cmd_mobile(args, config) -> int:
    """Start the LAN HTTPS remote-control bridge (for phone/tablet)."""
    from . import mobile_bridge
    return mobile_bridge.run(config, port=args.port)


def cmd_settings(args, config) -> int:
    """View and configure AI providers via GUI."""
    import webbrowser
    from .local_engine import get_provider_status

    status = get_provider_status(config)
    prov = status["provider"]
    model = status["model"]
    key_set = status["api_key_set"]
    masked = status["api_key_masked"]

    print(_bold("Oma AI Provider & Settings\n"))
    print(f"  Active Provider: {_bold(prov.upper())}")
    print(f"  Active Model:    {model}")
    print(f"  API Key:         {'Configured (' + masked + ')' if key_set else 'Not configured'}")
    print(f"  STT Backend:     {status['stt']}")

    url = "http://127.0.0.1:8765#settings"
    print(f"\nOpening Oma Settings GUI in your browser...")
    try:
        webbrowser.open(url)
        print(f"Opened: {url}")
        print("Tip: You can also tap ⚙️ on Oma Remote from your mobile phone!")
    except Exception as exc:
        print(f"Could not open browser automatically: {exc}")
        print(f"Open {url} in your browser.")
    return 0


# --- parser -----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omadeck",
        description="Drive Omarchy by voice, with OpenAI Realtime as the router.",
    )
    parser.add_argument("--version", action="version", version=f"omadeck {__version__}")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="decide, but narrate actions instead of running them")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--config", type=Path, help="alternate config.toml")
    parser.add_argument("--model", help="planner model for `say` (default: gpt-4.1)")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("say", help="run one command as if it had been spoken")
    p.add_argument("text", nargs="+")
    p.add_argument("--no-confirm", action="store_true",
                   help="never prompt for held actions; just report them")
    p.set_defaults(func=cmd_say)

    p = sub.add_parser("run", help="start the listening daemon")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("listen", help="control a running daemon")
    p.add_argument("action", choices=list(LISTEN_ACTIONS))
    p.add_argument("words", nargs="*",
                   help="text for `listen say`")
    p.set_defaults(func=cmd_listen)

    p = sub.add_parser("restart",
                       help="restart the voice daemon and the phone page, e.g. after an update")
    p.set_defaults(func=cmd_restart)

    p = sub.add_parser("kill-port", help="stop whatever is listening on a TCP port")
    p.add_argument("port", type=int)
    p.set_defaults(func=cmd_kill_port)

    p = sub.add_parser("status", help="what the daemon is doing (for the bar)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("doctor", help="check every moving part")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("manifest", help="print what the model knows about this machine")
    p.add_argument("--refresh", action="store_true")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("log", help="what it heard and did")
    p.add_argument("-n", "--lines", type=int, default=40)
    p.add_argument("-f", "--follow", action="store_true")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("mobile", help="start the LAN remote-control bridge for phone/tablet")
    p.add_argument("--port", type=int, default=8765, help="LAN port (default 8765)")
    p.set_defaults(func=cmd_mobile)

    p = sub.add_parser("settings", help="view and configure AI providers via GUI")
    p.set_defaults(func=cmd_settings)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg.ensure_dirs()
    env_warnings = cfg.load_env_file()
    if args.command == "doctor":
        cfg.warn_env_permissions(env_warnings)
    config = cfg.load(
        args.config,
        dry_run=args.dry_run or None,
        verbose=args.verbose or None,
        planner_model=getattr(args, "model", None),
    )
    return args.func(args, config)


if __name__ == "__main__":
    sys.exit(main())
