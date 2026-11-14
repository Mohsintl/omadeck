"""Understanding an obvious spoken command without a model.

Speech arrives as "Hey Oma, could you turn the volume up to max please." The
fixed actions (volume, keys, workspaces, the desktop's own keybindings) do not
need a model to understand that, and a model asked anyway sometimes guesses
wrong and always takes a second or more. These helpers turn the words into
something the fast path can match: cleaned text, a volume level, and the
Omarchy keybinding whose description the user said.
"""

from __future__ import annotations

import json
import re

# --- cleaning ----------------------------------------------------------------

_UNITS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19,
}
_TENS = {"twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60,
         "seventy": 70, "eighty": 80, "ninety": 90}

_WAKE = re.compile(r"^(?:(?:hey|hi|ok|okay|yo)\s+)?(?:oma|ohma|alma)\b\s*")
_LEAD = re.compile(
    r"^(?:please|kindly|pls|just|now|so|and|"
    r"(?:can|could|would|will) (?:you|u)|"
    r"i (?:want|need|would like|'d like) (?:you )?to|"
    r"go ahead and|let's|lets)\s+")
_TRAIL = re.compile(r"\s+(?:please|for me|now|right now|thanks|thank you)$")
_ARTICLES = re.compile(r"\b(?:the|a|an|my|this|that)\s+")


def _numbers(text: str) -> str:
    """Spoken numbers to digits: "workspace three" -> "workspace 3"."""
    words = text.split()
    out: list[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        if w in ("hundred", "one-hundred") or (
                w in ("a", "one") and i + 1 < len(words) and words[i + 1] == "hundred"):
            if w != "hundred" and w != "one-hundred":
                i += 1
            out.append("100")
        elif w in _TENS:
            value = _TENS[w]
            if i + 1 < len(words) and words[i + 1] in _UNITS and 0 < _UNITS[words[i + 1]] < 10:
                value += _UNITS[words[i + 1]]
                i += 1
            out.append(str(value))
        elif "-" in w and w.split("-", 1)[0] in _TENS and w.split("-", 1)[1] in _UNITS:
            tens, unit = w.split("-", 1)
            out.append(str(_TENS[tens] + _UNITS[unit]))
        elif w in _UNITS:
            out.append(str(_UNITS[w]))
        else:
            out.append(w)
        i += 1
    return " ".join(out)


def clean(text: str) -> str:
    """Lowercase, drop the wake word, politeness and punctuation, digits for numbers."""
    t = text.lower().replace("’", "'")
    t = re.sub(r"\b(?:per ?cent)\b", "%", t)
    t = re.sub(r"[.,!?;:\"]+", " ", t)
    t = " ".join(t.split())
    t = _WAKE.sub("", t)
    for _ in range(3):
        before = t
        t = _LEAD.sub("", t)
        t = _TRAIL.sub("", t)
        if t == before:
            break
    t = _numbers(t)
    return re.sub(r"(\d) %", r"\1%", t)


def drop_articles(text: str) -> str:
    """ "close the window" -> "close window", for a second try at matching."""
    return " ".join(_ARTICLES.sub("", text + " ").split())


# --- volume ------------------------------------------------------------------

_LEVEL_WORDS = {
    "max": 100, "maximum": 100, "full": 100, "highest": 100, "top": 100, "loudest": 100,
    "half": 50, "halfway": 50, "middle": 50,
    "min": 0, "minimum": 0, "lowest": 0, "zero": 0, "nothing": 0,
}
_SOUND = r"(?:the )?(?:volume|sound|audio)(?: level)?"
_LEVEL = r"(?:the )?(max|maximum|full|highest|top|loudest|half|halfway|middle|min|minimum|lowest|zero|nothing|\d{1,3}%?)"


def volume_level(text: str) -> int | None:
    """An absolute volume the user asked for (0-100), or None."""
    t = text
    m = (re.fullmatch(rf"(?:(?:set|turn|put|change|make|bring|crank) )?{_SOUND}"
                      rf"(?: all the way)?(?: up| down)? (?:to |at |on )?{_LEVEL}(?: volume)?", t)
         or re.fullmatch(rf"(?:(?:set|turn|put|change|make|bring|crank) )?(?:it |volume |sound )?"
                         rf"(?:up |down )?to {_LEVEL}(?: volume)?", t)
         or re.fullmatch(r"(max|maximum|full|half|min|minimum) (?:volume|sound)", t))
    if m:
        word = m.group(1).rstrip("%")
        value = _LEVEL_WORDS[word] if word in _LEVEL_WORDS else int(word)
        return max(0, min(100, value))
    if re.fullmatch(rf"(?:turn |crank |pump )?(?:it|{_SOUND}) all the way up", t):
        return 100
    if re.fullmatch(rf"(?:turn )?(?:it|{_SOUND}) all the way down", t):
        return 0
    return None


def volume_step(text: str) -> str | None:
    """A relative change: "+10", "-5", "raise", "lower", or None."""
    t = text
    m = re.fullmatch(rf"(?:turn |put )?(?:it|{_SOUND}) (up|down) (?:by )?(\d{{1,3}})%?", t) or \
        re.fullmatch(rf"(raise|lower|increase|decrease) {_SOUND} (?:by )?(\d{{1,3}})%?", t)
    if m:
        sign = "+" if m.group(1) in ("up", "raise", "increase") else "-"
        return f"{sign}{min(100, int(m.group(2)))}"
    up = (r"(?:(?:turn|crank|pump|bring|put) )?(?:it|" + _SOUND + r") up(?: (?:a bit|a little|some|more))?",
          r"(?:turn|crank|pump) up " + _SOUND,
          r"(?:make it |a bit |a little )?(?:louder|more volume)",
          r"(?:increase|raise) " + _SOUND,
          r"(?:the )?volume (?:higher|louder)")
    down = (r"(?:(?:turn|bring|put) )?(?:it|" + _SOUND + r") down(?: (?:a bit|a little|some|more))?",
            r"(?:turn|bring) down " + _SOUND,
            r"(?:make it |a bit |a little )?(?:quieter|softer|less volume)",
            r"(?:decrease|lower|reduce) " + _SOUND,
            r"(?:the )?volume (?:lower|quieter)")
    if any(re.fullmatch(p, t) for p in up):
        return "raise"
    if any(re.fullmatch(p, t) for p in down):
        return "lower"
    return None


ADDRESS_BAR = re.compile(
    r"(?:(?:focus|select|click|go to|jump to|open|move to|put (?:the )?cursor)"
    r"(?: on| in| into| to)? )?(?:the )?(?:browser(?:'s)? )?"
    r"(?:address|url|location|omni|search) ?(?:bar|box|field)")


def is_address_bar(text: str) -> bool:
    return bool(ADDRESS_BAR.fullmatch(text))


# --- Omarchy keybindings -----------------------------------------------------
#
# The Super+K menu lists every binding with what it runs. Saying a row's
# description ("toggle nightlight", "color picker", "focus on left window")
# runs that row, the way picking it in the menu does.

# Spoken and written forms that mean the same thing, applied to both sides.
_SAME = [
    (r"\bnight light\b", "nightlight"),
    (r"\bscreen ?record(?:ing|er)?\b|\brecord (?:the )?screen\b", "screenrecording"),
    (r"\bkey ?bindings?\b|\bkeyboard shortcuts\b|\bshortcuts\b", "keybindings"),
    (r"\bwi-?fi\b|\bwi fi\b", "wifi"),
    (r"\bfull ?screen\b", "fullscreen"),
    (r"\bcolour\b", "color"),
    (r"\block (?:the )?(?:screen|computer|pc|laptop|desktop)\b", "lock system"),
    (r"\bblue ?tooth\b", "bluetooth"),
    (r"\bsingle-window\b", "single window"),
    (r"&", " and "),
]

# Words that carry no meaning for matching: "open the terminal" is "Terminal",
# "turn on the nightlight" is "Toggle nightlight".
_FILLER = {"the", "a", "an", "my", "me", "this", "please", "on", "off", "to",
           "open", "launch", "start", "show", "run", "toggle", "turn", "use",
           "do", "bring", "pull", "switch"}

# Rows a voice slip must not run in one step: the planner holds these for a yes.
_RISKY = re.compile(r"close all|shut ?down|power ?off|reboot|restart|log ?out|"
                    r"suspend|hibernate|clear reminders|dismiss all")


def _key(text: str) -> tuple[str, ...]:
    t = text.lower()
    for pattern, same in _SAME:
        t = re.sub(pattern, same, t)
    t = re.sub(r"[^\w\s]", " ", t)
    return tuple(sorted(w for w in t.split() if w not in _FILLER))


def _variants(description: str) -> list[str]:
    """ "Toggle window floating/tiling" also answers to "toggle window floating"."""
    full = description.replace("(", " ").replace(")", " ")
    forms = [full]
    plain = re.sub(r"\([^)]*\)", " ", description)
    if plain != description:
        forms.append(plain)
    for form in list(forms):
        for word in re.findall(r"\S+/\S+", form):
            for part in word.split("/"):
                forms.append(form.replace(word, part))
            forms.append(form.replace(word, word.replace("/", " ")))
    return forms


def parse_binding_records(output: str) -> list[dict]:
    """Rows from `output_binding_records`: "<chords> → <action>\\t<dispatcher>\\t<arg>"."""
    rows = []
    for line in output.splitlines():
        display, _, rest = line.partition("\t")
        dispatcher, _, arg = rest.partition("\t")
        chords, arrow, action = display.partition("→")
        if not arrow:
            continue
        action = action.strip()
        if action and dispatcher.strip():
            rows.append({"chords": " ".join(chords.split()), "action": action,
                         "dispatcher": dispatcher.strip(), "arg": arg.strip()})
    return rows


def match_binding(text: str, rows: list[dict]) -> dict | None:
    """The row whose description the words say, or None.

    A full description wins over the same words with its bracket left out, so
    "browser" is Browser and "private browser" is Browser (private).
    """
    want = _key(text)
    if not want:
        return None
    exact: dict[tuple, dict] = {}
    loose: dict[tuple, dict] = {}
    for row in rows:
        if _RISKY.search(row["action"].lower()):
            continue
        forms = _variants(row["action"])
        exact.setdefault(_key(forms[0]), row)
        for form in forms[1:]:
            loose.setdefault(_key(form), row)
    return exact.get(want) or loose.get(want)


def binding_commands(row: dict) -> list[list[str]]:
    """How `omarchy-menu-keybindings` runs a row, as hyprctl calls to try in order."""
    dispatcher, arg = row["dispatcher"], row["arg"]
    if dispatcher == "exec":
        return [["hyprctl", "dispatch", f"hl.dsp.exec_cmd({json.dumps(arg, ensure_ascii=False)})"],
                ["hyprctl", "dispatch", "exec", arg]] if arg else []
    if dispatcher == "lua":
        return [["hyprctl", "dispatch", arg]] if arg else []
    if dispatcher == "sendshortcut":
        return [["hyprctl", "dispatch", "sendshortcut", arg]] if arg else []
    return [["hyprctl", "dispatch", dispatcher] + ([arg] if arg else [])]
