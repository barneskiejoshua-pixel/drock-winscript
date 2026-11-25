"""WinScript inside DRock: its Windows tweak catalogue behind /winscript, applied through DRock's own executor and
checked afterwards. Standard library only. research/winscript-audit/AUDIT.md has the why of every decision.

WinScript (github.com/flick9000/winscript, GPL-3.0) is a Tauri app whose value is a curated catalogue: ~150
tweaks (debloat, privacy, telemetry, performance), each a list of PowerShell lines, plus presets, groups,
mutually exclusive options, Store-app removal lists and an app list for winget/Chocolatey. Its Run button writes
the lines to a temp .ps1 and starts it elevated with every error silenced; nothing is read back and nothing can be
undone except through a restore point.

Here:
  import    the catalogue is parsed from the user's own WinScript checkout into DRock's data folder
            (data/winscript/catalog.json). No WinScript text lives in DRock's source.
  select    ids, group-<id>, debloat-<id>, preset names, or a WinScript config file ({"id": true, ...}, the
            format of WinScript's export and its -i flag). Two options of one radio group are refused. Tweaks
            that fetch from the internet and the activation script (MAS) are refused.
  apply     the selection becomes one script, run as ONE ADMIN_COMMAND through the session's executor: DRock's
            approval (HIGH risk, always asked) and Windows' UAC prompt. A restore point comes first and the run
            stops if none exists from the last 24 hours (--no-restore skips it). Each tweak runs in its own
            block and writes what happened to results.jsonl.
  verify    every `reg add` / `reg delete` is read back afterwards (winreg, not elevated) and every removed Store
            app looked up again. A tweak is reported verified, failed, ran-with-errors, ran (nothing to check), or
            not run, never "done" on the script's say-so.
  undo      the prior state of every registry value a tweak touches is saved before the run; /winscript undo
            puts those back (one more ADMIN_COMMAND). Removed apps, services and tasks are restore-point only,
            and the report says which tweaks those are.
  apps      WinScript's app list, installed one by one through DRock's INSTALL_PACKAGE (its own source order,
            checks and approvals), never through a downloaded installer piped to iex.
  unattend  an autounattend.xml that runs the selection at first logon, written here (the concept is WinScript's).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shlex
from pathlib import Path

DEFAULT_SOURCE = Path.home() / "Desktop" / "opensource" / "winscript-main"
REJECT = {"installmas": "the Microsoft Activation Scripts activate Windows and Office without a license"}
FETCH = re.compile(r"\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadString|DownloadFile|Start-BitsTransfer|"
                   r"curl(\.exe)?|wget(\.exe)?)\b|https?://", re.I)
RADIO_NONE = "none"   # WinScript's "no change" option in a radio group: selects nothing


# ------------------------------------------------------------------ reading WinScript's TypeScript and Astro

class SourceError(ValueError):
    pass


def _skip(src: str, i: int) -> int:
    """Past whitespace and // or /* */ comments."""
    while i < len(src):
        if src[i].isspace():
            i += 1
        elif src.startswith("//", i):
            i = src.find("\n", i)
            i = len(src) if i < 0 else i
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = len(src) if j < 0 else j + 2
        else:
            break
    return i


_ESC = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "b": "\b", "f": "\f", "v": "\v"}


def _string(src: str, i: int) -> tuple[str, int]:
    """One JavaScript string literal ('...', "..." or `...` without ${}) starting at src[i]."""
    q = src[i]
    if q not in "'\"`":
        raise SourceError(f"expected a string at offset {i}: {src[i:i + 30]!r}")
    out, i = [], i + 1
    while i < len(src):
        c = src[i]
        if c == "\\":
            n = src[i + 1]
            out.append(_ESC.get(n, n))
            i += 2
            continue
        if c == q:
            return "".join(out), i + 1
        if q == "`" and src.startswith("${", i):
            raise SourceError(f"template interpolation at offset {i}: the value is computed, not data")
        out.append(c)
        i += 1
    raise SourceError("unterminated string")


def _key(src: str, i: int) -> tuple[str, int]:
    if src[i] in "'\"`":
        return _string(src, i)
    m = re.compile(r"[A-Za-z_$][\w$-]*").match(src, i)
    if not m:
        raise SourceError(f"expected a key at offset {i}: {src[i:i + 30]!r}")
    return m.group(0), m.end()


def _string_list(src: str, i: int) -> tuple[list[str], int]:
    i = _skip(src, i)
    if src[i] != "[":
        raise SourceError(f"expected [ at offset {i}")
    out, i = [], _skip(src, i + 1)
    while src[i] != "]":
        s, i = _string(src, i)
        out.append(s)
        i = _skip(src, i)
        if src[i] == ",":
            i = _skip(src, i + 1)
    return out, i + 1


def _object_of_lists(src: str, i: int) -> tuple[dict[str, list[str]], int]:
    i = _skip(src, i)
    if src[i] != "{":
        raise SourceError(f"expected {{ at offset {i}")
    out, i = {}, _skip(src, i + 1)
    while src[i] != "}":
        k, i = _key(src, i)
        i = _skip(src, i)
        if src[i] != ":":
            raise SourceError(f"expected : after {k!r}")
        out[k], i = _string_list(src, i + 1)
        i = _skip(src, i)
        if src[i] == ",":
            i = _skip(src, i + 1)
    return out, i + 1


def _after(src: str, pattern: str) -> int:
    m = re.search(pattern, src)
    if not m:
        raise SourceError(f"{pattern!r} not found")
    return m.end()


def _objects(text: str) -> list[dict[str, str]]:
    """The flat `{ key: value, ... }` entries of an Astro props array: values that are strings, t["key"] lookups
    (kept as "t:key") or true/false."""
    out = []
    for body in re.findall(r"\{([^{}]*)\}", text):
        entry, i = {}, 0
        for m in re.finditer(r"(\w+)\s*:\s*(t\[\s*(\"[^\"]*\"|'[^']*')\s*\]|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|true|false)", body):
            k, v = m.group(1), m.group(2)
            if v.startswith("t["):
                entry[k] = "t:" + _string(m.group(3), 0)[0]
            elif v in ("true", "false"):
                entry[k] = v
            else:
                entry[k] = _string(v, 0)[0]
        if entry:
            out.append(entry)
    return out


def _components(astro: str, name: str):
    """(offset, props text) of every <name ... /> in the page, braces and quotes respected."""
    for m in re.finditer(rf"<{name}\b", astro):
        i, depth, q = m.end(), 0, None
        while i < len(astro):
            c = astro[i]
            if q:
                if c == "\\":
                    i += 1
                elif c == q:
                    q = None
            elif c in "\"'`":
                q = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            elif depth == 0 and astro.startswith("/>", i):
                yield m.start(), astro[m.end():i]
                break
            i += 1


def _prop(props: str, name: str) -> str | None:
    """A string prop (name="x") or a t["key"] prop (name={t["key"]}) as "t:key"."""
    m = re.search(rf"\b{name}\s*=\s*(\"[^\"]*\"|\{{\s*t\[\s*(\"[^\"]*\"|'[^']*')\s*\]\s*\}})", props)
    if not m:
        return None
    return "t:" + _string(m.group(2), 0)[0] if m.group(2) else _string(m.group(1), 0)[0]


def _array_prop(props: str, name: str) -> str:
    i = props.find(f"{name}={{[")
    if i < 0:
        return ""
    depth, j = 0, props.index("[", i)
    for k in range(j, len(props)):
        depth += props[k] == "["
        depth -= props[k] == "]"
        if depth == 0:
            return props[j:k + 1]
    return props[j:]


# ------------------------------------------------------------------ registry lines

def _split(cmd: str) -> list[str]:
    """Split a reg.exe line the way cmd does: whitespace outside double quotes, quotes removed."""
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def reg_ops(lines: list[str]) -> list[dict]:
    """Every `reg add` / `reg delete` in a tweak, as data: key, value name ("" = the default value), type, data.
    `checkable` is False when PowerShell would expand something in it ($...), so the read-back cannot know the
    value the line wrote."""
    out = []
    for line in lines:
        m = re.match(r"\s*(?:&\s*)?reg(?:\.exe)?\s+(add|delete)\s+(.*?);?\s*$", line, re.I)
        if not m:
            continue
        toks = _split(m.group(2))
        if not toks:
            continue
        op = {"op": m.group(1).lower(), "key": toks[0], "name": None, "type": "REG_SZ", "data": "",
              "checkable": "$" not in m.group(2), "line": line.strip()}
        i = 1
        while i < len(toks):
            t = toks[i].lower()
            if t == "/v" and i + 1 < len(toks):
                op["name"], i = toks[i + 1], i + 2
            elif t == "/ve":
                op["name"], i = "", i + 1
            elif t == "/t" and i + 1 < len(toks):
                op["type"], i = toks[i + 1].upper(), i + 2
            elif t == "/d" and i + 1 < len(toks):
                op["data"], i = toks[i + 1], i + 2
            else:
                i += 1
        if op["op"] == "delete" and op["name"] is None:
            op["op"] = "delete_key"
        out.append(op)
    return out


# ------------------------------------------------------------------ import

def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _body_sha(cat: dict) -> str:
    body = {k: v for k, v in cat.items() if k != "body_sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def import_catalog(src: Path) -> dict:
    """The catalogue, read from a WinScript checkout (the repository root or its app/ folder)."""
    src = Path(src)
    app = src / "app" if (src / "app" / "src").is_dir() else src
    files = {"scripts": app / "src/assets/js/scripts.ts", "page": app / "src/components/MainPage.astro",
             "en": app / "src/i18n/locales/en.json", "apps": app / "src/assets/js/appinstall.ts",
             "tauri": app / "src-tauri/tauri.conf.json"}
    missing = [str(p) for p in files.values() if not p.is_file()]
    if missing:
        raise SourceError(f"not a WinScript checkout ({src}): missing {', '.join(missing)}")
    ts = files["scripts"].read_text(encoding="utf-8")
    page = files["page"].read_text(encoding="utf-8")
    en = json.loads(files["en"].read_text(encoding="utf-8-sig"))
    scripts, _ = _object_of_lists(ts, _after(ts, r"const\s+scripts\s*:\s*Record<string,\s*string\[\]>\s*=\s*"))
    presets, _ = _object_of_lists(ts, _after(ts, r"const\s+presets\s*:\s*Record<string,\s*string\[\]>\s*=\s*"))

    def text(v):
        return en.get(v[2:], v[2:]) if isinstance(v, str) and v.startswith("t:") else v

    tabs = [(m.start(), m.group(1)) for m in re.finditer(r'<Tab\s+tab="([^"]+)"', page)]

    def tab_at(off):
        return next((name for start, name in reversed(tabs) if start <= off), "")

    meta: dict[str, dict] = {}
    groups: dict[str, dict] = {}
    debloat: dict[str, dict] = {}
    for off, props in _components(page, "ScriptToggle"):
        iid = _prop(props, "inputId")
        if iid:
            meta[iid] = {"title": text(_prop(props, "title")), "desc": text(_prop(props, "description")), "tab": tab_at(off)}
    for off, props in _components(page, "ScriptGroup"):
        section = text(_prop(props, "title"))
        for e in _objects(_array_prop(props, "tools")):
            if "inputId" in e:
                meta[e["inputId"]] = {"title": text(e.get("title")), "desc": text(e.get("description")), "tab": tab_at(off),
                                      "section": section, "radio": e.get("group") if e.get("radio") == "true" else None}
    for off, props in _components(page, "GroupToggle"):
        gid = "group-" + (_prop(props, "id") or "")
        members = []
        for e in _objects(_array_prop(props, "scripts")):
            if "inputId" in e:
                members.append(e["inputId"])
                meta[e["inputId"]] = {"title": text(e.get("title")), "desc": text(e.get("description")), "tab": tab_at(off),
                                      "section": text(_prop(props, "title")), "group": gid}
        groups[gid] = {"title": text(_prop(props, "title")), "desc": text(_prop(props, "description")), "members": members}
    for off, props in _components(page, "DebloatGroup"):
        did = "debloat-" + (_prop(props, "id") or "")
        debloat[did] = {"title": text(_prop(props, "title")), "desc": text(_prop(props, "desc")),
                        "apps": [{"title": text(e.get("title")), "appx": e["appId"]}
                                 for e in _objects(_array_prop(props, "apps")) if "appId" in e]}

    tweaks, rejected = {}, dict(REJECT)
    for iid, lines in scripts.items():
        info = meta.get(iid, {})
        fetch = next((l.strip() for l in lines if FETCH.search(l)), None)
        if fetch:
            rejected[iid] = f"needs the internet ({fetch[:120]}); DRock runs offline"
        tweaks[iid] = {"title": info.get("title") or iid, "desc": info.get("desc") or "", "tab": info.get("tab", ""),
                       "section": info.get("section"), "group": info.get("group"), "radio": info.get("radio"),
                       "lines": lines, "registry": reg_ops(lines)}
    radios = {}
    for iid, info in meta.items():
        if info.get("radio"):
            radios.setdefault(info["radio"], []).append(iid)
    apps_ts = files["apps"].read_text(encoding="utf-8")
    apps: dict[str, dict] = {}
    for which, var in (("winget", "appListWinget"), ("choco", "appListChocolatey")):
        i = _after(apps_ts, rf"const\s+{var}\s*=\s*")
        j = apps_ts.index("];", i)
        for e in _objects(apps_ts[i:j + 1]):
            if e.get("id"):
                apps.setdefault(e["id"], {})[which] = e.get("url") or None
    version = json.loads(files["tauri"].read_text(encoding="utf-8-sig")).get("version")
    cat = {"v": 1, "source": str(src), "winscript_version": version,
           "imported": datetime.datetime.now().isoformat(timespec="seconds"),
           "files": {k: _sha(p) for k, p in files.items()},
           "tweaks": tweaks, "groups": groups, "debloat": debloat, "presets": presets, "radios": radios,
           "apps": apps, "rejected": rejected,
           # the ids of the page's inputs (what WinScript's getElementById and its config export see)
           "ui_ids": sorted(set(re.findall(r'\binputId\s*[=:]\s*"([^"]+)"', page)) | set(groups) | set(debloat)
                            | {a["appx"] for d in debloat.values() for a in d["apps"]})}
    cat["body_sha256"] = _body_sha(cat)
    return cat


def _data_root() -> Path:
    """DRock's data folder inside DRock; on its own, $WINSCRIPT_DATA or ~/.drock-winscript."""
    try:
        from . import paths
        return paths.data() / "winscript"
    except ImportError:
        return Path(os.environ.get("WINSCRIPT_DATA") or Path.home() / ".drock-winscript")


def catalog_path() -> Path:
    return _data_root() / "catalog.json"


def save_catalog(cat: dict, path: Path | None = None) -> Path:
    p = Path(path or catalog_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cat, indent=1, ensure_ascii=False), encoding="utf-8")
    return p


def load_catalog(path: Path | None = None) -> dict:
    p = Path(path or catalog_path())
    if not p.is_file():
        raise SourceError("no WinScript catalogue yet: /winscript import [path to the winscript checkout]")
    cat = json.loads(p.read_text(encoding="utf-8"))
    if cat.get("body_sha256") != _body_sha(cat):
        raise SourceError(f"{p} changed after it was imported (sha256 mismatch); /winscript import it again")
    return cat


# ------------------------------------------------------------------ selection

class Selection:
    def __init__(self):
        self.tweaks: list[str] = []
        self.appx: list[dict] = []
        self.problems: list[str] = []   # stop the command
        self.notes: list[str] = []      # said, and the rest goes ahead

    def add_tweak(self, cat: dict, iid: str, via: str = "") -> None:
        """`via` set (a preset or group asked for it, not the user by name): a refused or missing id is a note,
        as WinScript itself skips ids its page does not have; typed by name, it stops the command."""
        if iid in cat["rejected"]:
            (self.notes if via else self.problems).append(f"{iid}: refused{f' (from {via})' if via else ''}, {cat['rejected'][iid]}")
        elif iid not in cat["tweaks"]:
            if iid == RADIO_NONE or any(iid in m for m in cat["radios"].values()):
                return   # a radio option with no script of its own ("none"): selects nothing
            if via:
                self.notes.append(f"{via}: {iid} selects nothing (WinScript has no switch with that id either)")
            else:
                self.problems.append(f"{iid}: no such tweak")
        elif iid not in self.tweaks:
            self.tweaks.append(iid)


def select(cat: dict, words: list[str]) -> Selection:
    """Ids, group-<id>, debloat-<id>, a single Store app (appx:<package pattern>), or a preset name."""
    sel = Selection()
    for w in words:
        if w in cat["presets"]:
            for iid in cat["presets"][w]:
                _one(cat, sel, iid, via=f"preset {w}")   # WinScript's applyPreset skips ids its page lacks
        else:
            _one(cat, sel, w)
    for group, members in cat["radios"].items():
        chosen = [m for m in members if m in sel.tweaks]
        if len(chosen) > 1:
            sel.problems.append(f"{' and '.join(chosen)} are options of one choice ({group}): pick one")
    return sel


def _one(cat: dict, sel: Selection, w: str, via: str = "") -> None:
    if w in cat["groups"]:
        for iid in cat["groups"][w]["members"]:
            sel.add_tweak(cat, iid, via=via or w)
    elif w in cat["debloat"]:
        for a in cat["debloat"][w]["apps"]:
            if a not in sel.appx:
                sel.appx.append(a)
    elif w.startswith("appx:"):
        pkg = w[5:]
        known = next((a for d in cat["debloat"].values() for a in d["apps"] if a["appx"] == pkg), None)
        if known is None:
            sel.problems.append(f"{w}: not in WinScript's app removal lists")
        elif known not in sel.appx:
            sel.appx.append(known)
    else:
        sel.add_tweak(cat, w, via=via)


def from_config(cat: dict, config: dict) -> Selection:
    """A WinScript config ({"elementId": true|false}) as a selection. Unknown ids and non-booleans are problems."""
    sel = Selection()
    if not isinstance(config, dict):
        sel.problems.append("a WinScript config is a JSON object of id: true|false")
        return sel
    appx_by_id = {a["appx"]: a for d in cat["debloat"].values() for a in d["apps"]}
    # switches of WinScript's page that are not tweaks (group switches mirror their members, app ids belong to
    # /winscript apps, the restore point is DRock's own default): a config names them all, they select nothing here
    known_ui = set(cat.get("ui_ids") or ()) | set(cat["groups"]) | set(cat["debloat"]) | set(cat["apps"]) \
        | {m for ms in cat["radios"].values() for m in ms}
    for k, v in config.items():
        if not isinstance(v, bool):
            sel.problems.append(f"{k}: {v!r} is not true or false")
        elif not v:
            continue
        elif k in appx_by_id:
            if appx_by_id[k] not in sel.appx:
                sel.appx.append(appx_by_id[k])
        elif k in cat["tweaks"] or k in cat["rejected"]:
            sel.add_tweak(cat, k)
        elif k not in known_ui:
            sel.problems.append(f"{k}: no such tweak")
    chosen_groups = [(g, [m for m in ms if m in sel.tweaks]) for g, ms in cat["radios"].items()]
    for g, chosen in chosen_groups:
        if len(chosen) > 1:
            sel.problems.append(f"{' and '.join(chosen)} are options of one choice ({g}): pick one")
    return sel


def to_config(cat: dict, sel: Selection) -> dict:
    """The selection in WinScript's own export format, every toggle named, so its -i flag loads it."""
    out = {iid: iid in sel.tweaks for iid in cat["tweaks"]}
    picked = {a["appx"] for a in sel.appx}
    for d in cat["debloat"].values():
        for a in d["apps"]:
            out[a["appx"]] = a["appx"] in picked
    return out


# ------------------------------------------------------------------ the script

def _psq(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def build_script(cat: dict, sel: Selection, run_dir: Path, restore: bool = True, stamp: str = "") -> str:
    """One PowerShell script for the selection. Each tweak runs in its own block; what happened is appended to
    results.jsonl in run_dir. Errors are recorded, not silenced (WinScript sets SilentlyContinue)."""
    results, log = run_dir / "results.jsonl", run_dir / "output.log"
    out = [f"# DRock /winscript run {stamp}: {len(sel.tweaks)} tweak(s), {len(sel.appx)} Store app(s)",
           f"# from WinScript {cat.get('winscript_version')} (catalogue {cat['body_sha256'][:12]}), {cat.get('source')}",
           "$ErrorActionPreference = 'Continue'",
           "$ProgressPreference = 'SilentlyContinue'",
           f"$DrockResults = {_psq(str(results))}",
           f"$DrockLog = {_psq(str(log))}",
           "function Invoke-DrockTweak([string]$Id, [scriptblock]$Body) {",
           "    $before = $Error.Count; $global:LASTEXITCODE = 0; $thrown = $null",
           "    try { & $Body *>&1 | Out-File -LiteralPath $DrockLog -Append -Encoding utf8 } catch { $thrown = \"$_\" }",
           "    $new = $Error.Count - $before",
           "    $errs = @(if ($new -gt 0) { $Error[0..($new - 1)] | ForEach-Object { \"$_\" } })",
           "    $row = [ordered]@{ id = $Id; exit = $LASTEXITCODE; thrown = $thrown; errors = $errs }",
           "    ($row | ConvertTo-Json -Compress -Depth 3) | Add-Content -LiteralPath $DrockResults -Encoding utf8",
           "}",
           ""]
    if restore:
        out += ["Invoke-DrockTweak '_restore_point' {",
                f"    Enable-ComputerRestore -Drive \"$env:SystemDrive\\\"",
                f"    Checkpoint-Computer -Description {_psq('DRock winscript ' + stamp)} -RestorePointType 'MODIFY_SETTINGS'",
                "}",
                "$rp = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1",
                "$rpAt = if ($rp) { [Management.ManagementDateTimeConverter]::ToDateTime($rp.CreationTime) } else { $null }",
                "$fresh = $rpAt -and ((Get-Date) - $rpAt).TotalHours -lt 24",
                "$row = [ordered]@{ id = '_restore_check'; found = [bool]$fresh; newest = \"$rpAt\"; description = \"$($rp.Description)\" }",
                "($row | ConvertTo-Json -Compress) | Add-Content -LiteralPath $DrockResults -Encoding utf8",
                "if (-not $fresh) { exit 3 }   # no restore point from the last 24 hours: nothing below runs",
                ""]
    for iid in sel.tweaks:
        out.append(f"Invoke-DrockTweak {_psq(iid)} {{")
        out += ["    " + l for l in cat["tweaks"][iid]["lines"]]
        out += ["}", ""]
    for a in sel.appx:
        out += [f"Invoke-DrockTweak {_psq('appx:' + a['appx'])} {{",
                f"    Get-AppxPackage {_psq(a['appx'])} | Remove-AppxPackage", "}", ""]
    out.append("exit 0")
    return "\r\n".join(out) + "\r\n"


# ------------------------------------------------------------------ the registry, read without elevation

_ROOTS = {"HKLM": "HKEY_LOCAL_MACHINE", "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER",
          "HKEY_CURRENT_USER": "HKEY_CURRENT_USER", "HKU": "HKEY_USERS", "HKEY_USERS": "HKEY_USERS",
          "HKCR": "HKEY_CLASSES_ROOT", "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT", "HKCC": "HKEY_CURRENT_CONFIG",
          "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG"}


def read_value(key: str, name: str):
    """(present, type name, value) of one registry value, 64-bit view; (None, None, error) when unreadable."""
    import winreg
    root, _, sub = key.replace("/", "\\").partition("\\")
    hive = getattr(winreg, _ROOTS.get(root.upper(), ""), None)
    if hive is None:
        return None, None, f"unknown hive {root}"
    types = {getattr(winreg, n): n for n in ("REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_MULTI_SZ",
                                             "REG_BINARY", "REG_NONE")}
    try:
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            value, t = winreg.QueryValueEx(k, name)
            return True, types.get(t, str(t)), value
    except FileNotFoundError:
        return False, None, None
    except OSError as e:
        return None, None, f"{type(e).__name__}: {e}"


def expected(op: dict):
    """What a reg add wrote, as winreg returns it."""
    t, d = op["type"], op["data"]
    if t in ("REG_DWORD", "REG_QWORD"):
        try:
            return int(d, 16) if d.lower().startswith("0x") else int(d)
        except ValueError:
            return d
    if t == "REG_MULTI_SZ":
        return [s for s in d.split("\\0") if s]
    if t == "REG_BINARY":
        try:
            return bytes.fromhex(d)
        except ValueError:
            return d
    return d


def check_op(op: dict) -> tuple[str, str]:
    """('verified'|'failed'|'unchecked', why) for one registry line, after the run."""
    if not op["checkable"]:
        return "unchecked", "PowerShell expands part of it"
    if op["op"] == "delete_key":
        import winreg
        root, _, sub = op["key"].replace("/", "\\").partition("\\")
        try:
            winreg.OpenKey(getattr(winreg, _ROOTS[root.upper()]), sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY).Close()
            return "failed", f"key {op['key']} still exists"
        except FileNotFoundError:
            return "verified", "key absent"
        except (OSError, KeyError) as e:
            return "unchecked", str(e)
    present, t, value = read_value(op["key"], op["name"] or "")
    if present is None:
        return "unchecked", str(value)
    if op["op"] == "delete":
        return ("verified", "value absent") if not present else ("failed", f"still {value!r}")
    want = expected(op)
    if not present:
        return "failed", f"{op['key']}\\{op['name'] or '(default)'} is absent, expected {want!r}"
    return ("verified", f"{value!r}") if value == want else ("failed", f"is {value!r}, expected {want!r}")


def snapshot(cat: dict, sel: Selection) -> list[dict]:
    """The prior state of every registry value the selection writes or deletes, for undo."""
    seen, out = set(), []
    for iid in sel.tweaks:
        for op in cat["tweaks"][iid]["registry"]:
            if op["op"] == "delete_key" or not op["checkable"]:
                continue
            k = (op["key"].lower(), (op["name"] or "").lower())
            if k in seen:
                continue
            seen.add(k)
            present, t, value = read_value(op["key"], op["name"] or "")
            out.append({"key": op["key"], "name": op["name"] or "", "present": present, "type": t,
                        "value": value.hex() if isinstance(value, bytes) else value, "binary": isinstance(value, bytes),
                        "tweak": iid})
    return out


def undo_lines(before: list[dict]) -> tuple[list[str], list[dict]]:
    """reg.exe lines that put the saved values back, and the entries that cannot be (unreadable before)."""
    lines, skipped = [], []
    for b in before:
        v = f'/v "{b["name"]}"' if b["name"] else "/ve"
        if b["present"] is None:
            skipped.append(b)
        elif not b["present"]:
            lines.append(f'reg delete "{b["key"]}" {v} /f')
        else:
            val = b["value"]
            if b["type"] == "REG_MULTI_SZ":
                val = "\\0".join(val)
            lines.append(f'reg add "{b["key"]}" {v} /t {b["type"]} /d "{val}" /f')
    return lines, skipped


# ------------------------------------------------------------------ results

def read_results(run_dir: Path) -> dict[str, dict]:
    out = {}
    p = run_dir / "results.jsonl"
    if p.is_file():
        for line in p.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            try:
                row = json.loads(line.lstrip("\ufeff"))
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("id"):
                out[row["id"]] = row
    return out


def appx_present(patterns: list[str]) -> dict[str, bool | None]:
    """Whether each Store package pattern still matches an installed package for this user."""
    if not patterns:
        return {}
    import subprocess
    script = "; ".join(f"[bool](Get-AppxPackage {_psq(p)})" for p in patterns)
    try:
        p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=120)
        rc, out = p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        rc, out = 1, ""
    vals = [l.strip() for l in (out or "").splitlines() if l.strip() in ("True", "False")]
    if rc != 0 or len(vals) != len(patterns):
        return {p: None for p in patterns}
    return {p: v == "True" for p, v in zip(patterns, vals)}


def undo_covers(tweak: dict) -> bool:
    """Whether /winscript undo can put everything this tweak changes back: only registry values it can read."""
    return all(o["op"] != "delete_key" and o["checkable"] for o in tweak["registry"]) \
        and not any(_changes_outside_registry(l) for l in tweak["lines"])


def verdicts(cat: dict, sel: Selection, results: dict[str, dict], appx_after: dict) -> list[dict]:
    """One row per tweak and Store app: verified, failed, ran-with-errors, ran, not run."""
    rows = []
    for iid in sel.tweaks:
        r = results.get(iid)
        ops = cat["tweaks"][iid]["registry"]
        undoable = undo_covers(cat["tweaks"][iid])
        if r is None:
            rows.append({"id": iid, "status": "not run", "why": "the script stopped before it", "undoable": undoable})
            continue
        checks = [(o, *check_op(o)) for o in ops]
        failed = [(o, why) for o, s, why in checks if s == "failed"]
        verified = sum(1 for _, s, _ in checks if s == "verified")
        errs = r.get("errors") or []
        errs = [errs] if isinstance(errs, str) else errs   # PowerShell 5.1 writes a one-item array as its item
        if r.get("thrown"):
            status, why = "failed", str(r["thrown"])[:200]
        elif failed:
            status, why = "failed", "; ".join(f"{o['line'][:80]}: {w}" for o, w in failed[:3])
        elif errs:
            status, why = "ran with errors", f"{len(errs)} error(s), first: {str(errs[0])[:180]}"
        elif verified:
            status, why = "verified", f"{verified} registry value(s) read back"
        else:
            status, why = "ran", "nothing in it can be read back"
        rows.append({"id": iid, "status": status, "why": why, "checked": verified, "undoable": undoable})
    for a in sel.appx:
        r = results.get("appx:" + a["appx"])
        still = appx_after.get(a["appx"])
        if r is None:
            rows.append({"id": "appx:" + a["appx"], "status": "not run", "why": "the script stopped before it", "undoable": False})
        elif still is None:
            rows.append({"id": "appx:" + a["appx"], "status": "ran", "why": "could not look the package up", "undoable": False})
        else:
            rows.append({"id": "appx:" + a["appx"], "status": "failed" if still else "verified",
                         "why": "still installed" if still else "no longer installed", "undoable": False})
    return rows


def _changes_outside_registry(line: str) -> bool:
    """A line that does something other than print, structure a block, or write a registry value with reg.exe."""
    l = line.strip()
    if not l or l.startswith("#") or re.match(r"(Write-Host|Write-Output)\b", l, re.I):
        return False
    if re.fullmatch(r"\}?\s*(try|catch|finally|else)?\s*\{?|\}", l, re.I):
        return False
    return not re.match(r"(&\s*)?reg(\.exe)?\s+(add|delete)\b", l, re.I)


# ------------------------------------------------------------------ unattend

def unattend_xml(script: str, bypass: bool = True) -> str:
    """autounattend.xml: Windows' documented LabConfig checks skipped (bypass), the network-required OOBE step
    off (BypassNRO), the online-account screens hidden, and `script` written to C:\\Windows\\Setup\\Scripts and run
    at first logon. The file is extracted from the answer file itself in the specialize pass."""
    from xml.sax.saxutils import escape
    labs = ["BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck", "BypassCPUCheck", "BypassStorageCheck"] if bypass else []
    pe = "".join(
        f'\n\t\t\t\t<RunSynchronousCommand wcm:action="add"><Order>{n}</Order><Path>reg.exe add "HKLM\\SYSTEM\\Setup\\LabConfig" '
        f'/v {v} /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>' for n, v in enumerate(labs, 1))
    comp = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
    extract = ("powershell.exe -NoProfile -Command \"$x = [xml](Get-Content -Raw 'C:\\Windows\\Panther\\unattend.xml'); "
               "foreach ($f in $x.unattend.Extensions.File) { $p = $f.path; New-Item -ItemType Directory -Force (Split-Path $p) | Out-Null; "
               "[IO.File]::WriteAllText($p, $f.InnerText.Trim(), [Text.UTF8Encoding]::new($true)) }\"")
    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
	<!-- Written by DRock /winscript from a WinScript selection -->
	<settings pass="windowsPE">
		<component name="Microsoft-Windows-Setup" {comp}>
			<UserData><ProductKey><Key>00000-00000-00000-00000-00000</Key><WillShowUI>Always</WillShowUI></ProductKey><AcceptEula>true</AcceptEula></UserData>
			<RunSynchronous>{pe}
			</RunSynchronous>
		</component>
	</settings>
	<settings pass="specialize">
		<component name="Microsoft-Windows-Deployment" {comp}>
			<RunSynchronous>
				<RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>{escape(extract)}</Path></RunSynchronousCommand>
				<RunSynchronousCommand wcm:action="add"><Order>2</Order><Path>reg.exe add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
			</RunSynchronous>
		</component>
	</settings>
	<settings pass="oobeSystem">
		<component name="Microsoft-Windows-Shell-Setup" {comp}>
			<OOBE><HideEULAPage>true</HideEULAPage><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><HideOnlineAccountScreens>true</HideOnlineAccountScreens><ProtectYourPC>3</ProtectYourPC></OOBE>
			<FirstLogonCommands>
				<SynchronousCommand wcm:action="add"><Order>1</Order><CommandLine>powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\\Windows\\Setup\\Scripts\\drock-winscript.ps1"</CommandLine></SynchronousCommand>
			</FirstLogonCommands>
		</component>
	</settings>
	<Extensions xmlns="urn:drock:winscript">
		<File path="C:\\Windows\\Setup\\Scripts\\drock-winscript.ps1">
{escape(script)}
		</File>
	</Extensions>
</unattend>
"""


# ------------------------------------------------------------------ /winscript

HELP = """/winscript: WinScript's Windows tweaks, run and checked by DRock
  /winscript import [path]          read the catalogue from a WinScript checkout (default {default})
  /winscript list [word]            tweaks by tab; a word filters titles, ids and tabs
  /winscript show <id>              what a tweak does, line by line, and whether undo covers it
  /winscript presets                basic, strict, extreme and what each selects
  /winscript status [selection]     which tweaks are in effect now, read from the registry (default: all)
  /winscript preview <selection>    the exact script apply would run (nothing runs)
  /winscript apply <selection> [--no-restore] [--dry-run]
                                    restore point, then the selection as ONE admin command (DRock asks, then UAC),
                                    then every registry value read back and every removed app looked up
  /winscript undo [run]             put back the registry values a run changed (default: the latest run)
  /winscript runs                   past runs and their reports
  /winscript export <file> <selection>   a config WinScript's -i flag (or /winscript apply --config) loads
  /winscript apps [word]            the app list; /winscript install <app>... installs through INSTALL_PACKAGE
  /winscript unattend <file.xml> <selection> [--no-bypass]   an autounattend.xml that runs the selection at first logon
  <selection>: tweak ids, group-<id>, debloat-<id>, appx:<package>, preset names, or --config <file.json>"""


def _runs_dir() -> Path:
    return _data_root() / "runs"


def _executor(session):
    """DRock's Executor under the session's Policy (its approvals, guard, UAC path). On its own: Standalone."""
    try:
        from .actions import Executor
        from .policy import Policy
    except ImportError:
        return Standalone()
    pol = getattr(session, "policy", None) or Policy("ask", confirm=getattr(session, "confirm", None))
    return Executor(pol)


class _Result:
    def __init__(self, ok: bool, error: str | None = None, declined: bool = False, verified: bool = False):
        self.ok, self.error, self.declined, self.verified = ok, error, declined, verified
        self.status, self.output = ("success" if ok else "failure"), ""


class Standalone:
    """The two actions /winscript runs, for use without DRock: asked y/N on the console every time, elevated by
    Windows' own UAC prompt, the exit code read back."""

    def __init__(self, ask=input):
        self.ask = ask

    def _yes(self, action: dict) -> bool:
        print(f"\n{action['action']}: {action.get('command') or action.get('package')}\n  {action.get('reason', '')}")
        return self.ask("run it? [y/N] ").strip().lower() in ("y", "yes")

    def run(self, action: dict):
        import subprocess
        if not self._yes(action):
            return _Result(False, "declined at the prompt", declined=True)
        if action["action"] == "ADMIN_COMMAND":
            ps = ("$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList "
                  f"@('-NoProfile','-ExecutionPolicy','Bypass','-Command',{_psq(action['command'])}); exit $p.ExitCode")
            try:
                rc = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps], timeout=3600).returncode
            except (OSError, subprocess.SubprocessError) as e:
                return _Result(False, str(e))
            if rc == 1:   # Start-Process throws when the UAC prompt is declined
                return _Result(False, "exit code 1223: the UAC prompt was declined", declined=True)
            return _Result(rc == 0, None if rc == 0 else f"exit code {rc}")
        if action["action"] == "INSTALL_PACKAGE":
            pkg = action["package"]
            rc = subprocess.run(["winget", "install", "--id", pkg, "-e", "--accept-source-agreements",
                                 "--accept-package-agreements"]).returncode
            listed = subprocess.run(["winget", "list", "--id", pkg, "-e"], capture_output=True, text=True).stdout
            return _Result(rc == 0, None if rc == 0 else f"exit code {rc}", verified=pkg.lower() in listed.lower())
        return _Result(False, f"{action['action']} is not something /winscript runs")


def main(argv=None) -> int:
    """Standalone: python winscript.py <the /winscript arguments>."""
    import sys
    return command(None, " ".join(sys.argv[1:] if argv is None else argv))


def _selection(cat: dict, words: list[str]) -> Selection:
    if "--config" in words:
        i = words.index("--config")
        if i + 1 >= len(words):
            s = Selection()
            s.problems.append("--config needs a file")
            return s
        try:
            config = json.loads(Path(words[i + 1]).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as e:
            s = Selection()
            s.problems.append(f"{words[i + 1]}: {e}")
            return s
        sel = from_config(cat, config)
        rest = select(cat, words[:i] + words[i + 2:])
        for iid in rest.tweaks:
            sel.add_tweak(cat, iid)
        sel.appx += [a for a in rest.appx if a not in sel.appx]
        sel.problems += rest.problems
        return sel
    return select(cat, words)


def command(session, arg: str) -> int:
    words = arg.split()
    sub, rest = (words[0].lower(), words[1:]) if words else ("", [])
    try:
        if sub in ("", "help"):
            print(HELP.format(default=DEFAULT_SOURCE))
            try:
                cat = load_catalog()
                print(f"(catalogue: WinScript {cat['winscript_version']}, {len(cat['tweaks'])} tweaks, "
                      f"{len(cat['rejected'])} refused, imported {cat['imported']} from {cat['source']})")
            except SourceError as e:
                print(f"({e})")
            return 0
        if sub == "import":
            src = Path(" ".join(rest)) if rest else DEFAULT_SOURCE
            cat = import_catalog(src)
            p = save_catalog(cat)
            regs = sum(len(t["registry"]) for t in cat["tweaks"].values())
            print(f"imported WinScript {cat['winscript_version']} from {src}: {len(cat['tweaks'])} tweaks "
                  f"({regs} registry lines), {len(cat['groups'])} groups, {len(cat['debloat'])} Store-app lists, "
                  f"{len(cat['presets'])} presets, {len(cat['apps'])} apps -> {p}")
            for iid, why in sorted(cat["rejected"].items()):
                print(f"  refused {iid}: {why}")
            return 0
        cat = load_catalog()
        if sub == "list":
            word = " ".join(rest).lower()
            last = None
            for iid, t in sorted(cat["tweaks"].items(), key=lambda kv: (kv[1]["tab"], kv[0])):
                if word and word not in f"{iid} {t['title']} {t['tab']} {t.get('section') or ''}".lower():
                    continue
                if t["tab"] != last:
                    print(f"\n{t['tab'] or '(no tab)'}")
                    last = t["tab"]
                flag = "  [refused]" if iid in cat["rejected"] else f"  [one of: {t['radio']}]" if t.get("radio") else ""
                print(f"  {iid:24} {t['title']}{flag}")
            return 0
        if sub == "show":
            if not rest or rest[0] not in cat["tweaks"]:
                print(f"no such tweak: {' '.join(rest)}")
                return 1
            iid, t = rest[0], cat["tweaks"][rest[0]]
            print(f"{iid}: {t['title']} ({t['tab']}{', ' + t['section'] if t.get('section') else ''})")
            if t["desc"]:
                print(f"  {t['desc']}")
            if iid in cat["rejected"]:
                print(f"  REFUSED: {cat['rejected'][iid]}")
            for l in t["lines"]:
                print(f"    {l}")
            ops = t["registry"]
            other = [l for l in t["lines"] if _changes_outside_registry(l)]
            print(f"  {len(ops)} registry line(s) read back after a run" +
                  (f"; {len(other)} other line(s) only a restore point can undo" if other else "; undo covers all of it"))
            return 0
        if sub == "status":
            return _status(cat, rest)
        if sub == "presets":
            for name, ids in cat["presets"].items():
                print(f"{name} ({len(ids)}): {' '.join(ids)}")
            return 0
        if sub == "apps":
            word = " ".join(rest).lower()
            for name, ids in sorted(cat["apps"].items()):
                if not word or word in name.lower():
                    print(f"  {name:28} winget {ids.get('winget') or '-':42} choco {ids.get('choco') or '-'}")
            return 0
        if sub == "install":
            return _install(session, cat, rest)
        if sub == "runs":
            for d in sorted(_runs_dir().glob("*"), reverse=True)[:20]:
                rep = d / "report.json"
                if rep.is_file():
                    r = json.loads(rep.read_text(encoding="utf-8"))
                    counts = {}
                    for row in r.get("rows", []):
                        counts[row["status"]] = counts.get(row["status"], 0) + 1
                    print(f"  {d.name}  {r.get('outcome')}  " + ", ".join(f"{k} {v}" for k, v in counts.items()))
                else:
                    print(f"  {d.name}  (no report)")
            return 0
        if sub == "undo":
            return _undo(session, rest[0] if rest else None)
        if sub in ("preview", "apply", "export", "unattend"):
            target = None
            if sub in ("export", "unattend"):
                if not rest:
                    print(f"/winscript {sub} needs a file name, then the selection")
                    return 1
                target, rest = Path(rest[0]), rest[1:]
            flags = {w for w in rest if w in ("--no-restore", "--dry-run", "--no-bypass")}
            sel = _selection(cat, [w for w in rest if w not in flags])
            for n in sel.notes:
                print(f"  note: {n}")
            if sel.problems:
                for p in sel.problems:
                    print(f"  {p}")
                print("(nothing ran)")
                return 1
            if not sel.tweaks and not sel.appx:
                print("nothing selected. /winscript list shows the ids; presets: " + ", ".join(cat["presets"]))
                return 1
            if sub == "export":
                target.write_text(json.dumps(to_config(cat, sel), indent=2), encoding="utf-8")
                print(f"wrote {target}: {len(sel.tweaks)} tweak(s), {len(sel.appx)} Store app(s) on")
                return 0
            if sub == "unattend":
                stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                script = build_script(cat, sel, Path(r"C:\Windows\Setup\Scripts"), restore=False, stamp=stamp)
                target.write_text(unattend_xml(script, bypass="--no-bypass" not in flags), encoding="utf-8")
                print(f"wrote {target}: {len(sel.tweaks)} tweak(s), {len(sel.appx)} Store app(s) at first logon"
                      + ("" if "--no-bypass" in flags else "; Windows 11's hardware checks skipped"))
                return 0
            return _apply(session, cat, sel, preview=sub == "preview" or "--dry-run" in flags,
                          restore="--no-restore" not in flags)
        print(f"unknown /winscript command {sub!r}. /winscript alone lists them.")
        return 1
    except SourceError as e:
        print(f"(winscript: {e})")
        return 1


def _new_run() -> tuple[str, Path]:
    """A run folder name nobody has used: two runs in one second must not share undo records."""
    base = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    stamp, n = base, 1
    while (_runs_dir() / stamp).exists():
        n += 1
        stamp = f"{base}-{n}"
    return stamp, _runs_dir() / stamp


def _apply(session, cat: dict, sel: Selection, preview: bool, restore: bool) -> int:
    stamp, run_dir = _new_run()
    script = build_script(cat, sel, run_dir, restore=restore, stamp=stamp)
    norestore = [t for t in sel.tweaks if not undo_covers(cat["tweaks"][t])]
    print(f"{len(sel.tweaks)} tweak(s), {len(sel.appx)} Store app(s)"
          + (f"; {len(norestore) + len(sel.appx)} of them change more than registry values, which only the restore "
             f"point can undo: {', '.join(norestore[:8])}{'...' if len(norestore) > 8 else ''}" if norestore or sel.appx else
             "; all of it is registry values /winscript undo can put back"))
    if preview:
        print(script)
        print("(preview: nothing ran)")
        return 0
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "winscript.ps1").write_text(script, encoding="utf-8-sig")
    before = snapshot(cat, sel)
    (run_dir / "before.json").write_text(json.dumps(before, indent=1, default=str), encoding="utf-8")
    (run_dir / "selection.json").write_text(json.dumps({"tweaks": sel.tweaks, "appx": sel.appx,
                                                        "catalogue": cat["body_sha256"], "restore": restore}, indent=1),
                                            encoding="utf-8")
    action = {"action": "ADMIN_COMMAND", "command": f"& {_psq(str(run_dir / 'winscript.ps1'))}",
              "reason": f"/winscript apply: {len(sel.tweaks)} WinScript tweak(s), {len(sel.appx)} Store app(s); the "
                        f"script is {run_dir / 'winscript.ps1'}"}
    r = _executor(session).run(action)
    results = read_results(run_dir)
    if getattr(r, "declined", False) or "1223" in str(getattr(r, "error", "")):
        outcome = "declined: nothing ran"
    elif restore and not (results.get("_restore_check") or {}).get("found"):
        rc = results.get("_restore_check") or {}
        outcome = (f"stopped: no restore point from the last 24 hours (newest: {rc.get('newest') or 'none'}); "
                   "nothing was changed. /winscript apply ... --no-restore runs without one") if rc else \
            f"stopped before the first tweak: {getattr(r, 'error', '') or 'no results'}"
    else:
        outcome = "ran" if getattr(r, "ok", False) else f"ran, exit: {getattr(r, 'error', '')}"
    rows = verdicts(cat, sel, results, appx_present([a["appx"] for a in sel.appx]) if results else {})
    report = {"run": stamp, "outcome": outcome, "restore": results.get("_restore_check"), "rows": rows}
    (run_dir / "report.json").write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
    print(f"/winscript run {stamp}: {outcome}")
    if results.get("_restore_check", {}).get("found"):
        print(f"  restore point: {results['_restore_check'].get('description')} ({results['_restore_check'].get('newest')})")
    for row in rows:
        print(f"  {row['status']:16} {row['id']:28} {row['why']}")
    if any(row["status"] in ("verified", "ran", "ran with errors") for row in rows):
        print(f"  a restart finishes some of these changes. /winscript undo {stamp} puts the registry values back.")
    print(f"  run folder: {run_dir}")
    return 0 if rows and all(row["status"] in ("verified", "ran") for row in rows) else 1


def status_of(tweak: dict) -> str:
    """Whether a tweak is in effect now, from its registry lines alone: in effect, partly, not in effect, or
    unknown (it has no registry line to read)."""
    states = [check_op(o)[0] for o in tweak["registry"] if o["checkable"]]
    if not states:
        return "unknown"
    hits = states.count("verified")
    return "in effect" if hits == len(states) else "partly" if hits else "not in effect"


def _status(cat: dict, words: list[str]) -> int:
    sel = _selection(cat, words) if words else None
    if sel and sel.problems:
        for p in sel.problems:
            print(f"  {p}")
        return 1
    ids = sel.tweaks if sel else sorted(cat["tweaks"])
    counts = {}
    for iid in ids:
        s = status_of(cat["tweaks"][iid])
        counts[s] = counts.get(s, 0) + 1
        print(f"  {s:14} {iid:24} {cat['tweaks'][iid]['title']}")
    print("  " + ", ".join(f"{k} {v}" for k, v in counts.items()) + "  (read from the registry now; "
          "'unknown' tweaks change things only a run can report)")
    return 0


def _undo(session, which: str | None) -> int:
    runs = sorted(d for d in _runs_dir().glob("*") if (d / "before.json").is_file())
    run_dir = next((d for d in runs if d.name == which), None) if which else (runs[-1] if runs else None)
    if run_dir is None:
        print("no recorded run to undo" + (f" named {which}" if which else ""))
        return 1
    before = json.loads((run_dir / "before.json").read_text(encoding="utf-8"))
    for b in before:
        if b.get("binary") and isinstance(b.get("value"), str):
            b["value"] = b["value"].upper()
    lines, skipped = undo_lines(before)
    if not lines:
        print(f"{run_dir.name}: no registry values to put back")
        return 1
    undo_dir = run_dir / "undo"
    undo_dir.mkdir(exist_ok=True)
    body = ["$ErrorActionPreference = 'Continue'"] + [f"& {l}" if l.startswith("reg ") else l for l in lines]
    (undo_dir / "undo.ps1").write_text("\r\n".join(body) + "\r\n", encoding="utf-8-sig")
    print(f"undo {run_dir.name}: {len(lines)} registry value(s) back to what they were"
          + (f"; {len(skipped)} could not be read before the run and stay as they are" if skipped else ""))
    r = _executor(session).run({"action": "ADMIN_COMMAND", "command": f"& {_psq(str(undo_dir / 'undo.ps1'))}",
                                "reason": f"/winscript undo {run_dir.name}: put {len(lines)} registry value(s) back"})
    if getattr(r, "declined", False):
        print("(declined: nothing changed)")
        return 1
    wrong = []
    for b in before:
        if b["present"] is None:
            continue
        present, t, value = read_value(b["key"], b["name"])
        want = bytes.fromhex(b["value"]) if b.get("binary") and isinstance(b["value"], str) else b["value"]
        if bool(present) != bool(b["present"]) or (present and value != want):
            wrong.append(f"{b['key']}\\{b['name'] or '(default)'}: is {value!r}, was {b['value']!r}")
    for w in wrong[:10]:
        print(f"  not restored: {w}")
    print(f"  {len(before) - len(skipped) - len(wrong)} of {len(before) - len(skipped)} value(s) read back as they were")
    return 0 if not wrong else 1


def _install(session, cat: dict, names: list[str]) -> int:
    if not names:
        print("/winscript install <app>...  (names from /winscript apps)")
        return 1
    ex, rc = _executor(session), 0
    lookup = {n.lower(): n for n in cat["apps"]}
    for n in names:
        name = lookup.get(n.lower())
        pkg = (cat["apps"].get(name) or {}).get("winget") if name else None
        if not pkg:
            print(f"  {n}: not in WinScript's app list with a winget id")
            rc = 1
            continue
        r = ex.run({"action": "INSTALL_PACKAGE", "package": pkg, "reason": f"/winscript install {name}"})
        print(f"  {name} ({pkg}): {'installed' if r.ok else (r.error or r.status)}" + ("" if r.ok and r.verified else
              "" if not r.ok else " (not verified)"))
        rc |= 0 if r.ok else 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
