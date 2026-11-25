# drock-winscript

WinScript's Windows tweaks (debloat, privacy, telemetry, performance) from the command line: browse them,
preview the exact PowerShell, apply a selection as one elevated run, then read every registry value back and
put them back on request.

It is the `/winscript` command of DRock, a local computer-use agent, and it also runs on its own. One file,
Python standard library only, Windows.

[WinScript](https://github.com/flick9000/winscript) by flick9000 is a desktop app with a curated catalogue of
about 130 tweaks. This program does not contain that catalogue. `import` reads it from your own copy of the
WinScript source and keeps it as data. What it adds is what WinScript's Run button does not do:

| | WinScript | drock-winscript |
|---|---|---|
| errors | `$ErrorActionPreference = "SilentlyContinue"` | every tweak runs in its own block; its errors and exit code are recorded |
| result | none | each registry value is read back; each removed Store app is looked up again |
| restore point | optional | made first; the run stops if Windows has none from the last 24 hours (`--no-restore` skips it) |
| undo | restore point only | the prior state of every registry value is saved first; `undo` puts it back |
| status | none | `status` reads which tweaks are in effect right now |

## Use

```
git clone https://github.com/flick9000/winscript
python winscript.py import winscript
python winscript.py list privacy
python winscript.py show recall
python winscript.py status basic
python winscript.py preview basic
python winscript.py apply basic
python winscript.py undo
```

Inside DRock the same commands are `/winscript import`, `/winscript list`, and so on.

| command | what it does |
|---|---|
| `import [path]` | read the catalogue from a WinScript checkout (default `$WINSCRIPT_SRC`, else `~/Desktop/opensource/winscript-main`) |
| `list [word]` | tweaks by tab; a word filters ids, titles and tabs |
| `show <id>` | the tweak's lines, and how much of it undo covers |
| `presets` | basic, strict, extreme |
| `status [selection]` | in effect, partly, not in effect, or unknown (no registry line to read), from the registry now |
| `preview <selection>` | the exact script `apply` would run; nothing runs |
| `apply <selection> [--no-restore] [--dry-run]` | restore point, the selection as one elevated PowerShell run, then the read-back report |
| `undo [run]` | put back the registry values a run changed (default: the latest run) |
| `runs` | past runs and their reports |
| `export <file> <selection>` | a config in WinScript's own format; its `-i` flag loads it |
| `apps [word]`, `install <app>...` | WinScript's app list, installed one at a time with winget |
| `unattend <file.xml> <selection> [--no-bypass]` | an autounattend.xml that runs the selection at first logon |

A selection is any mix of tweak ids, `group-<id>`, `debloat-<id>`, `appx:<package>`, preset names, and
`--config <file.json>` (a WinScript export).

Every elevated run is asked first (y/N on its own; DRock's approval prompt inside DRock), then Windows shows
its UAC prompt. Runs are kept in `~/.drock-winscript/runs/<time>/` (`$WINSCRIPT_DATA` moves it): the script,
the registry values before, what each tweak reported, and the report.

## What it refuses

- WinScript's `installmas` option, which runs the Microsoft Activation Scripts to activate Windows and Office
  without a license.
- Any tweak that downloads something when it runs. In WinScript 2.30.0 that is `adobetelemetry`, which appends
  a hosts list fetched from a third-party URL. The content is not known when you preview it.
- Two options of one choice (two DNS providers, two power plans).
- A catalogue file that changed after it was imported.

A preset or group that contains a refused tweak runs the rest and says what it left out. WinScript's `extreme`
preset names `thirdparty` and `msapps`, which match no switch in WinScript either; they select nothing here too.

## Limits

- Undo covers registry values written with `reg add` / `reg delete`. 80 of WinScript 2.30.0's 128 tweaks are
  only that. The rest also remove apps, change services or delete tasks; `show` and the apply report name them,
  and only the restore point takes those back.
- Values are read in the 64-bit view, as the current user. If the elevated run uses a different account (an
  administrator who is not you typed the UAC password), HKCU values land in that account and read back as failed.
- Some changes need a restart. Nothing here restarts the computer.

## Tests

```
python -m unittest discover -s tests
```

32 tests, no elevation and no registry writes: the elevated run is faked and the registry reads are patched,
except one that reads a value every Windows has. The rules were mutation-checked: 13 deliberate breaks
(radio conflicts, refusals, the read-back, the restore-point stop, undo, the catalogue hash, the dry run...),
each one caught by a test. `docs/AUDIT.md` compares WinScript and DRock problem by problem and lists the decisions.

## License

GPL-3.0, the same as WinScript (`LICENSE`). The catalogue you import is WinScript's work, under its license.
