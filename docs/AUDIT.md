# WinScript into DRock: audit before code (2026-11-25)

/winscript command", then "once built please opensource the program uploading it github".
radius, adversarial tests, before/after regression).

## 1. DRock baseline (before any change)

- 118 actions, 34 REPL commands (chat.COMMANDS; tests/test_commands.py holds the table to both dispatch loops).
- Actions that overlap WinScript: ADMIN_COMMAND (high), RUN_MAINTENANCE (high), UNINSTALL_PACKAGE (high),
  INSTALL_PACKAGE (medium, winget -> Chocolatey -> scoop), SET_SETTING (medium), GET_SETTING (low),
  START_SERVICE (medium), STOP_SERVICE (low), CHECK_PACKAGE (low).
- Elevation: act_fail._elevate_windows runs one command through Start-Process -Verb RunAs (Windows' own UAC
  prompt), captures output and exit code to files; a declined prompt is exit 1223.
- Approval: HIGH risk is asked every time, in every mode (policy). The REPL's slash commands are dispatched in
  chat.Session._handle; a feature module answers `command(session, arg)` (tribunal.py, remote.py).
  library only, no action counts as done because something said so.
- Suite: the full unittest run of 2026-11-25 (numbers in section 7, before and after).

## 2. WinScript audit (app 2.30.0, GPL-3.0, Tauri: Astro/TypeScript UI + 23 lines of Rust)

| part | what it is | why it exists |
|---|---|---|
| assets/js/scripts.ts `scripts` | ~150 ids, each a list of PowerShell lines (reg add, Remove-AppxPackage, services, tasks) | the curated tweak catalogue: the product |
| `checkboxItems`, `presets` (basic, strict, extreme) | which ids are toggles; three canned selections | quick start for non-experts |
| components/MainPage.astro | tabs, ScriptGroup (incl. radio groups), GroupToggle (`group-<id>` selects its members), DebloatGroup (`debloat-<id>`, AppX package ids) | the UI tree; titles are i18n keys |
| i18n/locales/en.json (+14 languages) | titles and descriptions | the only explanation of each tweak |
| DebloatGroup inline script | `@(ids) \| ForEach-Object { Get-AppxPackage $_ \| Remove-AppxPackage }` | Store-app removal |
| assets/js/appinstall.ts | app lists for Chocolatey and winget (`{id, url}` = name, package id) | bulk install |
| main.ts Run | writes %TEMP%\winscript\winscript.ps1, starts it in a new (elevated) PowerShell; nothing is read back | apply |
| MockupCode.astro | the script frame: admin check, `$ErrorActionPreference = "SilentlyContinue"`, optional restore point, Chocolatey bootstrap (iex of a download), MAS, restart prompt | glue |
| main.ts import/export, `-i` flag | `{elementId: bool}` JSON | share and replay a configuration |
| assets/js/unattend.ts | autounattend.xml with LabConfig bypass keys, BypassNRO, OOBE skips, the script run at first logon | unattended installs |
| tauri updater | self-update from GitHub | distribution |

## 3. Compared by problem

| # | problem | WinScript | DRock today | does DRock have the problem | decision |
|---|---|---|---|---|---|
| 2 | quick selections | presets, group-*, debloat-* | none | yes | ADAPT: imported with the catalogue, expanded to ids |
| 3 | options that exclude each other | radio groups | none | yes | ADAPT: a selection with two members of one radio group is refused, not silently resolved |
| 4 | running the script elevated | temp .ps1 in a new terminal; the app runs as administrator | ADMIN_COMMAND: UAC, captured output, exit code | no | KEEP DRock's: the whole selection is ONE ADMIN_COMMAND through the session's executor (asked as HIGH, one UAC prompt). No second runner. |
| 5 | knowing what happened | nothing: errors silenced, nothing read back | every action verified | WinScript lacks it | ADAPT: each tweak runs in its own try block and writes its status to a results file; every `reg add` / `reg delete` is read back afterwards (non-elevated reg query). A tweak is verified, failed, or ran-unverified, and the report says which. |
| 6 | undoing it | an optional restore point | RENAME_FILES writes an undo manifest | WinScript lacks it | ADAPT: restore point on by default (and checked to exist); the prior value of every registry value a `reg` line touches is saved first; /winscript undo restores those. Non-registry changes (removed apps, services) are named as restore-point-only. |
| 7 | sharing a configuration | `{id: bool}` JSON, `-i` | none | yes | ADAPT: the same format both ways, so a config moves between WinScript and DRock |
| 8 | bulk app install | appinstall.ts lists, `winget install` loop, Chocolatey bootstrap via iex | INSTALL_PACKAGE per package (winget, Chocolatey, scoop; signed checks; asks) | no | KEEP INSTALL_PACKAGE; import only the name -> winget id list. REJECT the Chocolatey bootstrap (remote script piped to iex). |
| 9 | removing Store apps | DebloatGroup | UNINSTALL_PACKAGE covers winget/MSI, not AppX | partly | ADAPT: AppX ids join the script; verified by Get-AppxPackage afterwards |
| 10 | unattended installs | unattend.ts | none | yes | ADAPT: DRock's own generator (Microsoft's documented LabConfig and OOBE settings, a local account, the selected tweaks at first logon). The concept is borrowed; the XML is written here. |
| 11 | Windows/Office activation | MAS: `irm https://get.activated.win \| iex` | none | - | REJECT: license circumvention, and remote code piped to iex |
| 12 | self-update | tauri updater, GitHub | offline-only | - | REJECT |
| 13 | restart after | Read-Host Y/N inside the script | the elevated window is hidden | - | ADAPT: the report says a restart is needed; DRock never restarts on its own |
| 14 | 15 languages | i18n | English | - | English titles only |

## 4. Invariants this must not break

1. No new agent action and no grammar change: the model cannot apply a tweak; only a person typing /winscript can.
2. HIGH risk is asked every time: the apply runs as ADMIN_COMMAND through the session's executor and policy.
3. Offline: /winscript reaches the network only through INSTALL_PACKAGE, when the user asks for apps.
4. Core stays standard library only (the importer parses TypeScript string literals itself).
5. Nothing is reported done without evidence: the report comes from the results file and the read-back.
6. chat.COMMANDS matches both dispatch loops (tests/test_commands.py).
7. GPL-3.0 text is never written into DRock's source tree; it lives in DRock's data folder, imported from the
   user's own copy.

## 5. Blast radius

REPL line -> chat.Session._handle (a new `/winscript` branch before classify; nothing else routes there) ->
winscript.command -> catalogue (data/winscript/catalog.json, read-only after import) -> selection -> script
assembly -> executor.run(ADMIN_COMMAND) / executor.run(INSTALL_PACKAGE) (existing paths, existing approvals) ->
data/winscript/runs/<stamp>/ (script, results, prior registry values, report) -> printed report.
Untouched: classify, routing, grammar, agent loop, gate, memory, traces (the run folder is the record).

## 6. Adversarial cases (each one a test)

- an id the catalogue does not have; a preset name that does not exist
- a request for MAS or any id outside the imported catalogue: refused
- two members of one radio group selected: refused with both names
- a catalogue changed after import (sha256 mismatch): apply refused until re-imported
- UAC declined (1223): nothing reported as applied
- one tweak throws, the others still run and are reported
- a `reg add` that ran but reads back a different value: failed, not verified
- `reg add` with /ve, quoted names with spaces, REG_SZ data with spaces, HKCU vs HKLM
- undo with no recorded run; undo of a run whose registry values were absent before (delete, not set to "")
- a config JSON with unknown ids, non-boolean values, or a radio conflict
- dry run never calls the executor
- the importer pointed at a folder that is not WinScript

## 7. Regression

Full suite before (the 2026-11-25 run) and after; tests/test_commands.py; `drock actions` count unchanged (118).
