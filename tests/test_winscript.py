"""/winscript (winscript.py): WinScript's catalogue imported as data, selected, applied through DRock's executor,
read back, undone. research/winscript-audit/AUDIT.md section 6 lists the adversarial cases these cover.

No elevation, no registry writes: the executor is a fake, the registry reads are patched (one test reads a real,
always-present HKLM value). Run from the repository root:
    python -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import winscript as ws  # noqa: E402

SCRIPTS_TS = r'''
document.addEventListener("DOMContentLoaded", function () {
    const parentDiv = document.querySelector(".allScripts");
    const scripts: Record<string, string[]> = {
        // a comment between entries
        storeupdates: [
            "Write-Host '-- Store updates off' -ForegroundColor Magenta",
            'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 2 /f',
        ],
        spaced: [
            'reg add "HKCU\\Control Panel\\Mouse" /v "Mouse Speed" /d "0" /t REG_SZ /f',
            `reg add "HKCU\\Software\\X" /ve /t REG_SZ /d "a b c" /f`,
        ],
        apps: [
            "Get-AppxPackage *Xbox* | Remove-AppxPackage",
        ],
        hosts: [
            'Invoke-WebRequest -Uri "https://example.com/list.txt" -OutFile "$env:TEMP\\l.txt"',
        ],
        googledns: ['Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8'],
        quad9dns: ['Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 9.9.9.9'],
    };
    const checkboxItems = ["storeupdates"];
});
const presets: Record<string, string[]> = {
    basic: ["storeupdates", "group-feat"],
    extreme: ["storeupdates", "hosts", "msapps"],
};
'''
PAGE = r'''
<Tab tab="debloat">
<ScriptToggle title={t["s.title"]} description={t["s.desc"]} inputId="storeupdates" />
<GroupToggle title={t["g.title"]} description={t["g.desc"]} id="feat" scripts={[
    { title: t["sp.title"], inputId: "spaced", description:
        t["sp.desc"] },
    { title: t["ap.title"], inputId: "apps" },
    { title: t["h.title"], inputId: "hosts" },
]} />
<DebloatGroup title={t["d.title"]} desc={t["d.desc"]} id="microsoft" apps={[
    { title: "3D Builder", appId: "*Microsoft.3DBuilder*" },
]} />
</Tab>
<Tab tab="privacy">
<ScriptGroup title={t["dns.title"]} description={t["dns.desc"]} tools={[
    { title: t["none"], inputId: "none", radio: true, group: "dns" },
    { title: t["gd"], inputId: "googledns", radio: true, group: "dns" },
    { title: t["q9"], inputId: "quad9dns", radio: true, group: "dns" },
]} />
<ScriptToggle title={t["rp.title"]} inputId="restorepoint" />
</Tab>
'''
EN = {"s.title": "Disable Store updates", "s.desc": "Stops automatic Store updates", "g.title": "Features",
      "sp.title": "Mouse speed", "sp.desc": "Acceleration off", "ap.title": "Xbox apps", "h.title": "Hosts list",
      "d.title": "Microsoft apps", "dns.title": "DNS", "gd": "Google DNS", "q9": "Quad9", "rp.title": "Restore point"}
APPS_TS = '''
const appListChocolatey = [
    { id: "Brave", url: "brave" },
];
const appListWinget = [
    { id: "Brave", url: "Brave.Brave" },
];
'''


def make_checkout(root: Path) -> Path:
    app = root / "app"
    for rel, text in (("src/assets/js/scripts.ts", SCRIPTS_TS), ("src/components/MainPage.astro", PAGE),
                      ("src/i18n/locales/en.json", json.dumps(EN)), ("src/assets/js/appinstall.ts", APPS_TS),
                      ("src-tauri/tauri.conf.json", json.dumps({"version": "9.9.9"}))):
        p = app / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="drock-ws-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        env = mock.patch.dict(os.environ, {"WINSCRIPT_DATA": str(self.tmp / "data" / "winscript")})
        env.start()
        self.addCleanup(env.stop)
        self.cat = ws.import_catalog(make_checkout(self.tmp / "winscript"))


class TestLiterals(unittest.TestCase):
    def test_escapes_and_quotes(self):
        cases = [(r'"a\\b \"q\""', 'a\\b "q"'), (r"'it\'s'", "it's"), ("`x \\` y`", "x ` y")]
        got = [ws._string(src, 0)[0] for src, _ in cases]
        self.assertEqual(got, [want for _, want in cases], f"got {got}")

    def test_template_interpolation_is_refused(self):
        with self.assertRaises(ws.SourceError):
            ws._string("`a ${b}`", 0)


class TestImport(Base):
    def test_catalogue(self):
        c = self.cat
        got = (sorted(c["tweaks"]), c["groups"]["group-feat"]["members"], [a["appx"] for a in c["debloat"]["debloat-microsoft"]["apps"]],
               c["radios"], c["apps"]["Brave"], c["tweaks"]["storeupdates"]["title"], c["tweaks"]["spaced"]["desc"],
               c["tweaks"]["storeupdates"]["tab"], c["winscript_version"])
        want = (["apps", "googledns", "hosts", "quad9dns", "spaced", "storeupdates"], ["spaced", "apps", "hosts"],
                ["*Microsoft.3DBuilder*"], {"dns": ["none", "googledns", "quad9dns"]}, {"choco": "brave", "winget": "Brave.Brave"},
                "Disable Store updates", "Acceleration off", "debloat", "9.9.9")
        self.assertEqual(got, want, f"got {got}\nexpected {want}")

    def test_network_tweak_and_mas_refused(self):
        self.assertIn("needs the internet", self.cat["rejected"]["hosts"])
        self.assertIn("installmas", self.cat["rejected"])

    def test_not_a_checkout(self):
        with self.assertRaises(ws.SourceError):
            ws.import_catalog(self.tmp)

    def test_tampered_catalogue_refused(self):
        p = ws.save_catalog(self.cat)
        data = json.loads(p.read_text(encoding="utf-8"))
        data["tweaks"]["storeupdates"]["lines"].append("Remove-Item C:\\ -Recurse")
        p.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ws.SourceError):
            ws.load_catalog()


@unittest.skipUnless(ws.DEFAULT_SOURCE.is_dir(), "no WinScript checkout at the default path")
class TestRealCheckout(unittest.TestCase):
    def test_imports_and_refuses_what_it_must(self):
        c = ws.import_catalog(ws.DEFAULT_SOURCE)
        ops = [o for t in c["tweaks"].values() for o in t["registry"]]
        print(f"\nWinScript {c['winscript_version']}: {len(c['tweaks'])} tweaks, {len(ops)} registry lines, "
              f"refused {sorted(c['rejected'])}")
        self.assertGreater(len(c["tweaks"]), 100)
        self.assertIn("adobetelemetry", c["rejected"])
        self.assertTrue(all(o["key"].split("\\")[0].upper() in ws._ROOTS for o in ops), "a key with an unknown hive")
        for name in c["presets"]:
            self.assertEqual(ws.select(c, [name]).problems, [], name)


class TestRegOps(unittest.TestCase):
    def test_forms(self):
        lines = ['reg add "HKLM\\A\\B" /v "Name With Space" /d "0" /t REG_DWORD /f',
                 'reg add "HKCU\\X" /ve /t REG_SZ /d "a b c" /f',
                 'reg.exe delete "HKLM\\A" /v Old /f',
                 'reg delete "HKLM\\Gone" /f',
                 'reg add "HKCU\\Y" /v P /t REG_SZ /d "$env:USERPROFILE\\x" /f',
                 'Write-Host "reg add not a command"']
        got = [(o["op"], o["key"], o["name"], o["type"], o["data"], o["checkable"]) for o in ws.reg_ops(lines)]
        want = [("add", "HKLM\\A\\B", "Name With Space", "REG_DWORD", "0", True),
                ("add", "HKCU\\X", "", "REG_SZ", "a b c", True),
                ("delete", "HKLM\\A", "Old", "REG_SZ", "", True),
                ("delete_key", "HKLM\\Gone", None, "REG_SZ", "", True),
                ("add", "HKCU\\Y", "P", "REG_SZ", "$env:USERPROFILE\\x", False)]
        self.assertEqual(got, want, f"got {got}\nexpected {want}")

    def test_expected_values(self):
        got = [ws.expected({"type": t, "data": d}) for t, d in
               (("REG_DWORD", "2"), ("REG_DWORD", "0x10"), ("REG_SZ", "a b"), ("REG_MULTI_SZ", "a\\0b"), ("REG_BINARY", "0aff"))]
        self.assertEqual(got, [2, 16, "a b", ["a", "b"], b"\x0a\xff"], f"got {got}")

    def test_a_real_value_reads(self):
        present, t, value = ws.read_value("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild")
        self.assertEqual((present, t), (True, "REG_SZ"), f"got {(present, t, value)}")


class TestSelection(Base):
    def test_unknown_and_refused_by_name_stop(self):
        s = ws.select(self.cat, ["storeupdates", "nosuch", "hosts", "installmas"])
        self.assertEqual(s.tweaks, ["storeupdates"])
        self.assertEqual(len(s.problems), 3, s.problems)

    def test_radio_conflict(self):
        s = ws.select(self.cat, ["googledns", "quad9dns"])
        self.assertTrue(any("one choice (dns)" in p for p in s.problems), s.problems)

    def test_group_and_preset_note_instead_of_stop(self):
        s = ws.select(self.cat, ["extreme", "group-feat"])
        self.assertEqual((s.tweaks, s.problems), (["storeupdates", "spaced", "apps"], []), (s.tweaks, s.problems))
        self.assertEqual(len(s.notes), 3, s.notes)   # hosts twice (preset, group) and msapps

    def test_debloat_and_single_app(self):
        s = ws.select(self.cat, ["debloat-microsoft", "appx:*Nope*"])
        self.assertEqual(([a["appx"] for a in s.appx], len(s.problems)), (["*Microsoft.3DBuilder*"], 1))

    def test_config_round_trip_and_strictness(self):
        s = ws.select(self.cat, ["storeupdates", "googledns", "debloat-microsoft"])
        config = ws.to_config(self.cat, s)
        back = ws.from_config(self.cat, {**config, "restorepoint": True, "group-feat": False, "Brave": True})
        self.assertEqual((back.tweaks, back.appx, back.problems), (s.tweaks, s.appx, []))
        bad = ws.from_config(self.cat, {"storeupdates": "yes", "made_up": True, "googledns": True, "quad9dns": True})
        self.assertEqual(len(bad.problems), 3, bad.problems)


class FakeResult:
    def __init__(self, ok=True, error=None, declined=False):
        self.ok, self.error, self.declined, self.status, self.verified, self.output = ok, error, declined, "success", ok, ""


class FakeExecutor:
    def __init__(self, write_results=None, result=None):
        self.actions, self.write_results, self.result = [], write_results, result or FakeResult()

    def run(self, action):
        self.actions.append(action)
        if self.write_results:
            self.write_results(action)
        return self.result


class TestApply(Base):
    def setUp(self):
        super().setUp()
        ws.save_catalog(self.cat)
        self.registry = {}   # (key, name) -> (type, value)

        def read(key, name):
            hit = self.registry.get((key.lower(), name.lower()))
            return (True, hit[0], hit[1]) if hit else (False, None, None)
        p = mock.patch.object(ws, "read_value", read)
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(ws, "appx_present", lambda pats: {x: False for x in pats})
        p2.start()
        self.addCleanup(p2.stop)

    def run_cmd(self, arg, ex):
        with mock.patch.object(ws, "_executor", lambda session: ex):
            return ws.command(object(), arg)

    def script_ran(self, rows, set_registry=True):
        """A fake elevated run: writes results.jsonl rows and (optionally) the registry values the lines write."""
        def write(action):
            path = action["command"][3:-1].replace("''", "'")
            run_dir = Path(path).parent
            with open(run_dir / "results.jsonl", "w", encoding="utf-8-sig") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")
            if set_registry:
                for iid in json.loads((run_dir / "selection.json").read_text(encoding="utf-8"))["tweaks"]:
                    for op in self.cat["tweaks"][iid]["registry"]:
                        self.registry[(op["key"].lower(), (op["name"] or "").lower())] = (op["type"], ws.expected(op))
        return write

    def test_preview_and_dry_run_never_execute(self):
        ex = FakeExecutor()
        rc = (self.run_cmd("preview storeupdates", ex), self.run_cmd("apply storeupdates --dry-run", ex))
        self.assertEqual((rc, ex.actions), ((0, 0), []))

    def test_problems_never_execute(self):
        ex = FakeExecutor()
        self.assertEqual((self.run_cmd("apply googledns quad9dns", ex), ex.actions), (1, []))

    def test_one_admin_command_then_read_back(self):
        ok = {"id": "_restore_check", "found": True, "newest": "now", "description": "DRock winscript"}
        ex = FakeExecutor(self.script_ran([ok, {"id": "storeupdates", "exit": 0, "errors": []},
                                           {"id": "spaced", "exit": 0, "errors": []}]))
        rc = self.run_cmd("apply storeupdates spaced", ex)
        report = json.loads(next((self.tmp / "data" / "winscript" / "runs").glob("*/report.json")).read_text(encoding="utf-8"))
        got = (rc, [a["action"] for a in ex.actions], [(r["id"], r["status"]) for r in report["rows"]])
        self.assertEqual(got, (0, ["ADMIN_COMMAND"], [("storeupdates", "verified"), ("spaced", "verified")]), f"got {got}")

    def test_a_value_that_reads_back_wrong_fails(self):
        ok = {"id": "_restore_check", "found": True}
        ex = FakeExecutor(self.script_ran([ok, {"id": "storeupdates", "exit": 0, "errors": []}], set_registry=False))
        rc = self.run_cmd("apply storeupdates", ex)
        report = json.loads(next((self.tmp / "data" / "winscript" / "runs").glob("*/report.json")).read_text(encoding="utf-8"))
        self.assertEqual((rc, report["rows"][0]["status"]), (1, "failed"), report["rows"])

    def test_a_value_present_but_different_fails(self):
        self.registry[("hklm\\software\\policies\\microsoft\\windowsstore", "autodownload")] = ("REG_DWORD", 4)
        ok = {"id": "_restore_check", "found": True}
        ex = FakeExecutor(self.script_ran([ok, {"id": "storeupdates", "exit": 0, "errors": []}], set_registry=False))
        self.run_cmd("apply storeupdates", ex)
        row = json.loads(next((self.tmp / "data" / "winscript" / "runs").glob("*/report.json")).read_text(encoding="utf-8"))["rows"][0]
        self.assertEqual(row["status"], "failed", row)
        self.assertIn("is 4, expected 2", row["why"])

    def test_one_tweak_throws_the_others_are_reported(self):
        ok = {"id": "_restore_check", "found": True}
        ex = FakeExecutor(self.script_ran([ok, {"id": "apps", "exit": 0, "thrown": "Access denied", "errors": ["x"]},
                                           {"id": "storeupdates", "exit": 0, "errors": []}]))
        self.run_cmd("apply apps storeupdates", ex)
        report = json.loads(next((self.tmp / "data" / "winscript" / "runs").glob("*/report.json")).read_text(encoding="utf-8"))
        self.assertEqual([(r["id"], r["status"]) for r in report["rows"]], [("apps", "failed"), ("storeupdates", "verified")])

    def test_uac_declined_reports_nothing_applied(self):
        ex = FakeExecutor(result=FakeResult(ok=False, error="exit code 1223: the UAC prompt was declined", declined=True))
        rc = self.run_cmd("apply storeupdates", ex)
        report = json.loads(next((self.tmp / "data" / "winscript" / "runs").glob("*/report.json")).read_text(encoding="utf-8"))
        self.assertEqual((rc, report["outcome"], report["rows"][0]["status"]), (1, "declined: nothing ran", "not run"))

    def test_no_restore_point_stops_before_any_tweak(self):
        ex = FakeExecutor(self.script_ran([{"id": "_restore_check", "found": False, "newest": ""}]),
                          result=FakeResult(ok=False, error="exit code 3"))
        rc = self.run_cmd("apply storeupdates", ex)
        report = json.loads(next((self.tmp / "data" / "winscript" / "runs").glob("*/report.json")).read_text(encoding="utf-8"))
        self.assertTrue(report["outcome"].startswith("stopped: no restore point"), report["outcome"])
        self.assertEqual((rc, report["rows"][0]["status"]), (1, "not run"))

    def test_undo_puts_back_what_was_there(self):
        self.registry[("hklm\\software\\policies\\microsoft\\windowsstore", "autodownload")] = ("REG_DWORD", 4)
        ok = {"id": "_restore_check", "found": True}
        ex = FakeExecutor(self.script_ran([ok, {"id": "storeupdates", "exit": 0, "errors": []},
                                           {"id": "spaced", "exit": 0, "errors": []}]))
        self.run_cmd("apply storeupdates spaced", ex)
        undo = FakeExecutor()
        self.run_cmd("undo", undo)
        script = Path(undo.actions[0]["command"][3:-1]).read_text(encoding="utf-8-sig")
        self.assertIn('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "4" /f', script)
        self.assertIn('reg delete "HKCU\\Control Panel\\Mouse" /v "Mouse Speed" /f', script)   # absent before: deleted
        self.assertIn('reg delete "HKCU\\Software\\X" /ve /f', script)

    def test_two_runs_in_one_second_keep_their_own_records(self):
        ok = {"id": "_restore_check", "found": True}
        for _ in range(2):
            self.run_cmd("apply storeupdates", FakeExecutor(self.script_ran([ok, {"id": "storeupdates", "exit": 0}])))
        runs = sorted(p.name for p in (self.tmp / "data" / "winscript" / "runs").iterdir())
        self.assertEqual(len(runs), 2, f"got {runs}")

    def test_the_restore_point_only_tweaks_are_named_before_running(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.run_cmd("preview apps storeupdates", FakeExecutor())
        first = buf.getvalue().splitlines()[0]
        self.assertIn("only the restore point can undo: apps", first, first)

    def test_status_reads_the_registry_now(self):
        t = self.cat["tweaks"]
        before = (ws.status_of(t["storeupdates"]), ws.status_of(t["apps"]))
        self.registry[("hkcu\\control panel\\mouse", "mouse speed")] = ("REG_SZ", "0")
        partly = ws.status_of(t["spaced"])
        self.registry[("hkcu\\software\\x", "")] = ("REG_SZ", "a b c")
        got = (before, partly, ws.status_of(t["spaced"]))
        self.assertEqual(got, (("not in effect", "unknown"), "partly", "in effect"), f"got {got}")

    def test_undo_with_nothing_recorded(self):
        ex = FakeExecutor()
        self.assertEqual((self.run_cmd("undo", ex), ex.actions), (1, []))


class TestStandalone(Base):
    def test_runs_without_drock(self):
        """A copy of winscript.py outside the package: its own data folder, the same commands."""
        import shutil
        import subprocess
        import sys
        alone = self.tmp / "alone"
        alone.mkdir()
        shutil.copy2(Path(ws.__file__), alone / "winscript.py")
        env = {**os.environ, "WINSCRIPT_DATA": str(self.tmp / "standalone-data"), "PYTHONUTF8": "1"}
        env.pop("DROCK_DATA", None)
        imp = subprocess.run([sys.executable, "-I", str(alone / "winscript.py"), "import", str(self.tmp / "winscript")],
                             capture_output=True, text=True, env=env, timeout=120)
        lst = subprocess.run([sys.executable, "-I", str(alone / "winscript.py"), "list", "store"],
                             capture_output=True, text=True, env=env, timeout=120)
        got = (imp.returncode, (self.tmp / "standalone-data" / "catalog.json").is_file(), lst.returncode, "storeupdates" in lst.stdout)
        self.assertEqual(got, (0, True, 0, True), f"got {got}\n{imp.stdout}{imp.stderr}\n{lst.stdout}{lst.stderr}")

    def test_a_no_at_the_prompt_runs_nothing(self):
        with mock.patch("subprocess.run") as sp:
            r = ws.Standalone(ask=lambda q: "n").run({"action": "ADMIN_COMMAND", "command": "x", "reason": "y"})
        self.assertEqual((r.ok, r.declined, sp.called), (False, True, False))


class TestScriptAndUnattend(Base):
    def test_script_shape(self):
        s = ws.select(self.cat, ["storeupdates", "debloat-microsoft"])
        text = ws.build_script(self.cat, s, Path("C:\\run"), restore=True, stamp="t")
        self.assertIn("Invoke-DrockTweak 'storeupdates' {", text)
        self.assertIn("Get-AppxPackage '*Microsoft.3DBuilder*' | Remove-AppxPackage", text)
        self.assertIn("if (-not $fresh) { exit 3 }", text)
        self.assertNotIn("$ErrorActionPreference = \"SilentlyContinue\"", text)
        self.assertLess(text.index("Checkpoint-Computer"), text.index("Invoke-DrockTweak 'storeupdates'"))

    def test_unattend_is_valid_xml_with_the_script(self):
        s = ws.select(self.cat, ["storeupdates"])
        xml = ws.unattend_xml(ws.build_script(self.cat, s, Path("C:\\Windows\\Setup\\Scripts"), restore=False))
        root = ET.fromstring(xml)
        ns = {"u": "urn:schemas-microsoft-com:unattend"}
        self.assertEqual(len(root.findall(".//u:RunSynchronousCommand", ns)), 7)   # 5 LabConfig + extract + BypassNRO
        file_text = root.find(".//{urn:drock:winscript}File").text
        self.assertIn("Invoke-DrockTweak 'storeupdates'", file_text)
        no_bypass = ET.fromstring(ws.unattend_xml("x", bypass=False))
        self.assertEqual(len(no_bypass.findall(".//u:RunSynchronousCommand", ns)), 2)


if __name__ == "__main__":
    unittest.main()
