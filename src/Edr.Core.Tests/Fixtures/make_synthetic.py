"""Writes the synthetic parity fixtures (inputs only). Then run EDR-Tray.ps1 -SelfTest on each to add model.json:

    python -I make_synthetic.py
    foreach ($f in 'synthetic-a','synthetic-b') { $env:EDR_SELFTEST_ROOT = "$PWD\\$f\\inputs"; $env:EDR_SELFTEST_DUMP = "$PWD\\$f"
                                                  powershell -STA -File ..\\..\\..\\EDR-Tray.ps1 -SelfTest }

They cover what the live fixture does not: Wail2Ban fails/bans/logins, user blocks, CVE items, history,
hidden apps, Defender de-duplication, wildcard/ancestor/CIDR exclusions, retired rules and pause states.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SEP = " \u00a6 "
CLAUDE = r"C:\Users\x\AppData\Local\Claude-Data\anthropicpbc.claude_abc\claude-code\2.1.309\9078b9c1d466\claude.exe"
PWSH = r"C:\Program Files\PowerShell\7\pwsh.exe"


def ev(i, time, blade, title, sev="Medium", **kw):
    e = {"time": time, "blade": blade, "severity": sev, "title": title, "process": kw.pop("process", ""), "detail": kw.pop("detail", ""), "id": f"e{i:02d}"}
    e.update(kw)
    return e


EVENTS = [
    ev(1, "2026-11-01 10:00:01", "realtime", "Encoded PowerShell command", "High", process=PWSH, parent=CLAUDE, rule="Encoded PowerShell command", detail="pwsh -enc AAAA"),
    ev(2, "2026-11-01 10:05:00", "realtime", "Encoded PowerShell command", "High", process=PWSH, parent=CLAUDE, rule="Encoded PowerShell command", detail="pwsh -enc BBBB"),
    ev(3, "2026-11-01 10:06:00", "realtime", "Startup entry added or changed (Run key)", process=r"C:\Program Files\Microsoft OneDrive\26.1.0\OneDrive.exe", rule="Startup entry added or changed (Run key)", detail=r"HKCU\...\Run\OneDrive"),
    ev(4, "2026-11-01 10:07:00", "realtime", "LSASS memory dump", "Critical", process=r"C:\Temp\evil.exe", parent=r"C:\Windows\explorer.exe", rule="LSASS memory dump", detail="evil.exe lsass procdump"),
    ev(5, "2026-11-01 10:08:00", "realtime", "PowerShell download or in-memory execution", "High", process=PWSH, parent=r"C:\WINDOWS\System32\cmd.exe", ancestors=[CLAUDE], rule="PowerShell download or in-memory execution", detail="-Command iex"),
    ev(6, "2026-10-31 09:00:00", "realtime", "Suspicious Encoded/Download Execution", process=r"C:\Program Files\Git\cmd\git.exe", rule="Suspicious Encoded/Download Execution", detail="git -e"),
    ev(7, "2026-11-01 10:09:00", "ioc", "Known malware: Mimi", "Critical", process=r"C:\Users\x\Downloads\m.exe", sha256="AAA111", rule="Executable launched from Downloads"),
    ev(8, "2026-11-01 10:10:00", "ioc", "Known malware: Fine", "Critical", process=r"C:\Tools\ok.exe", sha256="BBB222"),
    ev(9, "2026-11-01 10:11:00", "yara", "YARA match: Ransom_Note", "Critical", process=r"C:\Users\x\AppData\Local\Temp\r.exe"),
    ev(10, "2026-10-31 19:19:30", "defender", "Defender detected malware: HackTool:Win32/X", "High", kind="malware", threat="HackTool:Win32/X", threatId="2147786202", process=r"C:\Program Files\Git\bin\bash.exe", detail="CmdLine:_bash -c ..."),
    ev(11, "2026-10-31 20:05:03", "sigma", "Antivirus - Hacktool Signature", "High", process="PC1", detail="Threat: HackTool:Win32/X" + SEP + "Severity: High" + SEP + "Proc: C:\\Program Files\\Git\\bin\\bash.exe", eventTime="2026-10-31 19:19:30.123 +02:00"),
    ev(12, "2026-10-31 20:05:03", "sigma", "Defender Alert (High)", "High", process="PC1", detail="Threat: Trojan:PowerShell/Y" + SEP + "Severity: High" + SEP + "Proc: " + PWSH, eventTime="2026-10-31 19:56:00.621 +02:00"),
    ev(13, "2026-10-31 22:32:58", "defender", "Controlled folder access blocked a write", kind="cfa", path=r"%userprofile%\Pictures", process=r"C:\Windows\explorer.exe", detail=r"Tried to change: %userprofile%\Pictures"),
    ev(14, "2026-10-31 22:40:00", "defender", "Defender ASR blocked: Block credential stealing from LSASS", kind="asr", asrId="9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", path=r"C:\Windows\System32\lsass.exe", process=r"C:\Tools\dump.exe"),
    ev(15, "2026-10-31 22:41:00", "defender", "Defender ASR blocked: Block credential stealing from LSASS", kind="asr", asrId="9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", path=r"C:\Windows\System32\lsass.exe", process=r"C:\Tools\dump.exe"),
    ev(16, "2026-10-31 20:05:03", "sigma", "Important Log File Cleared", "High", process="PC1", detail="Log: System" + SEP + "User: x", eventTime="2026-10-30 17:10:48.009 +02:00"),
    ev(17, "2026-10-31 20:05:03", "sigma", "Proc Exec (Sysmon Alert)", "High", process="PC1", detail="Rule: X" + SEP + "Proc: C:\\a\\b.exe"),
    ev(18, "2026-11-01 15:14:41", "sigma", "Script Interpreter Execution From Suspicious Folder", "High", process="PC1",
       detail="Cmdline: cmd /c x" + SEP + "Proc: C:\\Windows\\System32\\cmd.exe" + SEP + "User: x" + SEP + "ParentCmdline: \"" + CLAUDE + "\" --output-format stream-json"),
    ev(19, "2026-11-01 15:14:41", "sigma", "Bad Rule", "Critical", process="PC1", detail="Proc: C:\\bad\\b.exe"),
    ev(20, "2026-11-01 15:20:00", "sigma", "Other Rule", "High", process="PC1", detail="Proc: C:\\o\\o.exe" + SEP + "ParentImage: C:\\p\\other.exe"),
    ev(21, "2026-11-01 11:00:00", "wail2ban", "Failed logon from 203.0.113.5", "Low", ip="203.0.113.5", kind="fail", user="admin"),
    ev(22, "2026-11-01 11:01:00", "wail2ban", "Failed logon from 203.0.113.5", "Low", ip="203.0.113.5", kind="fail", user="admin"),
    ev(23, "2026-11-01 11:02:00", "wail2ban", "Failed logon from 203.0.113.5", "Low", ip="203.0.113.5", kind="fail", user="root"),
    ev(24, "2026-11-01 11:03:00", "wail2ban", "Failed logon from 192.168.1.50", "Low", ip="192.168.1.50", kind="fail"),
    ev(25, "2026-10-30 08:00:00", "wail2ban", "Blocked 198.51.100.7 for 25 minutes", "Medium", ip="198.51.100.7", expires="2026-10-30 08:25:00", strike=2),
    ev(26, "2026-10-30 07:00:00", "wail2ban", "Failed logon from 198.51.100.7", "Low", ip="198.51.100.7", kind="fail"),
    ev(27, "2026-10-30 09:00:00", "wail2ban", "Failed logon from 198.51.100.7", "Low", ip="198.51.100.7", kind="fail"),
    ev(28, "2026-11-01 12:00:00", "wail2ban", "Blocked 198.51.100.9 for 2 hours", "Medium", ip="198.51.100.9", expires="2026-11-01 14:00:00", strike=3),
    ev(29, "2026-11-01 12:30:00", "wail2ban", "Successful login as PC1\\user from 203.0.113.77 (public internet)", "High", ip="203.0.113.77", kind="login", user="PC1\\user", logonType="10"),
    ev(30, "2026-11-01 12:31:00", "wail2ban", "Failed logon from 203.0.113.99", "Low", ip="203.0.113.99", kind="fail"),
    ev(31, "2026-11-01 13:00:00", "system", "Sysmon sensor is not working", "High", kind="health", detail="Sysmon driver is StopPending - restart the PC.  Real-time   detection is blind."),
    ev(32, "2026-11-01 13:05:00", "system", "Scan finished: 0 new Sigma alerts", "Info", kind="scan", trigger="schedule"),
    ev(33, "2026-11-01 13:06:00", "patch", "EDR tool update: Velociraptor 0.77.2 -> 0.77.3", "Info", kind="tool", process="Velociraptor"),
    ev(34, "2026-11-01 13:07:00", "cve", "CVE-2026-9 in foo 1.0", process="foo", cve="CVE-2026-9"),
    ev(35, "2026-10-29 10:00:00", "realtime", "Encoded PowerShell command", "High", process=r"C:\old\x.exe", rule="Encoded PowerShell command", legacy=True),
    ev(36, "2026-11-01 14:00:00", "realtime", "Executable launched from Downloads", "Low", process=r"C:\Users\x\Downloads\setup.exe", rule="Executable launched from Downloads"),
    ev(37, "2026-11-01 14:01:00", "realtime", "New user or admin group change", "High", process=r"C:\Windows\System32\net.exe", parent=r"C:\Windows\System32\cmd.exe", rule="New user or admin group change", detail="net user bob /add"),
    ev(38, "2026-11-01 14:02:00", "realtime", "Encoded PowerShell command", "High", process=PWSH, parent=r"C:\Users\x\AppData\Local\Programs\Other\other.exe", rule="Encoded PowerShell command", detail="x"),
    ev(39, "2026-11-01 14:03:00", "realtime", "Startup entry added or changed (Run key)", process=r"C:\Program Files\Google\Drive File Stream\133.0.2.0\GoogleDriveFS.exe", rule="Startup entry added or changed (Run key)", oldRule=False),
    ev(40, "2026-11-01 14:04:00", "realtime", "Encoded PowerShell command", "High", process=r"C:\Temp\evil.exe", rule="Encoded PowerShell command", kind="blocked-start"),
]

BLOCKS = {"items": [
    {"id": "b1", "blade": "realtime", "image": r"C:\Temp\evil.exe", "sha256": "", "title": "LSASS memory dump", "added": "2026-11-01 10:30:00", "note": "Blocked by you.", "hits": 2, "enforce": True},
    {"id": "b2", "blade": "sigma", "title": "Bad Rule", "added": "2026-11-01 16:00:00", "note": "Confirmed by you."},
    {"id": "b3", "blade": "wail2ban", "ip": "203.0.113.99", "added": "2026-11-01 12:40:00", "note": "Blocked by you."},
    None,
]}

EXCL = {
    "realtimePath": [],
    "realtime": [
        {"id": "x1", "added": "2026-11-01 09:00", "rule": "Startup entry added or changed (Run key)", "image": r"C:\Program Files\Microsoft OneDrive\*\OneDrive*.exe", "parent": "", "raw": ""},
        {"id": "x2", "added": "2026-11-01 09:01", "rule": "PowerShell download or in-memory execution", "image": "", "parent": r"C:\Users\x\AppData\Local\Claude-Data\anthropicpbc.claude_abc\claude-code\*\*\claude.exe", "ancestors": 3},
        {"id": "x8", "added": "2026-11-01 09:02", "rule": "*", "image": "", "parent": "", "signer": "Google LLC"},
        None,
    ],
    "ioc": [{"id": "x3", "added": "2026-11-01 09:03", "sha256": "bbb222", "image": r"C:\Tools\ok.exe"}],
    "yara": [],
    "sigma": [{"id": "x4", "added": "2026-11-01 09:04", "title": "*", "parent": r"C:\p\other.exe"}],
    "wail2ban": [{"id": "x5", "added": "2026-11-01 09:05", "cidr": "192.168.1.0/24", "note": "home LAN"}],
    "cve": [{"id": "x6", "added": "2026-11-01 09:06", "cve": "CVE-2026-1", "package": "foo"}],
    "defender": [{"id": "x7", "added": "2026-11-01 09:07", "kind": "cfa", "path": r"C:\Windows\explorer.exe", "note": ""}],
}

CVE = {"scanned": "2026-11-01T21:16:00", "items": [
    {"id": "GHSA-1", "cve": "CVE-2026-1", "aliases": ["GHSA-1"], "package": "foo", "version": "1.0", "fixed": "1.1", "severity": "High", "summary": "excluded", "path": "C:/a"},
    {"id": "GHSA-2", "cve": "CVE-2026-2", "package": "bar", "version": "2.0", "fixed": "2.1", "severity": "High", "summary": "Bar   has\na  bug " * 20, "path": "C:/b"},
    {"id": "GHSA-3", "cve": "CVE-2026-3", "package": "aaa", "version": "3.0", "fixed": "3.1", "severity": "Medium", "summary": "aaa bug", "path": "C:/c"},
    {"id": "GHSA-4", "cve": "CVE-2026-4", "package": "Zed", "version": "4.0", "fixed": "4.1", "severity": "High", "summary": "zed bug", "path": "C:/d"},
    {"id": "GHSA-5", "cve": "CVE-2026-5", "package": "upd", "version": "5.0", "fixed": "5.1", "severity": "Critical", "summary": "updated", "path": "C:/e"},
    {"id": "GHSA-6", "cve": "CVE-2026-6", "package": "odd", "version": "6.0", "fixed": "6.1", "severity": "Weird", "summary": "unknown severity", "path": "C:/f"},
]}

HISTORY = {"items": [
    {"id": "h1", "sec": "cve", "key": "GHSA-5", "time": "2026-11-01 22:00:00", "cve": "CVE-2026-5", "package": "upd", "version": "5.0", "fixed": "5.1"},
    {"id": "h2", "sec": "apps", "key": "Foo.App", "time": "2026-11-01 22:10:00", "name": "Foo App", "version": "1.0", "latest": "2.0"},
    {"id": "h3", "sec": "cve", "key": "GHSA-3", "time": "2026-11-01 08:00:00", "cve": "CVE-2026-3", "package": "aaa", "version": "3.0", "fixed": "3.1"},
]}

SYSMON = """<Sysmon schemaversion="4.90"><EventFiltering>
<RuleGroup name="ProcessCreateInclude" groupRelation="or"><ProcessCreate onmatch="include">
<Rule name="Encoded PowerShell command" groupRelation="and"><Image condition="contains any">pwsh.exe</Image></Rule>
<Rule name="PowerShell download or in-memory execution" groupRelation="and"><Image condition="contains any">pwsh.exe</Image></Rule>
<Rule name="LSASS memory dump" groupRelation="and"><CommandLine condition="contains">lsass</CommandLine></Rule>
<Rule name="New user or admin group change" groupRelation="or"><CommandLine condition="contains any">user /add</CommandLine></Rule>
<Rule name="Executable launched from Downloads" groupRelation="or"><Image condition="begin with">C:\\Users\\x\\Downloads\\</Image></Rule>
</ProcessCreate></RuleGroup>
<RuleGroup name="RegistryInclude" groupRelation="or"><RegistryEvent onmatch="include">
<TargetObject name="Startup entry added or changed (Run key)" condition="contains any">\\CurrentVersion\\Run\\</TargetObject>
</RegistryEvent></RuleGroup>
<RuleGroup name="BuiltInExclusions" groupRelation="or"><ProcessCreate onmatch="exclude">
<Image condition="begin with">C:\\Program Files\\Epic Games\\</Image><Image condition="begin with">C:\\EDR\\</Image><Image condition="begin with">C:\\EDR\\</Image>
</ProcessCreate></RuleGroup>
</EventFiltering></Sysmon>
"""


def status(paused, scan_ok=True):
    return {
        "heartbeat": "2099-01-01T00:00:00", "engineStarted": "2026-11-01T21:35:29",
        "edr": {"state": "paused" if paused else "on", "pausedUntil": "9999-12-31T00:00:00" if paused else None, "error": None},
        "wail2ban": {"state": "paused" if paused else "on", "pausedUntil": "2026-11-01T23:45:00" if paused else None, "error": None,
                     "banned": [{"ip": "198.51.100.9", "expires": "2026-11-01 14:00:00", "strikes": 3}], "rdp140": True},
        "sysmon": {"ok": True, "message": "Running", "service": "Running", "driver": "Running"},
        "scan": {"running": False, "lastStart": "2026-11-01T21:15:49", "lastEnd": "2026-11-01T21:16:50", "ok": scan_ok, "summary": "Sigma scan failed", "nextDue": "2026-11-02T06:00:00"},
        "blocks": 1,
    }


def write(fixture, reviewed, st, event_list=None):
    base = os.path.join(HERE, fixture, "inputs")
    for d in ("data", "config", "local"):
        os.makedirs(os.path.join(base, d), exist_ok=True)

    def dump(rel, obj):
        with open(os.path.join(base, rel), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)

    evs = EVENTS if event_list is None else event_list
    with open(os.path.join(base, "data", "events.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for e in evs:
            f.write(json.dumps(e) + "\n")
        f.write('{"broken json\n')   # skipped by both trays
        f.write('{"time":"2026-11-01 23:59:59","blade":"realtime","title":"incomplete last line"')   # no newline: not read yet
    dump(os.path.join("data", "status.json"), st)
    dump(os.path.join("data", "cve-current.json"), CVE)
    dump(os.path.join("config", "exclusions.json"), EXCL)
    dump(os.path.join("config", "blocklist.json"), BLOCKS)
    dump(os.path.join("local", "history.json"), HISTORY)
    with open(os.path.join(base, "config", "sysmonconfig.xml"), "w", encoding="utf-8") as f:
        f.write(SYSMON)
    with open(os.path.join(base, "local", "reviewed.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(reviewed) + "\n")
    with open(os.path.join(base, "local", "ignored-apps.txt"), "w", encoding="utf-8") as f:
        f.write("Some.App\nOther.App\n")


write("synthetic-a", ["e36", "  "], status(paused=False))
write("synthetic-b", ["e16", "e29", "e37", "e36"], status(paused=True, scan_ok=False))

# synthetic-c: more than 10,000 events to verify bounded buffer eviction and aggregate retention
older_evs = []
for i in range(20):
    older_evs.append(ev(1000 + i, "2026-10-28 01:00:00", "realtime", "Encoded PowerShell command", "High", process=PWSH, parent=CLAUDE, rule="Encoded PowerShell command", detail="pwsh -enc OLD"))
for i in range(10):
    older_evs.append(ev(1100 + i, "2026-10-28 01:01:00", "wail2ban", "Failed logon from 203.0.113.5", "Low", ip="203.0.113.5", kind="fail", user="admin"))
for i in range(10):
    older_evs.append(ev(1200 + i, "2026-10-28 01:02:00", "wail2ban", "Blocked 198.51.100.99 for 1 hour", "Medium", ip="198.51.100.99", expires="2026-10-28 02:00:00", strike=1))
for i in range(10):
    older_evs.append(ev(1300 + i, "2026-10-28 01:03:00", "realtime", "New user or admin group change", "High", process=r"C:\Windows\System32\net.exe", parent=r"C:\Windows\System32\cmd.exe", rule="New user or admin group change", detail="net user alice /add"))

import datetime

base_dt = datetime.datetime(2026, 10, 20, 0, 0, 0)
filler_evs = [ev(2000 + i, (base_dt + datetime.timedelta(seconds=10 * i)).strftime("%Y-%m-%d %H:%M:%S"), "system", f"Periodic scan heartbeat {i}", "Info", kind="scan") for i in range(9960)]
events_c = older_evs + filler_evs + EVENTS

write("synthetic-c", ["e36", "  "], status(paused=False), event_list=events_c)
print("ok")
