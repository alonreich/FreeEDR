using System.Text.Json.Nodes;

namespace Edr.Core;

public sealed record ProfileEntry(string List, string Rule = "", string Image = "", string Parent = "", string ParentSigner = "",
                                  int Ancestors = 0, string Signer = "", string Detail = "", string Match = "", string Title = "");

public sealed record AllowProfile(string Id, string Name, bool Default, string Category, string What, string[] Detect, ProfileEntry[] Entries);

public static class Profiles
{
    private static readonly string[] PsLauncherRules = ["Encoded PowerShell command", "PowerShell download or in-memory execution"];
    private static readonly string[] PsLauncherSigma = ["PowerShell Base64 Encoded FromBase64String Cmdlet", "Script Interpreter Execution From Suspicious Folder"];

    private static IEnumerable<ProfileEntry> AiEntries(string parent, string signer) =>
        PsLauncherRules.Select(r => new ProfileEntry("realtime", Rule: r, Parent: parent, ParentSigner: signer, Ancestors: Catalog.MaxAncestors))
            .Concat(PsLauncherSigma.Select(t => new ProfileEntry("sigma", Title: t, Parent: parent, ParentSigner: signer)));

    private static List<AllowProfile>? _all;

    public static IReadOnlyList<AllowProfile> All => _all ??= Build();

    public static AllowProfile? Get(string id) => All.FirstOrDefault(p => p.Id == id);

    private static List<AllowProfile> Build()
    {
        var pr = EdrPaths.ProfilesRoot;
        var pf = EdrPaths.ProgramFiles;
        var pf86 = EdrPaths.ProgramFilesX86;
        var sysRoot = EdrPaths.SystemRoot;
        const string claudeLauncher = "$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT; $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT = $null; Invoke-Expression -Command $__claudeCodeScript";
        return
        [
            new("claude-code", "Claude Code (Anthropic)", true, "app",
                "Claude Code's PowerShell tool: encoded syntax checks and its shell launcher. Only these PowerShell rules, only under claude.exe signed by Anthropic, PBC (or its exact launcher command line).",
                [$@"{pr}\*\AppData\Local\Claude-Data\*\claude-code", $@"{pf}\WindowsApps\AnthropicPBC.Claude_*", $@"{pr}\*\.local\bin\claude.exe"],
                [.. AiEntries(@"*\claude.exe", Catalog.ClaudeSigner),
                 new("realtime", Rule: "PowerShell download or in-memory execution", Image: @"*\pwsh.exe", Match: "exact", Detail: $"\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\"  -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{claudeLauncher}\""),
                 new("realtime", Rule: "PowerShell download or in-memory execution", Image: @"*\pwsh.exe", Match: "exact", Detail: $"pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{claudeLauncher}\""),
                 new("realtime", Rule: "PowerShell download or in-memory execution", Image: @"*\pwsh.exe", Match: "exact", Detail: "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\" -NoLogo -Command \"$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT; Invoke-Expression ...\""),
                 new("realtime", Rule: "Encoded PowerShell command", Image: @"*\pwsh.exe", Match: "exact", Detail: "pwsh.exe -NoProfile -EncodedCommand CgBmAHUAbgBjAHQAaQBvAG4AIABXAHIAaQB0AGUALQBSAGUAcwB1AGwAdAAoACQASgBzAG8AbgA="),
                 new("realtime", Rule: "Encoded PowerShell command", Image: @"*\pwsh.exe", Match: "exact", Detail: "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\" -NoProfile -NonInteractive -NoLogo -EncodedCommand CgBmAHUAbgBjAHQAaQBvAG4AIABXAHIAaQB0AGUALQBSAGUAcwB1AGwAdAAoACQASgBzAG8AbgApACAAewAKACAAIAAgACAAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoAVABvAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuA...")]),
            new("openai-codex", "ChatGPT / Codex (OpenAI)", true, "app",
                "PowerShell started by the ChatGPT desktop app and the Codex agent (signed by OpenAI OpCo, LLC): commands, notification sounds, git helpers.",
                [$@"{pf}\WindowsApps\OpenAI.Codex_*", $@"{pr}\*\AppData\Local\OpenAI\Codex"],
                [.. AiEntries(@"*\ChatGPT.exe", "OpenAI OpCo, LLC"), .. AiEntries(@"*\codex.exe", "OpenAI OpCo, LLC")]),
            new("antigravity", "Antigravity (Google AI IDE)", false, "dev",
                "PowerShell started by the Antigravity agent. Off by default: Antigravity is not digitally signed and lives in a user-writable folder; enable only if trusted.",
                [$@"{pr}\*\AppData\Local\Programs\antigravity\Antigravity.exe"],
                [.. AiEntries($@"{pr}\*\AppData\Local\Programs\antigravity\*", "")]),
            new("vcpkg", "Visual Studio Build Tools (vcpkg shell)", true, "dev",
                "The vcpkg environment script that Visual Studio developer shells load with \"iex (get-content ...vcpkg-init.cmd)\".",
                [$@"{pf}*\Microsoft Visual Studio\*\*\VC\vcpkg\vcpkg-init.cmd"],
                [new("realtime", Rule: "PowerShell download or in-memory execution", Image: @"*\pwsh.exe", Detail: "*vcpkg-init.cmd*"),
                 new("realtime", Rule: "PowerShell download or in-memory execution", Image: @"*\powershell.exe", Detail: "*vcpkg-init.cmd*")]),
            new("wpbbin", "OEM Motherboard Boot Binary (wpbbin.exe)", true, "system",
                "Motherboard UEFI platform binary executed at boot by smss.exe (Windows Platform Binary Table / WPBT).",
                [$@"{sysRoot}\System32\wpbbin.exe"],
                [new("sigma", Title: "UEFI Persistence Via Wpbbin - ProcessCreation", Parent: @"*\smss.exe"),
                 new("realtime", Rule: "*", Image: $@"{sysRoot}\System32\wpbbin.exe", Parent: @"*\smss.exe")]),
            new("freeedr-build", "FreeEDR Project Build Output", true, "dev",
                "FreeEDR installer and build outputs (FreeEDR-Setup*.exe, FreeEDR-*.exe) regardless of folder, preventing false-positive alerts during local builds.",
                [],
                [new("realtime", Rule: "*", Image: @"*\FreeEDR-Setup*.exe"),
                 new("realtime", Rule: "*", Image: @"*\FreeEDR-Tray*.exe"),
                 new("realtime", Rule: "Defender exclusion added", Detail: "*FreeEDR-Setup.exe*"),
                 new("realtime", Rule: "Encoded PowerShell command", Image: @"*\powershell.exe", Detail: "* -Encoding *"),
                 new("realtime", Rule: "Encoded PowerShell command", Image: @"*\pwsh.exe", Detail: "* -Encoding *"),
                 new("realtime", Rule: "Windows script/LOLBin made a network connection", Image: @"*\rundll32.exe"),
                 new("sigma", Title: "Suspicious PowerShell Invocations - Specific", Parent: @"*\FreeEDR-Setup*.exe")]),
            new("onedrive", "Microsoft OneDrive", true, "app",
                "Everything OneDrive does: start-up entries, sync service, updates and its setup program (any version; per-user copies only when signed by Microsoft).",
                [$@"{pf}\Microsoft OneDrive", $@"{pr}\*\AppData\Local\Microsoft\OneDrive\OneDrive.exe"],
                [new("realtime", Rule: "*", Image: $@"{pf}\Microsoft OneDrive\*"),
                 new("realtime", Rule: "*", Image: $@"{pr}\*\AppData\Local\Microsoft\OneDrive\*", Signer: "Microsoft Corporation"),
                 new("realtime", Rule: "*", Image: $@"{pr}\*\Downloads\OneDriveSetup*.exe", Signer: "Microsoft Corporation")]),
            new("office", "Microsoft Office updates (Click-to-Run)", true, "app",
                "Office Click-to-Run: its update service and the scheduled tasks it creates.",
                [$@"{pf}\Common Files\microsoft shared\ClickToRun"],
                [new("realtime", Rule: "*", Image: $@"{pf}\Common Files\microsoft shared\ClickToRun\*"),
                 new("realtime", Rule: "Scheduled task created from command line", Parent: $@"{pf}\Common Files\microsoft shared\ClickToRun\*", Ancestors: 1)]),
            new("google-drive", "Google Drive", true, "app",
                "Google Drive for desktop (any version): its start-up entry and everything it runs from its install folder.",
                [$@"{pf}\Google\Drive File Stream"],
                [new("realtime", Rule: "*", Image: $@"{pf}\Google\Drive File Stream\*")]),
            new("razer", "Razer (Synapse / Cortex / App Engine)", true, "app",
                "Razer software from its install folders (start-up entries, updates).",
                [$@"{pf}\Razer", $@"{pf86}\Razer"],
                [new("realtime", Rule: "*", Image: $@"{pf}\Razer\*"), new("realtime", Rule: "*", Image: $@"{pf86}\Razer\*")]),
            new("installers", "Software installers (one-time RunOnce entries)", false, "system",
                "Installers (Visual C++, .NET, Python, ...) add a one-time \"RunOnce\" start-up entry to finish setup. Off by default: malware can use RunOnce too.",
                [],
                [new("realtime", Rule: "Startup entry added or changed (Run key)", Detail: @"*\CurrentVersion\RunOnce\*")]),
        ];
    }

    public static bool IsInstalled(AllowProfile p) => p.Detect.Length == 0 || p.Detect.Any(PathGlob.Exists);

    public static AllowProfile? FindFor(Rec e, Func<string, bool> isOn, ISignerLookup signers) =>
        All.FirstOrDefault(p => !isOn(p.Id) && p.Entries.Any(en => EntryMatches(en, e, signers)));

    public static bool EntryMatches(ProfileEntry x, Rec e, ISignerLookup signers)
    {
        if (x.List == "realtime" && Ps.Eq(e.S("blade"), "realtime"))
        {
            if (x.Rule.Length > 0 && x.Rule != "*" && x.Rule != e.S("rule")) return false;
            if (x.Image.Length > 0 && !Ps.Like(e.S("process"), x.Image)) return false;
            if (x.Detail.Length > 0)
            {
                if (x.Match == "exact") { if (!string.Equals(e.S("detail").Trim(), x.Detail.Trim(), StringComparison.OrdinalIgnoreCase)) return false; }
                else if (!Ps.Like(e.S("detail"), x.Detail)) return false;
            }
            if (x.Parent.Length > 0)
            {
                var chain = new[] { e.S("parent") }.Concat(e.Strings("ancestors")).Where(c => c.Length > 0).Take(Math.Max(1, x.Ancestors));
                if (!chain.Any(c => Ps.Like(c, x.Parent) && (x.ParentSigner.Length == 0 || Ps.Eq(signers.SignerOf(c), x.ParentSigner)))) return false;
            }
            if (x.Signer.Length > 0 && !Ps.Eq(signers.SignerOf(e.S("process")), x.Signer)) return false;
            return x.Image.Length > 0 || x.Parent.Length > 0 || x.Signer.Length > 0 || x.Detail.Length > 0;
        }
        if (x.List == "sigma" && Ps.Eq(e.S("blade"), "sigma"))
        {
            if (x.Title.Length > 0 && x.Title != "*" && x.Title != e.S("title")) return false;
            var par = SigmaProcess.Of(e).Parent;
            if (x.Parent.Length > 0 && !(Ps.Like(par, x.Parent) && (x.ParentSigner.Length == 0 || Ps.Eq(signers.SignerOf(par), x.ParentSigner)))) return false;
            return x.Parent.Length > 0 || (x.Title.Length > 0 && x.Title != "*");
        }
        return false;
    }

    public static IEnumerable<JsonObject> Ops(AllowProfile p) => p.Entries.Select(e => ToOp(e, p.Id));

    public static JsonObject ToOp(ProfileEntry e, string profile)
    {
        var op = new JsonObject { ["action"] = "exclude", ["blade"] = e.List, ["profile"] = profile };
        if (e.List == "realtime")
        {
            op["rule"] = e.Rule.Length > 0 ? e.Rule : "*";
            op["image"] = e.Image;
            op["parent"] = e.Parent;
            if (e.ParentSigner.Length > 0) op["parentSigner"] = e.ParentSigner;
            if (e.Ancestors > 0) op["ancestors"] = e.Ancestors;
            if (e.Signer.Length > 0) op["signer"] = e.Signer;
            if (e.Detail.Length > 0) op["detail"] = e.Detail;
            if (e.Match.Length > 0) op["match"] = e.Match;
        }
        else
        {
            op["title"] = e.Title;
            op["parent"] = e.Parent;
            op["parentSigner"] = e.ParentSigner;
        }
        return op;
    }
}

public static class PathGlob
{
    public static bool Exists(string pattern) => Expand(pattern).Any();

    public static IEnumerable<string> Expand(string pattern)
    {
        var segs = pattern.Split('\\');
        if (segs.Length == 0) yield break;
        IEnumerable<string> current = [segs[0].EndsWith(':') ? segs[0] + "\\" : segs[0]];
        if (segs[0].Contains('*') || segs[0].Contains('?')) yield break;
        for (var i = 1; i < segs.Length; i++)
        {
            var seg = segs[i];
            if (seg.Length == 0) continue;
            var last = i == segs.Length - 1;
            var next = new List<string>();
            foreach (var dir in current)
            {
                try
                {
                    if (!Directory.Exists(dir)) continue;
                    if (seg.Contains('*') || seg.Contains('?'))
                        next.AddRange(last ? Directory.EnumerateFileSystemEntries(dir, seg) : Directory.EnumerateDirectories(dir, seg));
                    else
                    {
                        var p = Path.Combine(dir, seg);
                        if (last ? File.Exists(p) || Directory.Exists(p) : Directory.Exists(p)) next.Add(p);
                    }
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                if (next.Count > 2000) break;
            }
            current = next;
        }
        foreach (var c in current) yield return c;
    }
}
