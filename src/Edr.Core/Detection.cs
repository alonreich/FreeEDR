using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Edr.Core;

/// <summary>
/// The engine's allow decisions (Test-RealtimeExcluded, Test-SigmaExcluded, Test-DefenderExcluded) as pure functions,
/// so they are tested without Sysmon. Ancestors are supplied lazily (the process chain is read only when an allow
/// with "ancestors" needs it); signatures through <see cref="ISignerLookup"/>.
/// </summary>
public static class Detection
{
    /// <summary>A parent pattern matches one of the first N ancestors; with parentSigner that file must carry that valid signature.</summary>
    public static bool ParentMatches(JsonObject x, string parent, Func<int, IReadOnlyList<string>>? ancestors, ISignerLookup signers)
    {
        var n = x.Int("ancestors");
        IEnumerable<string> cands = n > 1 && ancestors is not null ? ancestors(n) : [parent];
        foreach (var c in cands)
        {
            if (c.Length == 0 || !Ps.Like(c, x.Str("parent"))) continue;
            if (x.Str("parentSigner").Length > 0 && !Ps.Eq(signers.SignerOf(c), x.Str("parentSigner"))) continue;
            return true;
        }
        return false;
    }

    public static JsonObject? RealtimeExcluded(IEnumerable<JsonObject> realtimePath, IEnumerable<JsonObject> realtime, string rule, string image, string parent,
                                               string detail, Func<int, IReadOnlyList<string>>? ancestors, ISignerLookup signers)
    {
        foreach (var p in realtimePath)
            if (image.Length > 0 && p.Str("prefix").Length > 0 && image.StartsWith(p.Str("prefix"), StringComparison.OrdinalIgnoreCase)) return p;
        foreach (var x in realtime)
        {
            var r = x.Str("rule");
            if (r.Length > 0 && r != "*" && r != rule) continue;
            if (x.Str("image").Length > 0 && !Ps.Like(image, x.Str("image"))) continue;
            if (x.Str("detail").Length > 0)
            {
                if (x.Str("match") == "exact") { if (!string.Equals(detail.Trim(), x.Str("detail").Trim(), StringComparison.OrdinalIgnoreCase)) continue; }
                else if (!Ps.Like(detail, x.Str("detail"))) continue;
            }
            if (x.Str("parent").Length > 0 && !ParentMatches(x, parent, ancestors, signers)) continue;
            if (x.Str("signer").Length > 0 && !Ps.Eq(signers.SignerOf(image), x.Str("signer"))) continue;
            var specific = (x.Str("image").Length > 0 && PatternRules.IsSpecific(x.Str("image"), "image")) ||
                           (x.Str("parent").Length > 0 && PatternRules.IsSpecific(x.Str("parent"), "parent", x.Str("parentSigner"))) ||
                           (x.Str("detail").Length > 0 && PatternRules.IsSpecific(x.Str("detail"), "detail")) ||
                           (x.Str("signer").Length > 0 && !PatternRules.IsUnsafeSigner(x.Str("signer")));
            if (!specific) continue;   // never a blanket "ignore everything"
            return x;
        }
        return null;
    }

    public static JsonObject? SigmaExcluded(IEnumerable<JsonObject> sigma, string title, string parent, ISignerLookup signers)
    {
        foreach (var x in sigma)
        {
            var anyRule = x.Str("title").Length == 0 || x.Str("title") == "*";
            if (!anyRule && x.Str("title") != title) continue;
            if (x.Str("parent").Length > 0 && !ParentMatches(x, parent, null, signers)) continue;
            if (anyRule && (x.Str("parent").Length == 0 || !PatternRules.IsSpecific(x.Str("parent"), "parent", x.Str("parentSigner")))) continue;
            return x;
        }
        return null;
    }

    public static bool DefenderExcluded(IEnumerable<JsonObject> defender, IEnumerable<JsonObject> realtime, string threatId, string path)
    {
        if (threatId.Length > 0 && defender.Any(x => x.Str("kind") == "threat" && x.Str("path") == threatId)) return true;
        var clean = Regex.Replace(path, "^file:_?", "");
        var leaf = Ps.Leaf(clean);
        foreach (var x in realtime)
        {
            var img = x.Str("image");
            if (img.Length == 0) continue;
            if (Ps.Like(clean, img) || (leaf.Length > 0 && (Ps.Like(leaf, img) || Ps.Like("*\\" + leaf, img)))) return true;
        }
        return false;
    }

    /// <summary>"Proc: C:\x.exe ¦ ..." parsing shared with the tray.</summary>
    public static SigmaProcess SigmaProcessOf(string details) => SigmaProcess.FromDetails(details);
}

/// <summary>
/// Identity-based trust for FreeEDR's own processes, which are never reported: FreeEDR's executables live in the
/// admin-only install folder, so their exact path is their identity. A child of the engine / control helper / installer
/// is trusted only when it runs elevated; a child of the (unelevated) tray only when it is one of the few programs the
/// tray starts. Anything that only imitates FreeEDR's names is reported ("near miss").
/// </summary>
public static partial class OwnProcess
{
    public enum Verdict { NotOwn, Own, NearMiss }

    private static readonly string[] ElevatedParents = [EdrPaths.EngineExe, EdrPaths.ControlExe, EdrPaths.InstallerExe];

    public static Verdict Check(IReadOnlyDictionary<string, string> d, string root)
    {
        string F(string k) => d.TryGetValue(k, out var v) ? v ?? "" : "";
        var rootFull = SafeFull(root).TrimEnd('\\');
        var img = F("Image").Length > 0 ? F("Image") : F("SourceImage").Length > 0 ? F("SourceImage") : F("ImageLoaded");
        var cmd = F("CommandLine");
        var parent = F("ParentImage");
        var pCmd = F("ParentCommandLine");

        // 1. FreeEDR's own executables (also the installer writing the tray's Run value)
        if (IsOwnExe(img, rootFull) is not null) return Verdict.Own;

        // 2. A child of FreeEDR's own executables
        var parentExe = IsOwnExe(parent, rootFull);
        if (parentExe is not null)
        {
            if (ElevatedParents.Any(e => Ps.Eq(e, parentExe)) && IsElevated(F("IntegrityLevel"), F("User"))) return Verdict.Own;
            if (Ps.Eq(parentExe, EdrPaths.TrayExe) && IsTrayChild(img)) return Verdict.Own;
        }

        // 3. Imitation: a command line naming FreeEDR's programs that failed the checks above
        if (OwnNameRx().IsMatch(cmd) || OwnNameRx().IsMatch(pCmd)) return Verdict.NearMiss;
        return Verdict.NotOwn;
    }

    /// <summary>The file name when the path is exactly one of FreeEDR's executables under the install folder.</summary>
    public static string? IsOwnExe(string path, string rootFull)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var p = SafeFull(path.Trim('"'));
        if (p.Length == 0) return null;
        string[] names = [EdrPaths.EngineExe, EdrPaths.ControlExe, EdrPaths.InstallerExe];
        foreach (var n in names)
            if (Ps.Eq(p, $@"{rootFull}\bin\{n}") || Ps.Eq(p, $@"{rootFull}\setup-src\bin\{n}")) return n;
        if (Ps.Eq(p, $@"{rootFull}\bin\tray\{EdrPaths.TrayExe}")) return EdrPaths.TrayExe;
        return null;
    }

    public static bool IsElevated(string integrity, string user)
    {
        if (integrity.Length > 0) return integrity is "High" or "System";
        return SystemUserRx().IsMatch(user);
    }

    /// <summary>The programs the tray starts: Explorer (open location), Notepad (logs), winget, terminals for updates,
    /// Python/pip (CVE updates), Defender's command-line scanner, the browser handler.</summary>
    public static bool IsTrayChild(string image)
    {
        if (string.IsNullOrWhiteSpace(image)) return false;
        var leaf = Ps.Leaf(image).ToLowerInvariant();
        var sys = EdrPaths.SystemRoot;
        return leaf switch
        {
            "explorer.exe" => Ps.Eq(image, $@"{sys}\explorer.exe"),
            "notepad.exe" => image.StartsWith(sys + "\\", StringComparison.OrdinalIgnoreCase) || image.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase),
            "winget.exe" => image.Contains(@"\Microsoft.DesktopAppInstaller_", StringComparison.OrdinalIgnoreCase),
            "mpcmdrun.exe" => image.Contains(@"\Windows Defender\", StringComparison.OrdinalIgnoreCase),
            "cmd.exe" or "conhost.exe" => image.StartsWith(sys + "\\", StringComparison.OrdinalIgnoreCase),
            "windowsterminal.exe" or "wt.exe" => image.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    private static string SafeFull(string p)
    {
        try { return Path.IsPathRooted(p) ? Path.GetFullPath(p) : ""; }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return ""; }
    }

    [GeneratedRegex(@"FreeEDR-(Engine|Control|Installer|Tray)\.exe|EDR-(Engine|Scan|Tray|Control)\.ps1", RegexOptions.IgnoreCase)]
    private static partial Regex OwnNameRx();

    [GeneratedRegex(@"^(NT AUTHORITY|AUTORITE NT)\\(SYSTEM|SYST.ME)$|\\SYSTEM$|^SYSTEM$", RegexOptions.IgnoreCase)]
    private static partial Regex SystemUserRx();
}
