using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Edr.Core;

/// <summary>
/// The single validation rules for allows and commands (Test-PatternSpecific / Test-EdrCommandOp): no match-all
/// patterns, no allow of Windows' own publishers, rooted and specific paths. Used by the elevated helper (before a
/// command is written) and by the engine (before it is executed), so the tray's own checks are only advisory.
/// </summary>
public static partial class PatternRules
{
    public static readonly string[] PauseBlades = ["edr", "realtime", "malware", "sigma", "cve", "wail2ban"];
    public static readonly string[] BatchActions = ["unban", "exclude", "unexclude", "block", "unblock"];
    public static readonly string[] AdminActions = ["pause", "resume", "scan-now", "unban", "exclude", "unexclude", "block", "unblock", "batch", "restart-engine", "set-config", "restore-defaults", "update-tool"];
    public static readonly string[] InboxActions = ["resume", "scan-now"];
    /// <summary>Verbs FreeEDR's own elevated programs send to the engine; never accepted in a payload to the helper
    /// (not in <see cref="AdminActions"/>). "note": an event the engine writes for them, so it stays the only writer of
    /// data\events.jsonl.</summary>
    public static readonly string[] EngineOnlyActions = ["note"];
    public static readonly string[] NoteSeverities = ["Info", "Medium", "High"];
    public static readonly string[] NoteKinds = ["status", "health", "tool-update"];
    public static readonly string[] ToolNames = ["Hayabusa", "YARA", "OSV-Scanner", "Velociraptor"];
    public const int MaxBatch = 100;
    public const int MaxPayload = 65_536;

    public static bool IsUnsafeSigner(string? s) => Catalog.UnsafeSigners.Any(u => Ps.Eq(u, s));

    public static bool IsSpecific(string? pattern, string kind, string? signer = null)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return false;
        var pat = pattern.Trim();
        if (pat.Length > 2048) return false;
        var k = kind.ToLowerInvariant();
        if (k == "threat") return DigitsRx().IsMatch(pat);

        var stripped = StripRx().Replace(pat, "");
        var safeSigner = !string.IsNullOrEmpty(signer) && !IsUnsafeSigner(signer);
        if (stripped.Length == 0) return k == "parent" && safeSigner;

        switch (k)
        {
            case "detail":
                return stripped.Length >= 3;
            case "cfa" or "defender-cfa":
            {
                if (pat.Contains('*') || pat.Contains('?')) return false;
                var ex = Environment.ExpandEnvironmentVariables(pat);
                return IsRooted(ex) && !IsDriveRoot(ex) && Segments(ex).Any();
            }
            case "asr" or "defender-asr" or "defender":
            {
                var ex = Environment.ExpandEnvironmentVariables(pat);
                if (!IsRooted(ex) || IsDriveRoot(ex)) return false;
                return Segments(ex).Any(s => s.Replace("*", "").Replace("?", "").Length >= 2);
            }
            case "image" or "parent":
            {
                if (k == "parent" && safeSigner) return true;
                foreach (var s in pat.Split('\\', '/'))
                    if (ExeSegmentRx().IsMatch(s)) return true;
                var ex = Environment.ExpandEnvironmentVariables(pat);
                if (IsRooted(ex))
                {
                    if (IsDriveRoot(ex)) return false;
                    return Segments(ex).Any(s => s.Replace("*", "").Replace("?", "").Length >= 3);
                }
                return false;
            }
            default:
                return stripped.Length >= 3;
        }
    }

    private static bool IsRooted(string p) => RootedRx().IsMatch(p) || UncRx().IsMatch(p);
    private static bool IsDriveRoot(string p) => DriveRx().IsMatch(p.TrimEnd('\\', '/', '*', '?'));
    private static IEnumerable<string> Segments(string p) => p.Split('\\', '/').Where(s => s.Length > 0 && !DriveRx().IsMatch(s));

    /// <summary>Test-EdrCommandOp: may this one operation be executed? (fields as written by the tray)</summary>
    public static bool IsValidOp(JsonObject? op)
    {
        if (op is null) return false;
        var action = op.Str("action");
        string F(string n) => op.Str(n);
        switch (action)
        {
            case "exclude":
                switch (F("blade"))
                {
                    case "realtime":
                        if (F("image").Length == 0 && F("parent").Length == 0 && F("signer").Length == 0 && F("detail").Length == 0) return false;
                        if (F("match").Length > 0 && F("match") != "exact") return false;
                        if (F("image").Length > 0 && !IsSpecific(F("image"), "image")) return false;
                        if (F("parent").Length > 0 && !IsSpecific(F("parent"), "parent", F("parentSigner"))) return false;
                        if (F("detail").Length > 0 && !IsSpecific(F("detail"), "detail")) return false;
                        if (F("signer").Length > 0 && IsUnsafeSigner(F("signer")) && F("image").Length == 0) return false;
                        if (F("parentSigner").Length > 0 && IsUnsafeSigner(F("parentSigner"))) return false;
                        return true;
                    case "sigma":
                        if (F("title").Length == 0 && F("parent").Length == 0) return false;
                        var anyRule = F("title").Length == 0 || F("title") == "*";
                        if (anyRule && (F("parent").Length == 0 || !IsSpecific(F("parent"), "parent", F("parentSigner")))) return false;
                        if (F("parent").Length > 0 && !IsSpecific(F("parent"), "parent", F("parentSigner"))) return false;
                        if (F("parentSigner").Length > 0 && IsUnsafeSigner(F("parentSigner"))) return false;
                        return true;
                    case "defender":
                    {
                        var path = F("path");
                        if (path.Length == 0) return false;
                        var k = F("kind").Length > 0 ? F("kind") : "asr";
                        return k switch { "threat" => DigitsRx().IsMatch(path), "cfa" => IsSpecific(path, "cfa"), "asr" => IsSpecific(path, "asr"), _ => false };
                    }
                    case "ioc": return Sha256Rx().IsMatch(F("sha256"));
                    case "yara": return F("image").Length > 0 && IsSpecific(F("image"), "image");
                    case "cve": return F("cve").Length is > 0 and < 128 && F("package").Length is > 0 and < 256;
                    case "wail2ban": return Ip.IsValidCidr(F("cidr"));
                    default: return false;
                }
            case "pause": return PauseBlades.Contains(F("blade")) && op.Int("minutes") is >= 0 and <= 525_600;
            case "resume": return PauseBlades.Contains(F("blade"));
            case "scan-now" or "restart-engine" or "restore-defaults": return true;
            case "unban": return Ip.Normalize(F("ip")) is not null;
            case "unexclude" or "unblock": return IdRx().IsMatch(F("id"));
            case "block":
                return F("blade") switch
                {
                    "realtime" or "ioc" or "yara" => F("image").Length > 0 && Path.IsPathRooted(F("image")) && IsSpecific(F("image"), "image"),
                    "sigma" => F("title").Length is > 0 and < 512,
                    "wail2ban" => Ip.Normalize(F("ip")) is not null,
                    _ => false,
                };
            case "set-config": return op["config"] is JsonObject;
            case "update-tool": return ToolNames.Contains(F("name"));
            case "note":
                return F("blade") == "system" && NoteSeverities.Contains(F("severity")) && F("title").Length is > 0 and <= 200
                       && F("process").Length <= 260 && F("detail").Length <= 4000 && NoteKinds.Contains(F("kind"))
                       && F("tool").Length <= 64 && op.All(kv => kv.Key is "action" or "blade" or "severity" or "title" or "process" or "detail" or "kind" or "tool" or "ok" or "user");
            default: return false;
        }
    }

    /// <summary>Validates a whole request as the elevated helper does (batch: 1-100 batchable ops).</summary>
    public static bool IsValidCommand(JsonObject? cmd, out string reason)
    {
        reason = "";
        if (cmd is null || cmd.Str("action").Length == 0) { reason = "no action"; return false; }
        var action = cmd.Str("action");
        if (!AdminActions.Contains(action)) { reason = $"unknown action '{action}'"; return false; }
        if (action == "batch")
        {
            if (cmd["ops"] is not JsonArray ops || ops.Count == 0 || ops.Count > MaxBatch) { reason = "batch needs 1-100 ops"; return false; }
            foreach (var o in ops)
            {
                if (o is not JsonObject op || !BatchActions.Contains(op.Str("action")) || !IsValidOp(op)) { reason = $"invalid batch op {o?.ToJsonString()}"; return false; }
            }
            return true;
        }
        if (!IsValidOp(cmd)) { reason = $"invalid {action} request"; return false; }
        return true;
    }

    /// <summary>claude-code\2.1.309\9078b9c1d466\claude.exe -> claude-code\*\*\claude.exe (survives app updates).</summary>
    public static string VersionlessPattern(string path) =>
        string.Join('\\', path.Split('\\').Select(p => VersionSegRx().IsMatch(p) || HexSegRx().IsMatch(p) || p.StartsWith("app-", StringComparison.OrdinalIgnoreCase) && p.Length > 4 && char.IsDigit(p[4]) ? "*" : EscapeWildcards(p)));

    /// <summary>[WildcardPattern]::Escape: the path matches only itself.</summary>
    public static string EscapeWildcards(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length + 4);
        foreach (var c in s)
        {
            if (c is '*' or '?' or '[' or ']' or '`') sb.Append('`');
            sb.Append(c);
        }
        return sb.ToString();
    }

    public static string UnescapeWildcards(string s) => UnescapeRx().Replace(s, "$1");

    public static bool HasWildcards(string s) => WildcardRx().IsMatch(s);

    [GeneratedRegex(@"^\d+$")] private static partial Regex DigitsRx();
    [GeneratedRegex(@"[\*\?\\/\s\.]")] private static partial Regex StripRx();
    [GeneratedRegex(@"^[^\*\?/\\:]{3,}.*\.exe$", RegexOptions.IgnoreCase)] private static partial Regex ExeSegmentRx();
    [GeneratedRegex(@"^[a-zA-Z]:[\\/]")] private static partial Regex RootedRx();
    [GeneratedRegex(@"^\\\\[^\\]+[\\/][^\\]+")] private static partial Regex UncRx();
    [GeneratedRegex(@"^[a-zA-Z]:$")] private static partial Regex DriveRx();
    [GeneratedRegex(@"^[0-9a-fA-F]{64}$")] private static partial Regex Sha256Rx();
    [GeneratedRegex(@"^[A-Za-z0-9\-]{1,64}$")] private static partial Regex IdRx();
    [GeneratedRegex(@"^v?\d+(\.\d+)+$")] private static partial Regex VersionSegRx();
    [GeneratedRegex(@"^[0-9a-fA-F]{8,}$")] private static partial Regex HexSegRx();
    [GeneratedRegex(@"`(.)")] private static partial Regex UnescapeRx();
    [GeneratedRegex(@"(?<!`)[*?\[]")] private static partial Regex WildcardRx();
}
