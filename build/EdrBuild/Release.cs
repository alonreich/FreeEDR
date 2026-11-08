using System.Diagnostics;
using System.Text;
using Edr.Core;

namespace EdrBuild;

internal sealed record BuildVersion(string Numeric, string Text, string Informational, string Commit, bool Tagged);

internal static class Release
{
    public const string ChangelogPath = @"docs\CHANGELOG.md";
    private static readonly string[] CodeDirs = ["src", "build", "config", "rules"];

    public static (int Exit, string Output) Git(string root, params string[] args)
    {
        var psi = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = new UTF8Encoding(false), UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEndAsync();
            _ = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(60_000)) { try { p.Kill(true); } catch (InvalidOperationException) { } return (-1, ""); }
            return (p.ExitCode, o.Result.Trim());
        }
        catch (System.ComponentModel.Win32Exception) { return (-1, ""); }
    }

    public static BuildVersion Compute(string root, bool dev, DateTime utcNow, BuildLog log)
    {
        var (rc, sha) = Git(root, "rev-parse", "--short=12", "HEAD");
        var commit = rc == 0 && sha.Length > 0 ? sha : "nogit";
        var dirty = rc == 0 && Git(root, "status", "--porcelain", "--untracked-files=no").Output.Length > 0;
        var source = commit + (dirty ? ".dirty" : "");
        if (dev)
        {
            var v = AppVersion.LocalNumber(utcNow);
            return new(v, $"{v} (dev build {source})", $"{v}-dev+{source}", source, false);
        }
        string? version = null;
        var env = Environment.GetEnvironmentVariable("EDR_VERSION")?.Trim().TrimStart('v');
        if (!string.IsNullOrEmpty(env))
        {
            if (!AppVersion.IsValidRelease(env)) throw new InvalidDataException($"EDR_VERSION '{env}' is not a release version (YYYY.M.D or YYYY.M.D.N, each part 0-65535)");
            version = env;
        }
        var (trc, tag) = Git(root, "describe", "--tags", "--exact-match", "HEAD");
        var tagged = trc == 0 && AppVersion.IsValidRelease(tag.TrimStart('v'));
        if (version is null && tagged) version = tag.TrimStart('v');
        if (dirty) log.Warn("[Version] the working tree has uncommitted changes: this build cannot be traced to one commit");
        if (version is null)
        {
            var local = AppVersion.LocalNumber(utcNow);
            log.Warn($"[Version] HEAD is not a release tag and EDR_VERSION is not set: local release build {local} (UTC). It ranks below every published release, so published updates are still offered over it. Published releases come from the release workflow.");
            return new(local, $"{local} (local release build {source})", $"{local}-local+{source}", source, false);
        }
        var numeric = AppVersion.Parse(version)!.ToString(4);
        return new(numeric, version, $"{version}+{source}", source, tagged || env is { Length: > 0 });
    }

    public static bool ChangelogGate(string root, BuildVersion v, bool dev, BuildLog log)
    {
        var file = Path.Combine(root, ChangelogPath);
        if (!File.Exists(file)) { log.Error($"{ChangelogPath} is missing (every code change records what it changes there)"); return false; }
        string text;
        try { text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(File.ReadAllBytes(file)); }
        catch (DecoderFallbackException) { log.Error($"{ChangelogPath}: not valid UTF-8"); return false; }
        var problems = Changelog.Problems(text);
        foreach (var p in problems) log.Error($"{ChangelogPath}: {p}");
        if (problems.Count > 0) return false;
        var unreleased = Changelog.Section(text, Changelog.Unreleased)!;
        if (!dev && v.Tagged)
        {
            var section = Changelog.ForVersion(text, v.Text);
            if (!Changelog.HasEntries(section) || Changelog.UserPart(section).Length == 0)
            {
                log.Error($"{ChangelogPath} has no \"## {v.Text}\" section with \"{Changelog.UserHeading}\" entries: run the release workflow (it promotes Unreleased)");
                return false;
            }
        }
        var (rc, last) = Git(root, "describe", "--tags", "--abbrev=0", "--match", "v*");
        if (rc == 0 && last.Length > 0)
        {
            var args = new List<string> { "diff", "--quiet", last, "--" };
            args.AddRange(CodeDirs);
            var changed = Git(root, [.. args]).Exit == 1;
            if (changed && !Changelog.HasEntries(unreleased) && !(v.Tagged && Changelog.HasEntries(Changelog.ForVersion(text, v.Text))))
            {
                log.Error($"code changed since {last} but \"## {Changelog.Unreleased}\" in {ChangelogPath} has no entries: add a technical line and a plain-English line for users");
                return false;
            }
            var (src, then) = Git(root, "show", $"{last}:{ChangelogPath.Replace('\\', '/')}");
            if (src == 0 && !Changelog.ReleasedKept(then, text))
            {
                log.Error($"{ChangelogPath}: a released section changed since {last}. Released sections are never edited: put the correction in a new \"## {Changelog.Unreleased}\" entry");
                return false;
            }
        }
        if (!EntryFollowsCode(root, dev, log)) return false;
        log.Success($"[Changelog] {ChangelogPath}: {(Changelog.HasEntries(unreleased) ? "Unreleased has entries" : "Unreleased is empty")}{(rc == 0 ? $", last release tag {last}" : ", no release tag yet")}");
        return true;
    }

    private static bool EntryFollowsCode(string root, bool dev, BuildLog log)
    {
        var codeDirty = Git(root, ["status", "--porcelain", "--", .. CodeDirs]);
        var logDirty = Git(root, "status", "--porcelain", "--", ChangelogPath.Replace('\\', '/'));
        if (codeDirty.Exit != 0 || logDirty.Exit != 0) { log.Warn("[Changelog] git is not available: the \"entry for every code change\" check was skipped"); return true; }
        if (logDirty.Output.Length > 0) return true;
        if (codeDirty.Output.Length > 0)
        {
            var msg = $"code under {string.Join(", ", CodeDirs)} has uncommitted changes but {ChangelogPath} has none: add your \"## {Changelog.Unreleased}\" entry in the same change";
            if (dev) { log.Warn("[Changelog] " + msg); return true; }
            log.Error(msg);
            return false;
        }
        var code = Git(root, ["log", "-1", "--format=%H", "--", .. CodeDirs]).Output;
        var clog = Git(root, "log", "-1", "--format=%H", "--", ChangelogPath.Replace('\\', '/')).Output;
        if (code.Length == 0 || code == clog) return true;
        if (clog.Length == 0 || Git(root, "merge-base", "--is-ancestor", code, clog).Exit == 1)
        {
            log.Error($"commit {code[..Math.Min(12, code.Length)]} changed code after the last edit of {ChangelogPath}: add its \"## {Changelog.Unreleased}\" entry (every code change records itself)");
            return false;
        }
        return true;
    }

    public static int Promote(string root, string version, string notesOut)
    {
        var file = Path.Combine(root, ChangelogPath);
        try
        {
            var text = File.ReadAllText(file, Encoding.UTF8);
            var (updated, notes) = Changelog.Promote(text, version, DateTime.UtcNow.ToString("yyyy-MM-dd"));
            if (updated != text) File.WriteAllText(file, updated, new UTF8Encoding(false));
            var user = Changelog.UserPart(notes);
            if (user.Length == 0) { Console.Error.WriteLine($"ERROR: {version} has no \"{Changelog.UserHeading}\" entries"); return 1; }
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(notesOut))!);
            File.WriteAllText(notesOut, Changelog.ReleaseBody(notes).Trim() + "\n", new UTF8Encoding(false));
            Console.WriteLine($"Changelog: {version} {(updated != text ? "promoted from Unreleased" : "already promoted")}; notes -> {notesOut}");
            return 0;
        }
        catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"ERROR: {e.Message}");
            return 1;
        }
    }
}
