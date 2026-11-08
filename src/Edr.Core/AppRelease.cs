using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Edr.Core;

public static partial class AppVersion
{
    public static Version? Parse(string? text)
    {
        var m = LeadingRx().Match(text ?? "");
        if (!m.Success || !Version.TryParse(m.Groups[1].Value, out var v)) return null;
        return new Version(v.Major, v.Minor, Math.Max(0, v.Build), Math.Max(0, v.Revision));
    }

    public static bool IsDev(string? text) => (text ?? "").Contains("dev", StringComparison.OrdinalIgnoreCase) || Parse(text) is { Major: 0 };

    public static bool IsDowngrade(string? installed, string? incoming) =>
        Parse(installed) is { } i && Parse(incoming) is { } n && n < i;

    public static bool IsValidRelease(string? text) =>
        ReleaseRx().IsMatch(text ?? "") && Parse(text) is { } v && v.Major >= 2026 && new[] { v.Major, v.Minor, v.Build, v.Revision }.All(c => c is >= 0 and <= 65535);

    public static string LocalNumber(DateTime utc) => $"0.{utc.Year % 100 * 100 + utc.Month}.{utc.Day * 100 + utc.Hour}.{utc.Minute}";

    [GeneratedRegex(@"^\s*v?(\d+\.\d+(?:\.\d+){0,2})")]
    private static partial Regex LeadingRx();

    [GeneratedRegex(@"^\d{4}\.\d{1,2}\.\d{1,2}(\.\d{1,5})?$")]
    private static partial Regex ReleaseRx();
}

public static class Changelog
{
    public const string Unreleased = "Unreleased";
    public const string UserHeading = "What's new for you";
    public const string TechHeading = "Technical";

    public static string? Section(string text, string heading)
    {
        var lines = text.Replace("\r\n", "\n").Split('\n');
        var start = Array.FindIndex(lines, l => IsVersionHeading(l) && Title(l) is { } t && (Ps.Eq(t, heading) || Ps.Eq(t.Split(' ')[0], heading)));
        if (start < 0) return null;
        var end = Array.FindIndex(lines, start + 1, IsVersionHeading);
        return string.Join("\n", lines[(start + 1)..(end < 0 ? lines.Length : end)]).Trim();
    }

    public static string? ForVersion(string text, string? version)
    {
        if (AppVersion.Parse(version) is not { } want) return null;
        foreach (var l in text.Replace("\r\n", "\n").Split('\n').Where(IsVersionHeading))
            if (Title(l) is { } t && AppVersion.Parse(t) is { } v && Same(v, want)) return Section(text, t);
        return null;
    }

    public static string UserPart(string? section)
    {
        if (string.IsNullOrWhiteSpace(section)) return "";
        var lines = section.Replace("\r\n", "\n").Split('\n');
        var i = Array.FindIndex(lines, l => l.TrimStart().StartsWith("###") && l.Contains(UserHeading, StringComparison.OrdinalIgnoreCase));
        if (i < 0) return Plain(string.Join("\n", lines[..EndOfNotes(lines, 0)]));
        return Plain(string.Join("\n", lines[(i + 1)..EndOfNotes(lines, i + 1)]));
    }

    public static string Part(string? section, string heading)
    {
        if (string.IsNullOrWhiteSpace(section)) return "";
        var lines = section.Replace("\r\n", "\n").Split('\n');
        var i = Array.FindIndex(lines, l => IsPartHeading(l, heading));
        return i < 0 ? "" : string.Join("\n", lines[(i + 1)..EndOfNotes(lines, i + 1)]).Trim();
    }

    public static bool HasEntries(string? section) =>
        (section ?? "").Replace("\r\n", "\n").Split('\n').Any(l => l.TrimStart().StartsWith("- ") || l.TrimStart().StartsWith("* "));

    public static string ReleaseBody(string section)
    {
        var user = Part(section, UserHeading);
        var tech = Part(section, TechHeading);
        var sb = new StringBuilder($"### {UserHeading}\n\n{(user.Length > 0 ? user : "- Maintenance release.")}\n");
        if (tech.Length > 0) sb.Append($"\n<details><summary>Technical changes (for developers)</summary>\n\n### {TechHeading}\n\n{tech}\n\n</details>\n");
        return sb.ToString();
    }

    public static string ReleasedPart(string text)
    {
        var lines = text.Replace("\r\n", "\n").Split('\n');
        var u = Array.FindIndex(lines, l => IsVersionHeading(l) && Ps.Eq(Title(l), Unreleased));
        var first = Array.FindIndex(lines, u < 0 ? 0 : u + 1, IsVersionHeading);
        return first < 0 ? "" : string.Join("\n", lines[first..]).Trim();
    }

    public static bool ReleasedKept(string atTag, string now)
    {
        static string Norm(string s) => s.Replace("\r\n", "\n").TrimEnd();
        var before = Norm(ReleasedPart(atTag));
        return before.Length == 0 || Norm(ReleasedPart(now)).EndsWith(before, StringComparison.Ordinal);
    }

    public static List<string> Problems(string text)
    {
        var errors = new List<string>();
        var unreleased = Section(text, Unreleased);
        if (unreleased is null) { errors.Add($"no \"## {Unreleased}\" section"); return errors; }
        var lines = unreleased.Replace("\r\n", "\n").Split('\n');
        foreach (var h in new[] { UserHeading, TechHeading })
            if (!lines.Any(l => IsPartHeading(l, h))) errors.Add($"\"## {Unreleased}\" has no \"### {h}\" heading");
        foreach (var l in lines.Where(l => l.TrimStart().StartsWith('#') && !IsPartHeading(l, UserHeading) && !IsPartHeading(l, TechHeading)))
            errors.Add($"\"## {Unreleased}\" has a heading other than \"### {UserHeading}\" and \"### {TechHeading}\": {l.Trim()}");
        var stray = lines.TakeWhile(l => !l.TrimStart().StartsWith('#')).FirstOrDefault(l => l.TrimStart().StartsWith("- ") || l.TrimStart().StartsWith("* "));
        if (stray is not null) errors.Add($"\"## {Unreleased}\" has an entry outside the two headings: {stray.Trim()}");
        if (HasEntries(Part(unreleased, UserHeading)) && !HasEntries(Part(unreleased, TechHeading)))
            errors.Add($"\"## {Unreleased}\" has a \"{UserHeading}\" entry but no \"{TechHeading}\" entry: add the technical line too");
        return errors;
    }

    public static List<(Version Version, string Notes)> UserPartsBetween(string text, Version? after, Version upTo)
    {
        var list = new List<(Version Version, string Notes)>();
        foreach (var l in text.Replace("\r\n", "\n").Split('\n').Where(IsVersionHeading))
        {
            if (Title(l) is not { } t || Ps.Eq(t, Unreleased) || AppVersion.Parse(t) is not { } v) continue;
            if (v > upTo || (after is not null ? v <= after : !Same(v, upTo))) continue;
            var notes = UserPart(Section(text, t));
            if (notes.Length > 0) list.Add((v, notes));
        }
        return [.. list.OrderByDescending(x => x.Version)];
    }

    public static string Combine(IReadOnlyList<(Version Version, string Notes)> parts) =>
        parts.Count switch
        {
            0 => "",
            1 => parts[0].Notes,
            _ => string.Join("\n\n", parts.Select(p => $"FreeEDR {Short(p.Version)}:\n{p.Notes}")),
        };

    public static bool IsCombined(string? notes) => (notes ?? "").StartsWith("FreeEDR ", StringComparison.Ordinal) && (notes ?? "").Split('\n')[0].TrimEnd().EndsWith(':');

    public static string Short(Version v) => v.Revision > 0 ? v.ToString(4) : v.ToString(3);

    public static (string Text, string Notes) Promote(string text, string version, string date)
    {
        if (!AppVersion.IsValidRelease(version)) throw new InvalidDataException($"not a release version: {version}");
        var nl = text.Contains("\r\n") ? "\r\n" : "\n";
        var lines = text.Replace("\r\n", "\n").Split('\n').ToList();
        if (ForVersion(text, version) is { } existing)
        {
            if (HasEntries(Section(text, Unreleased))) throw new InvalidDataException($"{version} is already in the changelog and Unreleased has new entries: use a new version");
            return (text, existing);
        }
        var u = lines.FindIndex(l => IsVersionHeading(l) && Ps.Eq(Title(l), Unreleased));
        if (u < 0) throw new InvalidDataException("the changelog has no \"## Unreleased\" section");
        var body = Section(text, Unreleased) ?? "";
        if (!HasEntries(body)) throw new InvalidDataException("\"## Unreleased\" has no entries: nothing to release");
        var end = lines.FindIndex(u + 1, IsVersionHeading);
        if (end < 0) end = lines.Count;
        var fresh = new List<string> { $"## {Unreleased}", "", $"### {UserHeading}", "", $"### {TechHeading}", "", $"## {version} - {date}", "" };
        fresh.AddRange(body.Split('\n'));
        fresh.Add("");
        lines.RemoveRange(u, end - u);
        lines.InsertRange(u, fresh);
        return (string.Join(nl, lines), body);
    }

    private static int EndOfNotes(string[] lines, int from)
    {
        var end = Array.FindIndex(lines, from, l => l.TrimStart().StartsWith("##") || l.TrimStart().StartsWith("<details", StringComparison.OrdinalIgnoreCase) || l.Trim() == "---");
        return end < 0 ? lines.Length : end;
    }

    private static bool IsPartHeading(string l, string heading) => l.TrimStart().StartsWith("### ") && Ps.Eq(l.Trim()[4..].Trim(), heading);

    private static bool Same(Version a, Version b) => a.Major == b.Major && a.Minor == b.Minor && a.Build == b.Build && Math.Max(0, a.Revision) == Math.Max(0, b.Revision);

    private static bool IsVersionHeading(string l) => l.StartsWith("## ", StringComparison.Ordinal);

    private static string? Title(string l) => l.Length > 3 ? l[3..].Trim() : null;

    private static string Plain(string s) => string.Join("\n", s.Replace("\r\n", "\n").Split('\n')
        .Where(l => !l.TrimStart().StartsWith('#'))
        .Select(l => l.TrimEnd().Replace("**", "").Replace("`", "")))
        .Trim();
}

public sealed record AppUpdateInfo(string Tag, Version Latest, string PageUrl, string AssetUrl, string Sha256, long Size, string Notes, DateTime? Published,
                                   string Asset = AppRelease.SetupAsset);

public sealed partial class AppRelease(EdrPaths paths, Func<string, string?>? signerOf = null)
{
    public const string Repo = "alonreich/FreeEDR";
    public const string SetupAsset = "FreeEDR-Setup.exe";
    public const string UpdateAsset = "FreeEDR-Update.exe";
    public const long MaxSetupBytes = 400L * 1024 * 1024;
    private static readonly TimeSpan Stall = TimeSpan.FromSeconds(60);

    // Publisher identities (normalized subject, see NormalizeSubject) that may sign a FreeEDR update in addition to the
    // installed copy's own signer. To move to a new certificate subject: add it here in a release signed by the old
    // certificate, publish that release, then sign later releases with the new certificate.
    public static readonly string[] TrustedSuccessorSubjects = [];

    private readonly Func<string, string?> _signerOf = signerOf ?? (f => new Native.AuthenticodeSigners().SubjectOf(f));

    public string UpdateDir => Path.Combine(paths.LocalDir, "update");

    public string InstalledText()
    {
        try { return File.Exists(paths.VersionFile) ? File.ReadAllText(paths.VersionFile).Trim() : ""; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return ""; }
    }

    public static AppUpdateInfo? Parse(JsonObject? release, bool preferUpdate = false)
    {
        if (release is null || release.Truthy("draft") || release.Truthy("prerelease")) return null;
        var tag = release.Str("tag_name");
        if (!AppVersion.IsValidRelease(tag.TrimStart('v')) || AppVersion.Parse(tag) is not { } v) return null;
        var found = new Dictionary<string, (string Url, string Sha, long Size)>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in release.Objects("assets"))
        {
            var name = a.Str("name");
            if (!Ps.Eq(name, SetupAsset) && !Ps.Eq(name, UpdateAsset)) continue;
            var d = a.Str("digest");
            if (!d.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) || d.Length != 71) return null;
            var url = a.Str("browser_download_url");
            if (!url.StartsWith($"https://github.com/{Repo}/releases/download/", StringComparison.OrdinalIgnoreCase)) return null;
            long size = 0;
            if (a["size"] is JsonValue sv && sv.TryGetValue<long>(out var s)) size = s;
            if (size <= 0 || size > MaxSetupBytes) return null;
            found[name] = (url, d[7..].ToUpperInvariant(), size);
        }
        var pick = preferUpdate && found.ContainsKey(UpdateAsset) ? UpdateAsset : found.ContainsKey(SetupAsset) ? SetupAsset : null;
        if (pick is null) return null;
        var (assetUrl, sha, bytes) = found[pick];
        return new AppUpdateInfo(tag, v, release.Str("html_url").Length > 0 ? release.Str("html_url") : $"https://github.com/{Repo}/releases/tag/{tag}",
            assetUrl, sha, bytes, Changelog.UserPart(release.Str("body")), Ps.ToDate(release.Str("published_at")), pick);
    }

    public static bool IsNewer(AppUpdateInfo info, string installedText) =>
        AppVersion.Parse(installedText) is not { } cur || info.Latest > cur;

    public static string NotesSince(JsonArray? releases, Version? installed, AppUpdateInfo latest)
    {
        var parts = new List<(Version Version, string Notes)>();
        foreach (var r in releases?.OfType<JsonObject>() ?? [])
        {
            if (r.Truthy("draft") || r.Truthy("prerelease")) continue;
            var tag = r.Str("tag_name");
            if (!AppVersion.IsValidRelease(tag.TrimStart('v')) || AppVersion.Parse(tag) is not { } v) continue;
            if (v > latest.Latest || (installed is not null && v <= installed) || parts.Any(p => p.Version == v)) continue;
            var notes = Changelog.UserPart(r.Str("body"));
            if (notes.Length > 0) parts.Add((v, notes));
        }
        if (!parts.Any(p => p.Version == latest.Latest) && latest.Notes.Length > 0) parts.Add((latest.Latest, latest.Notes));
        return Changelog.Combine([.. parts.OrderByDescending(p => p.Version)]);
    }

    public async Task<(AppUpdateInfo? Info, string Message, bool Reached)> Check(CancellationToken ct = default, bool reinstall = false)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(45));
            using var resp = await Get($"https://api.github.com/repos/{Repo}/releases/latest", cts.Token);
            if (resp.StatusCode == HttpStatusCode.NotFound)
                return (null, "No FreeEDR release is published on GitHub yet (or the FreeEDR repository is not public). FreeEDR checks again later.", true);
            if (!resp.IsSuccessStatusCode) return (null, $"GitHub answered {(int)resp.StatusCode}; FreeEDR tries again later.", false);
            var info = Parse(JsonFile.Parse(await resp.Content.ReadAsStringAsync(cts.Token)) as JsonObject, preferUpdate: true);
            if (info is null) return (null, "The latest release has no complete, checkable FreeEDR installer yet (it may still be publishing); FreeEDR tries again later.", false);
            var installed = InstalledText();
            if (!IsNewer(info, installed))
            {
                if (reinstall && AppVersion.Parse(installed) is { } cur && cur == info.Latest)
                    return (info, $"FreeEDR {info.Latest} can be installed again to finish the update that did not complete.", true);
                return (null, $"FreeEDR {installed} is up to date (latest release: {info.Latest}).", true);
            }
            try
            {
                using var list = await Get($"https://api.github.com/repos/{Repo}/releases?per_page=30", cts.Token);
                if (list.IsSuccessStatusCode)
                    info = info with { Notes = NotesSince(JsonFile.Parse(await list.Content.ReadAsStringAsync(cts.Token)) as JsonArray, AppVersion.Parse(installed), info) };
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException) { }
            return (info, $"FreeEDR {info.Latest} is available (you have {(installed.Length > 0 ? installed : "an unknown version")}).", true);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
        {
            return (null, ct.IsCancellationRequested ? "Check cancelled." : "GitHub could not be reached (offline, or a proxy blocks it). FreeEDR tries again later.", false);
        }
    }

    private static async Task<HttpResponseMessage> Get(string url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return await Tools.Http.SendAsync(req, ct);
    }

    public string SetupPath(AppUpdateInfo info) => Path.Combine(UpdateDir, $"{Path.GetFileNameWithoutExtension(info.Asset)}-{info.Latest}.exe");

    public static int PurgeDownloads(string dir, Version? installed, string? keep = null)
    {
        var n = 0;
        try
        {
            if (!Directory.Exists(dir)) return 0;
            foreach (var f in Directory.GetFiles(dir, "FreeEDR-*"))
            {
                if (keep is not null && (Ps.Eq(f, keep) || Ps.Eq(f, keep + ".part"))) continue;
                var m = DownloadRx().Match(Path.GetFileName(f));
                if (!m.Success) continue;
                if (installed is not null && AppVersion.Parse(m.Groups[1].Value) is { } v && v > installed) continue;
                if (installed is null && keep is null) continue;
                try { File.Delete(f); n++; } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return n;
    }

    public int PurgeInstalled() => PurgeDownloads(UpdateDir, AppVersion.Parse(InstalledText()));

    [GeneratedRegex(@"^FreeEDR-(?:Setup|Update)-(\d+\.\d+\.\d+\.\d+)\.exe(?:\.part)?$", RegexOptions.IgnoreCase)]
    private static partial Regex DownloadRx();

    public async Task<string> Download(AppUpdateInfo info, IProgress<(long Done, long Total)>? progress, CancellationToken ct)
    {
        Directory.CreateDirectory(UpdateDir);
        var final = SetupPath(info);
        PurgeDownloads(UpdateDir, null, keep: final);
        if (File.Exists(final) && Ps.Eq(Tools.Sha256Of(final), info.Sha256)) { progress?.Report((info.Size, info.Size)); return final; }
        JsonFile.TryDelete(final);
        var part = final + ".part";
        var have = File.Exists(part) ? new FileInfo(part).Length : 0;
        if (have > info.Size) { JsonFile.TryDelete(part); have = 0; }
        var free = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(UpdateDir))!).AvailableFreeSpace;
        if (free < info.Size - have + 200L * 1024 * 1024)
            throw new IOException($"Not enough free disk space: the update needs {(info.Size - have) / 1048576 + 200} MB, {free / 1048576} MB are free.");

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                have = await Fetch(info, part, have, progress, ct);
                break;
            }
            catch (Exception e) when (attempt < 3 && !ct.IsCancellationRequested && e is HttpRequestException or IOException or TaskCanceledException)
            {
                have = File.Exists(part) ? new FileInfo(part).Length : 0;
                await Task.Delay(TimeSpan.FromSeconds(5 * attempt), ct);
            }
        }
        if (have != info.Size || !Ps.Eq(Tools.Sha256Of(part), info.Sha256))
        {
            JsonFile.TryDelete(part);
            throw new InvalidDataException("The download does not match the SHA256 fingerprint GitHub publishes for this release; it was deleted. Try again.");
        }
        File.Move(part, final, true);
        return final;
    }

    private static async Task<long> Fetch(AppUpdateInfo info, string part, long have, IProgress<(long, long)>? progress, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, info.AssetUrl);
        if (have > 0) req.Headers.Range = new RangeHeaderValue(have, null);
        using var headers = CancellationTokenSource.CreateLinkedTokenSource(ct);
        headers.CancelAfter(TimeSpan.FromSeconds(60));
        using var resp = await Tools.Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, headers.Token);
        resp.EnsureSuccessStatusCode();
        var append = have > 0 && resp.StatusCode == HttpStatusCode.PartialContent;
        if (!append) have = 0;
        await using var src = await resp.Content.ReadAsStreamAsync(ct);
        await using var dst = new FileStream(part, append ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.None);
        var buf = new byte[81920];
        while (true)
        {
            using var stall = CancellationTokenSource.CreateLinkedTokenSource(ct);
            stall.CancelAfter(Stall);
            var n = await src.ReadAsync(buf, stall.Token);
            if (n == 0) break;
            have += n;
            if (have > info.Size) throw new InvalidDataException("The download is larger than the release says.");
            await dst.WriteAsync(buf.AsMemory(0, n), ct);
            progress?.Report((have, info.Size));
        }
        return have;
    }

    public (bool Ok, string Message, FileStream? Lock) Verify(AppUpdateInfo info, string setup)
    {
        FileStream? fs = null;
        try
        {
            fs = new FileStream(setup, FileMode.Open, FileAccess.Read, FileShare.Read);
            var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
            if (!Ps.Eq(sha, info.Sha256)) { fs.Dispose(); return (false, "The downloaded file changed after it was checked; it is not started.", null); }
            var expected = _signerOf(paths.EnginePath);
            var signer = _signerOf(setup);
            var (ok, msg) = SignerVerdict(expected, signer);
            if (!ok) { fs.Dispose(); return (false, msg, null); }
            return (true, msg, fs);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            fs?.Dispose();
            return (false, $"The downloaded file could not be checked: {e.Message}", null);
        }
    }

    public static string NormalizeSubject(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject)) return "";
        if (!subject.Contains('=')) return subject.Trim();
        var keep = new[] { "CN", "O", "L", "S", "ST", "C" };
        var parts = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in subject.Replace("\r\n", "\n").Split('\n'))
        {
            var i = raw.IndexOf('=');
            if (i <= 0) continue;
            var key = raw[..i].Trim().ToUpperInvariant();
            if (key == "ST") key = "S";
            if (!keep.Contains(key)) continue;
            var value = raw[(i + 1)..].Trim().Trim('"').Trim();
            if (value.Length > 0) parts[key] = value;
        }
        return parts.Count == 0 ? subject.Trim() : string.Join(", ", parts.Select(p => $"{p.Key}={p.Value}"));
    }

    public static string DisplayName(string? subject)
    {
        var n = NormalizeSubject(subject);
        var cn = n.Split(", ").FirstOrDefault(p => p.StartsWith("CN=", StringComparison.Ordinal));
        return cn is not null ? cn[3..] : n;
    }

    public static (bool Ok, string Message) SignerVerdict(string? installedSigner, string? downloadSigner, IEnumerable<string>? successors = null)
    {
        var have = NormalizeSubject(installedSigner);
        var got = NormalizeSubject(downloadSigner);
        if (have.Length > 0)
        {
            var allowed = (successors ?? TrustedSuccessorSubjects).Select(NormalizeSubject).Append(have);
            if (got.Length > 0 && allowed.Any(a => string.Equals(a, got, StringComparison.OrdinalIgnoreCase)))
                return (true, $"Digitally signed by {DisplayName(got)}, the same publisher as the installed FreeEDR.");
            return (false, got.Length == 0
                ? $"The download is not digitally signed, but your FreeEDR is signed by {DisplayName(have)}: it is not started."
                : $"The download is signed by '{got}', not by {have} like your FreeEDR: it is not started.");
        }
        return got.Length > 0
            ? (true, $"Digitally signed by {DisplayName(got)}; its SHA256 fingerprint matches GitHub's.")
            : (true, "Not digitally signed (like the installed FreeEDR); its SHA256 fingerprint matches the one GitHub publishes for this release.");
    }

    public static string Describe(long bytes) => bytes >= 1048576 ? $"{bytes / 1048576.0:0.0} MB" : $"{Math.Max(1, bytes / 1024)} KB";

    public string? InstalledNotes() => NotesSinceInstalled(null);

    public string? NotesSinceInstalled(Version? since)
    {
        var file = Path.Combine(paths.DocsDir, "CHANGELOG.md");
        try
        {
            if (!File.Exists(file) || AppVersion.Parse(InstalledText()) is not { } now) return null;
            return Changelog.Combine(Changelog.UserPartsBetween(File.ReadAllText(file, Encoding.UTF8), since, now));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    public JsonObject? PendingUpgrade()
    {
        var marker = JsonFile.ReadObject(paths.UpgradePendingFile);
        if (marker is null) return null;
        try
        {
            using var p = Process.GetProcessById((int)marker.Int("pid"));
            if (Ps.Eq(p.ProcessName, Path.GetFileNameWithoutExtension(EdrPaths.InstallerExe))) return null;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
        return marker;
    }
}
