using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Edr.Core;

/// <summary>A tool FreeEDR runs, pinned to a version and the SHA256 of its executable.</summary>
public sealed record ToolSpec(string Name, string Repo, string Tag, string AssetPattern, string Exe, string Sha256, string VersionArgs, string VersionLinePattern);

/// <summary>
/// Downloads, verifies and updates the external tools (Hayabusa, YARA, OSV-Scanner, Velociraptor).
/// Install: the pinned version, SHA256 checked. Update (one click in the dashboard): the latest GitHub release, checked
/// against the SHA256 digest GitHub publishes for the asset, swapped in with roll-back when the new copy does not run.
/// </summary>
public sealed partial class Tools(EdrPaths paths, Action<string>? log = null)
{
    public static readonly ToolSpec[] Pinned =
    [
        new("Hayabusa", "Yamato-Security/hayabusa", "v4.3.1", @"-win-x64\.zip$", @"hayabusa\hayabusa.exe", "411CE8749115C85B359ADE15B9824B38650B06274DC816D1D4B9035859C8C573", "help", ""),
        new("YARA", "VirusTotal/yara", "v4.6.0", @"win64\.zip$", "yara64.exe", "6B4897B945F408080645EC06E2D2540F067A57A68D5E5830781CDC1D88FC41E2", "-v", ""),
        new("OSV-Scanner", "google/osv-scanner", "v2.7.0", @"windows_amd64\.exe$", "osv-scanner.exe", "9964ED64EC9A387391EB4CC006AD5C531154821AEF29B793E02C448DE4686438", "--version", ""),
        new("Velociraptor", "Velocidex/velociraptor", "v0.77.3", @"windows-amd64\.exe(\.gz)?$", "velociraptor.exe", "3D20A5A2D272E3EB2BCCAE4A80EBE469FC1A6F63EB4A8F8A586DBAE356437D32", "version", "^version:"),
    ];

    public static ToolSpec? Spec(string name) => Pinned.FirstOrDefault(t => Ps.Eq(t.Name, name));

    private static readonly Lazy<HttpClient> Client = new(() =>
    {
        var h = new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All, UseProxy = true, DefaultProxyCredentials = CredentialCache.DefaultCredentials };
        var c = new HttpClient(h) { Timeout = TimeSpan.FromMinutes(10) };
        c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("FreeEDR", "2"));
        return c;
    });

    public static HttpClient Http => Client.Value;

    private void Log(string s) => log?.Invoke(s);

    public string ExePath(ToolSpec t) => Path.Combine(paths.BinDir, t.Exe);

    /// <summary>Version reported by the installed tool ("4.3.1"), or null.</summary>
    public string? InstalledVersion(ToolSpec t)
    {
        var exe = ExePath(t);
        if (!File.Exists(exe)) return null;
        var (_, output) = RunCapture(exe, t.VersionArgs.Split(' '), Path.GetDirectoryName(exe)!, 30);
        var lines = output.Split('\n');
        var line = t.VersionLinePattern.Length > 0 ? lines.FirstOrDefault(l => Ps.Match(l, t.VersionLinePattern)) : lines.FirstOrDefault(l => l.Trim().Length > 0);
        return VersionOf(line ?? output);
    }

    public static string? VersionOf(string? text)
    {
        var m = VersionRx().Match(text ?? "");
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>The latest GitHub release: tag, page, assets (name, url, sha256 digest when GitHub provides it).</summary>
    public async Task<(string Tag, string Url, List<(string Name, string Url, string? Sha256)> Assets)?> LatestRelease(string repo, string? tag = null, CancellationToken ct = default)
    {
        try
        {
            var api = $"https://api.github.com/repos/{repo}/releases/{(tag is null ? "latest" : "tags/" + tag)}";
            using var resp = await Http.GetAsync(api, ct);
            if (!resp.IsSuccessStatusCode) return null;
            var j = JsonFile.Parse(await resp.Content.ReadAsStringAsync(ct)) as JsonObject;
            if (j is null) return null;
            var assets = j.Objects("assets").Select(a =>
            {
                var d = a.Str("digest");
                return (a.Str("name"), a.Str("browser_download_url"), d.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? d[7..].ToUpperInvariant() : null);
            }).ToList();
            return (j.Str("tag_name"), j.Str("html_url").Length > 0 ? j.Str("html_url") : $"https://github.com/{repo}/releases", assets);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException) { return null; }
    }

    public async Task Download(string url, string file, CancellationToken ct = default)
    {
        using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        await using var fs = File.Create(file);
        await resp.Content.CopyToAsync(fs, ct);
    }

    public static string Sha256Of(string file)
    {
        using var fs = File.OpenRead(file);
        return Convert.ToHexString(SHA256.HashData(fs));
    }

    /// <summary>Installs the pinned version if the tool is missing (or, for Velociraptor, when its hash differs).</summary>
    public async Task<string> EnsurePinned(ToolSpec t, CancellationToken ct = default)
    {
        var target = ExePath(t);
        if (File.Exists(target))
        {
            if (t.Name != "Velociraptor" || Sha256Of(target) == t.Sha256) return $"OK {t.Name} present";
        }
        var rel = await LatestRelease(t.Repo, t.Tag, ct) ?? throw new IOException($"{t.Name} {t.Tag}: GitHub not reachable");
        var asset = rel.Assets.FirstOrDefault(a => Ps.Match(a.Name, t.AssetPattern) && !Ps.Match(a.Name, "live-response|debug|msi"));
        if (asset.Name is null) throw new IOException($"{t.Name} {t.Tag}: no matching release asset");
        await InstallAsset(t, asset.Name, asset.Url, expectedExeSha: t.Sha256, expectedAssetSha: null, ct);
        return $"OK {t.Name} {t.Tag} downloaded and verified";
    }

    /// <summary>
    /// Updates a tool to the latest release. The asset must carry a SHA256 digest from GitHub and must match it; the
    /// new copy must run (version query) or the old one is put back. Returns a one-line result.
    /// </summary>
    public async Task<(bool Ok, string Message)> UpdateToLatest(ToolSpec t, CancellationToken ct = default)
    {
        var rel = await LatestRelease(t.Repo, null, ct);
        if (rel is null) return (false, $"{t.Name}: GitHub is not reachable");
        var asset = rel.Value.Assets.FirstOrDefault(a => Ps.Match(a.Name, t.AssetPattern) && !Ps.Match(a.Name, "live-response|debug|msi"));
        if (asset.Name is null) return (false, $"{t.Name} {rel.Value.Tag}: no matching release asset");
        if (asset.Sha256 is null) return (false, $"{t.Name} {rel.Value.Tag}: GitHub publishes no SHA256 digest for {asset.Name}; not updated");
        var current = InstalledVersion(t);
        if (current is not null && VersionOf(rel.Value.Tag) is { } latest && Version.TryParse(latest, out var lv) && Version.TryParse(current, out var cv) && lv <= cv)
            return (true, $"{t.Name} {current} is already the latest version");

        var target = ExePath(t);
        var backup = target + ".old";
        try
        {
            if (File.Exists(target)) File.Move(target, backup, true);
            await InstallAsset(t, asset.Name, asset.Url, expectedExeSha: null, expectedAssetSha: asset.Sha256, ct);
            if (InstalledVersion(t) is null) throw new IOException("the new version does not run");
            JsonFile.TryDelete(backup);
            return (true, $"{t.Name} updated to {rel.Value.Tag} (SHA256 verified against GitHub's digest)");
        }
        catch (Exception e) when (e is IOException or HttpRequestException or UnauthorizedAccessException or InvalidDataException or TaskCanceledException)
        {
            if (File.Exists(backup)) { JsonFile.TryDelete(target); File.Move(backup, target, true); }
            return (false, $"{t.Name} update failed, kept the installed version: {e.Message}");
        }
    }

    private async Task InstallAsset(ToolSpec t, string assetName, string url, string? expectedExeSha, string? expectedAssetSha, CancellationToken ct)
    {
        Directory.CreateDirectory(paths.DownloadDir);
        var dl = Path.Combine(paths.DownloadDir, Path.GetFileName(assetName));
        var target = ExePath(t);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        try
        {
            Log($"Downloading {t.Name}: {assetName}");
            await Download(url, dl, ct);
            if (expectedAssetSha is not null && Sha256Of(dl) != expectedAssetSha) throw new InvalidDataException($"{t.Name}: download does not match GitHub's SHA256 digest");
            if (dl.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                await using var input = File.OpenRead(dl);
                await using var gz = new GZipStream(input, CompressionMode.Decompress);
                await using var output = File.Create(target);
                await gz.CopyToAsync(output, ct);
            }
            else if (dl.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                var x = Path.Combine(paths.DownloadDir, "x-" + t.Name);
                if (Directory.Exists(x)) Directory.Delete(x, true);
                ZipFile.ExtractToDirectory(dl, x, true);
                if (t.Name == "Hayabusa")
                {
                    CopyTree(x, paths.HayabusaDir);
                    var exe = Directory.GetFiles(paths.HayabusaDir, "hayabusa-*-win-x64.exe").FirstOrDefault() ?? throw new IOException("hayabusa executable not found in the archive");
                    File.Move(exe, target, true);
                }
                else
                {
                    foreach (var f in Directory.GetFiles(x, "*.exe", SearchOption.AllDirectories).Where(f => Ps.Match(Path.GetFileName(f), "^yarac?64\\.exe$")))
                        File.Copy(f, Path.Combine(paths.BinDir, Path.GetFileName(f)), true);
                }
                Directory.Delete(x, true);
            }
            else File.Copy(dl, target, true);
            if (expectedExeSha is not null && Sha256Of(target) != expectedExeSha)
            {
                JsonFile.TryDelete(target);
                throw new InvalidDataException($"{t.Name}: SHA256 mismatch - refusing to install");
            }
        }
        finally { JsonFile.TryDelete(dl); }
    }

    private static void CopyTree(string from, string to)
    {
        foreach (var d in Directory.GetDirectories(from, "*", SearchOption.AllDirectories)) Directory.CreateDirectory(Path.Combine(to, Path.GetRelativePath(from, d)));
        Directory.CreateDirectory(to);
        foreach (var f in Directory.GetFiles(from, "*", SearchOption.AllDirectories)) File.Copy(f, Path.Combine(to, Path.GetRelativePath(from, f)), true);
    }

    /// <summary>Runs a program with an argument vector, returns exit code and combined output (bounded wait).</summary>
    public static (int Exit, string Output) RunCapture(string exe, IEnumerable<string> args, string? workDir = null, int timeoutSeconds = 120, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = workDir ?? Path.GetDirectoryName(exe) ?? "",
        };
        foreach (var a in args) if (a.Length > 0) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEndAsync(ct);
            var e = p.StandardError.ReadToEndAsync(ct);
            using var reg = ct.Register(() => { try { p.Kill(true); } catch (InvalidOperationException) { } });
            if (!p.WaitForExit(timeoutSeconds * 1000)) { try { p.Kill(true); } catch (InvalidOperationException) { } return (-1, "timeout"); }
            return (p.ExitCode, (o.IsCompletedSuccessfully ? o.Result : "") + (e.IsCompletedSuccessfully ? e.Result : ""));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { return (-1, ex.Message); }
    }

    [GeneratedRegex(@"(\d+\.\d+(\.\d+)?)")]
    private static partial Regex VersionRx();
}
