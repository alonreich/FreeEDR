using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Xunit;

namespace Edr.Core.Tests;

public class ReleaseTests
{
    private static string Folder(string name)
    {
        var d = Path.Combine(AppContext.BaseDirectory, "release", $"{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(d);
        return d;
    }

    private static string RepoFile(string rel)
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "project_structure.txt"))) return Path.Combine(d.FullName, rel);
        throw new FileNotFoundException("repository root not found");
    }

    [Fact]
    public void Versions_are_parsed_and_ordered()
    {
        Assert.Equal(new Version(2026, 11, 8, 0), AppVersion.Parse("2026.11.8"));
        Assert.Equal(new Version(2026, 11, 6, 1823), AppVersion.Parse("2026.11.6.1823 (dev build)"));
        Assert.Equal(new Version(2026, 11, 8, 1), AppVersion.Parse("v2026.11.8.1"));
        Assert.Null(AppVersion.Parse("installed 2026-11-06"));
        Assert.Null(AppVersion.Parse(""));
        Assert.True(AppVersion.IsDowngrade("2026.11.9", "2026.11.8.5"));
        Assert.False(AppVersion.IsDowngrade("2026.11.8", "2026.11.8"));
        Assert.False(AppVersion.IsDowngrade("2026.11.8", "2026.11.10"));
        Assert.False(AppVersion.IsDowngrade("", "2026.11.8"));
        Assert.False(AppVersion.IsDowngrade("2026.11.8", ""));
        Assert.True(AppVersion.IsDowngrade("2026.11.6.1823 (dev build)", "0.2611.812.30 (dev build abc)"));
        Assert.True(AppVersion.IsDev("0.2611.812.30 (dev build abc)"));
        Assert.True(AppVersion.IsDev("2026.11.6.1823 (dev build)"));
        Assert.False(AppVersion.IsDev("2026.11.8"));
        Assert.True(AppVersion.IsValidRelease("2026.11.8"));
        Assert.True(AppVersion.IsValidRelease("2026.11.8.2"));
        Assert.False(AppVersion.IsValidRelease("2026.11.8.99999"));
        Assert.False(AppVersion.IsValidRelease("0.2611.812.30"));
        Assert.False(AppVersion.IsValidRelease("2026.11"));
        Assert.True(AppVersion.Parse("0.2611.812.30")! < AppVersion.Parse("2026.1.1")!);
    }

    private const string Sample = "# FreeEDR changelog\n\nRead for: x\n\n## Unreleased\n\n### What's new for you\n- Faster scans.\n\n### Technical\n- `Scanner.cs`: parallel steps.\n\n## 2026.11.1 - 2026-11-01\n\n### What's new for you\n- First release.\n";

    [Fact]
    public void Changelog_promotion_moves_Unreleased_under_the_version_and_keeps_history()
    {
        var (text, notes) = Changelog.Promote(Sample, "2026.11.8", "2026-11-08");
        Assert.Contains("Faster scans.", notes);
        Assert.False(Changelog.HasEntries(Changelog.Section(text, Changelog.Unreleased)));
        Assert.Contains("### What's new for you", Changelog.Section(text, Changelog.Unreleased));
        Assert.Equal("- Faster scans.", Changelog.UserPart(Changelog.ForVersion(text, "2026.11.8")));
        Assert.Equal("- First release.", Changelog.UserPart(Changelog.ForVersion(text, "2026.11.1.0")));
        Assert.True(text.IndexOf("## Unreleased", StringComparison.Ordinal) < text.IndexOf("## 2026.11.8", StringComparison.Ordinal));
        Assert.True(text.IndexOf("## 2026.11.8", StringComparison.Ordinal) < text.IndexOf("## 2026.11.1", StringComparison.Ordinal));

        var (again, notes2) = Changelog.Promote(text, "2026.11.8", "2026-11-09");
        Assert.Equal(text, again);
        Assert.Contains("Faster scans.", notes2);

        Assert.Throws<InvalidDataException>(() => Changelog.Promote(text, "2026.11.9", "2026-11-09"));
        Assert.Throws<InvalidDataException>(() => Changelog.Promote(Sample, "0.1.2", "2026-11-09"));
        Assert.Throws<InvalidDataException>(() => Changelog.Promote("# x\n", "2026.11.9", "2026-11-09"));
    }

    [Fact]
    public void Release_notes_for_users_drop_the_technical_part_and_markup()
    {
        var user = Changelog.UserPart("### What's new for you\n- **Bold** `code` fix.\n\n### Technical\n- Engine.cs changed.\n");
        Assert.Equal("- Bold code fix.", user);
        Assert.Equal("- plain", Changelog.UserPart("- plain"));
        Assert.Equal("", Changelog.UserPart(null));
    }

    [Fact]
    public void The_repository_changelog_has_an_Unreleased_section_in_the_expected_format()
    {
        var text = File.ReadAllText(RepoFile(@"docs\CHANGELOG.md"));
        var u = Changelog.Section(text, Changelog.Unreleased);
        Assert.NotNull(u);
        Assert.Contains($"### {Changelog.UserHeading}", u);
        Assert.Contains($"### {Changelog.TechHeading}", u);
        Assert.Contains("Read for:", string.Join("\n", text.Split('\n').Take(4)));
    }

    private static JsonObject Release(string tag = "v2026.11.8", string digest = "sha256:" + "AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12", long size = 90_000_000,
                                      string url = "https://github.com/alonreich/FreeEDR/releases/download/v2026.11.8/FreeEDR-Setup.exe", bool draft = false, bool pre = false) => new()
    {
        ["tag_name"] = tag, ["draft"] = draft, ["prerelease"] = pre, ["html_url"] = "https://github.com/alonreich/FreeEDR/releases/tag/" + tag,
        ["published_at"] = "2026-11-08T10:00:00Z",
        ["body"] = "### What's new for you\n- Update checks.\n\n### Technical\n- AppRelease.cs\n",
        ["assets"] = new JsonArray(new JsonObject { ["name"] = "FreeEDR-Setup.exe", ["digest"] = digest, ["size"] = size, ["browser_download_url"] = url }),
    };

    [Fact]
    public void Only_complete_published_releases_from_the_FreeEDR_repository_are_offered()
    {
        var info = AppRelease.Parse(Release());
        Assert.NotNull(info);
        Assert.Equal(new Version(2026, 11, 8, 0), info.Latest);
        Assert.Equal("- Update checks.", info.Notes);
        Assert.Equal(64, info.Sha256.Length);
        Assert.Null(AppRelease.Parse(Release(draft: true)));
        Assert.Null(AppRelease.Parse(Release(pre: true)));
        Assert.Null(AppRelease.Parse(Release(digest: "")));
        Assert.Null(AppRelease.Parse(Release(digest: "sha1:abc")));
        Assert.Null(AppRelease.Parse(Release(size: 0)));
        Assert.Null(AppRelease.Parse(Release(size: AppRelease.MaxSetupBytes + 1)));
        Assert.Null(AppRelease.Parse(Release(url: "https://evil.example/FreeEDR-Setup.exe")));
        Assert.Null(AppRelease.Parse(Release(tag: "nightly")));
        Assert.Null(AppRelease.Parse(null));

        Assert.True(AppRelease.IsNewer(info, "2026.11.6.1823 (dev build)"));
        Assert.True(AppRelease.IsNewer(info, "0.2611.812.30 (dev build abc)"));
        Assert.False(AppRelease.IsNewer(info, "2026.11.8"));
        Assert.False(AppRelease.IsNewer(info, "2026.11.9"));
    }

    [Fact]
    public void Signer_rules_never_accept_a_weaker_download_than_the_installed_copy()
    {
        Assert.True(AppRelease.SignerVerdict("FreeEDR Project", "FreeEDR Project").Ok);
        Assert.False(AppRelease.SignerVerdict("FreeEDR Project", null).Ok);
        Assert.False(AppRelease.SignerVerdict("FreeEDR Project", "Someone Else").Ok);
        Assert.True(AppRelease.SignerVerdict(null, null).Ok);
        Assert.True(AppRelease.SignerVerdict(null, "FreeEDR Project").Ok);
    }

    [Fact]
    public void Signer_identity_is_the_whole_subject_so_a_lookalike_name_is_refused_and_a_successor_can_be_announced()
    {
        const string ours = "CN=FreeEDR Project\nO=FreeEDR Project\nL=Tel Aviv\nS=Tel Aviv\nC=IL";
        const string sameCnElsewhere = "CN=FreeEDR Project\nO=FreeEDR Project\nL=Elsewhere\nC=XX";
        Assert.Equal("C=IL, CN=FreeEDR Project, L=Tel Aviv, O=FreeEDR Project, S=Tel Aviv", AppRelease.NormalizeSubject(ours));
        Assert.Equal(AppRelease.NormalizeSubject(ours), AppRelease.NormalizeSubject("C=IL\nST=Tel Aviv\nO=FreeEDR Project\nOU=Signing 2027\nCN=FreeEDR Project\nL=Tel Aviv"));
        Assert.Equal("FreeEDR Project", AppRelease.DisplayName(ours));
        Assert.True(AppRelease.SignerVerdict(AppRelease.NormalizeSubject(ours), AppRelease.NormalizeSubject(ours)).Ok);
        Assert.False(AppRelease.SignerVerdict(AppRelease.NormalizeSubject(ours), AppRelease.NormalizeSubject(sameCnElsewhere)).Ok);
        Assert.True(AppRelease.SignerVerdict(ours, sameCnElsewhere, [sameCnElsewhere]).Ok);
        Assert.False(AppRelease.SignerVerdict(ours, null, [sameCnElsewhere]).Ok);
        Assert.Empty(AppRelease.TrustedSuccessorSubjects);
    }

    [Fact]
    public void The_dashboard_prefers_the_small_update_package_and_Setup_stays_the_fallback()
    {
        var r = Release();
        ((JsonArray)r["assets"]!).Add((JsonNode)new JsonObject
        {
            ["name"] = "FreeEDR-Update.exe", ["digest"] = "sha256:" + new string('C', 64), ["size"] = 12_000_000L,
            ["browser_download_url"] = "https://github.com/alonreich/FreeEDR/releases/download/v2026.11.8/FreeEDR-Update.exe",
        });
        var upd = AppRelease.Parse(r, preferUpdate: true)!;
        Assert.Equal(AppRelease.UpdateAsset, upd.Asset);
        Assert.Equal(12_000_000L, upd.Size);
        Assert.Equal(AppRelease.SetupAsset, AppRelease.Parse(r)!.Asset);
        Assert.Equal(AppRelease.SetupAsset, AppRelease.Parse(Release(), preferUpdate: true)!.Asset);
        var paths = new EdrPaths(Folder("asset"), null);
        Assert.EndsWith("FreeEDR-Update-2026.11.8.0.exe", new AppRelease(paths).SetupPath(upd));
        ((JsonObject)((JsonArray)r["assets"]!)[1]!)["digest"] = "";
        Assert.Null(AppRelease.Parse(r, preferUpdate: true));
    }

    [Fact]
    public void Users_who_skip_versions_see_the_notes_of_every_version_in_between()
    {
        var text = "## Unreleased\n\n### What's new for you\n\n### Technical\n\n" +
                   "## 2026.11.10 - 2026-11-10\n\n### What's new for you\n- Third.\n\n### Technical\n- c\n\n" +
                   "## 2026.11.9 - 2026-11-09\n\n### What's new for you\n- Second.\n\n### Technical\n- b\n\n" +
                   "## 2026.11.8 - 2026-11-08\n\n### What's new for you\n- First.\n\n### Technical\n- a\n";
        var parts = Changelog.UserPartsBetween(text, new Version(2026, 11, 8, 0), new Version(2026, 11, 10, 0));
        Assert.Equal(2, parts.Count);
        var notes = Changelog.Combine(parts);
        Assert.True(notes.IndexOf("Third.", StringComparison.Ordinal) < notes.IndexOf("Second.", StringComparison.Ordinal));
        Assert.DoesNotContain("First.", notes);
        Assert.StartsWith("FreeEDR 2026.11.10:", notes);
        Assert.True(Changelog.IsCombined(notes));
        Assert.Equal("- Second.", Changelog.Combine(Changelog.UserPartsBetween(text, null, new Version(2026, 11, 9, 0))));
        Assert.False(Changelog.IsCombined("- Second."));

        static JsonObject R(string tag, string user) => new() { ["tag_name"] = tag, ["body"] = Changelog.ReleaseBody($"### What's new for you\n{user}\n\n### Technical\n- x.cs\n") + "\n---\n**Download:** x\n" };
        var latest = new AppUpdateInfo("v2026.11.10", new Version(2026, 11, 10, 0), "", "", "", 1, "- Third.", null);
        var list = new JsonArray(R("v2026.11.10", "- Third."), R("v2026.11.9", "- Second."), R("v2026.11.8", "- First."), new JsonObject { ["tag_name"] = "v2026.11.9.1", ["draft"] = true, ["body"] = "- Draft." });
        var since = AppRelease.NotesSince(list, new Version(2026, 11, 8, 0), latest);
        Assert.Contains("- Second.", since);
        Assert.Contains("- Third.", since);
        Assert.DoesNotContain("First", since);
        Assert.DoesNotContain("Draft", since);
        Assert.DoesNotContain("x.cs", since);
        Assert.Equal("- Third.", AppRelease.NotesSince(null, new Version(2026, 11, 9, 0), latest));
    }

    [Fact]
    public void The_public_release_body_puts_plain_notes_first_and_hides_the_technical_part()
    {
        var body = Changelog.ReleaseBody("### What's new for you\n- Faster scans.\n\n### Technical\n- `Scanner.cs`: parallel.\n");
        Assert.StartsWith("### What's new for you", body);
        Assert.True(body.IndexOf("Faster scans", StringComparison.Ordinal) < body.IndexOf("<details>", StringComparison.Ordinal));
        Assert.Contains("Scanner.cs", body);
        Assert.Equal("- Faster scans.", Changelog.UserPart(body + "\n---\n**Download:** FreeEDR-Setup.exe\n\n<!-- marker -->\n"));
        Assert.Equal("- Only users.", Changelog.UserPart(Changelog.ReleaseBody("### What's new for you\n- Only users.\n") + "\n---\n**Download:** x\n"));
        Assert.DoesNotContain("<details>", Changelog.ReleaseBody("### What's new for you\n- Only users.\n"));
    }

    [Fact]
    public void The_changelog_gate_refuses_broken_Unreleased_sections_and_edited_releases()
    {
        Assert.Empty(Changelog.Problems(Sample));
        Assert.Empty(Changelog.Problems(File.ReadAllText(RepoFile(@"docs\CHANGELOG.md"))));
        Assert.NotEmpty(Changelog.Problems("# x\n"));
        Assert.NotEmpty(Changelog.Problems("## Unreleased\n\n### What's new for you\n- a\n"));
        Assert.NotEmpty(Changelog.Problems("## Unreleased\n\n### What's new for you\n- a\n\n### Technical\n"));
        Assert.Empty(Changelog.Problems("## Unreleased\n\n### What's new for you\n\n### Technical\n- only technical\n"));
        Assert.NotEmpty(Changelog.Problems("## Unreleased\n- stray\n\n### What's new for you\n\n### Technical\n"));
        Assert.NotEmpty(Changelog.Problems("## Unreleased\n\n### What's new for you\n\n### Fixes\n- x\n\n### Technical\n- y\n"));

        var (promoted, _) = Changelog.Promote(Sample, "2026.11.8", "2026-11-08");
        var later = promoted.Replace("## Unreleased\n\n### What's new for you\n", "## Unreleased\n\n### What's new for you\n- Next thing.\n");
        Assert.True(Changelog.ReleasedKept(promoted, later));
        var (next, _) = Changelog.Promote(later.Replace("### Technical\n\n## 2026.11.8", "### Technical\n- n.cs\n\n## 2026.11.8"), "2026.11.9", "2026-11-09");
        Assert.True(Changelog.ReleasedKept(promoted, next));
        Assert.False(Changelog.ReleasedKept(promoted, promoted.Replace("- Faster scans.", "- Much faster scans.")));
        Assert.True(Changelog.ReleasedKept("## Unreleased\n", promoted));
    }

    [Fact]
    public void Installed_update_downloads_are_removed_and_newer_ones_are_kept()
    {
        var dir = Folder("purge");
        foreach (var n in new[] { "FreeEDR-Setup-2026.11.8.0.exe", "FreeEDR-Update-2026.11.8.0.exe.part", "FreeEDR-Update-2026.11.9.0.exe", "FreeEDR-Setup-2026.11.7.0.exe", "notes.txt" })
            File.WriteAllBytes(Path.Combine(dir, n), [1]);
        Assert.Equal(3, AppRelease.PurgeDownloads(dir, new Version(2026, 11, 8, 0)));
        Assert.Equal(new[] { "FreeEDR-Update-2026.11.9.0.exe", "notes.txt" }, Directory.GetFiles(dir).Select(Path.GetFileName).Order().ToArray());
        Assert.Equal(0, AppRelease.PurgeDownloads(dir, null));
        Assert.Equal(0, AppRelease.PurgeDownloads(Path.Combine(dir, "missing"), new Version(2026, 1, 1, 0)));
        Directory.Delete(dir, true);
    }

    [Fact]
    public void Local_builds_rank_below_every_release_so_published_updates_are_still_offered()
    {
        var local = AppVersion.LocalNumber(new DateTime(2026, 11, 8, 15, 30, 0, DateTimeKind.Utc));
        Assert.Equal("0.2611.815.30", local);
        Assert.True(AppVersion.IsDev(local));
        Assert.True(AppVersion.Parse(local)! < AppVersion.Parse("2026.11.8")!);
        Assert.False(AppVersion.IsDowngrade(local, "2026.11.8"));
        Assert.Contains("AppVersion.LocalNumber", File.ReadAllText(RepoFile(@"build\EdrBuild\Release.cs")));
        Assert.DoesNotContain("utcNow.Hour * 100 + utcNow.Minute", File.ReadAllText(RepoFile(@"build\EdrBuild\Release.cs")));
    }

    [Fact]
    public void An_interrupted_update_is_recorded_and_only_a_running_installer_hides_it()
    {
        var root = Folder("pending");
        var paths = new EdrPaths(root, Path.Combine(root, "user", "S-1-5-21-test"));
        var release = new AppRelease(paths, _ => null);
        Assert.Null(release.PendingUpgrade());
        Directory.CreateDirectory(paths.DataDir);
        JsonFile.WriteAtomic(paths.UpgradePendingFile, new JsonObject { ["to"] = "2026.11.9", ["from"] = "2026.11.8", ["backup"] = "x", ["pid"] = Environment.ProcessId });
        Assert.Equal("2026.11.9", release.PendingUpgrade()!.Str("to"));
        JsonFile.WriteAtomic(paths.UpgradePendingFile, new JsonObject { ["to"] = "2026.11.9", ["pid"] = 0 });
        Assert.NotNull(release.PendingUpgrade());
        Directory.Delete(root, true);
    }

    [Fact]
    public void Setup_restarts_the_tray_after_any_outcome_and_spares_its_own_download()
    {
        var i = File.ReadAllText(RepoFile(@"src\Edr.Setup\Installer.cs"));
        var common = File.ReadAllText(RepoFile(@"src\Edr.Setup\SetupCommon.cs"));
        var fin = i[i.IndexOf("        finally", i.IndexOf("public int Run()", StringComparison.Ordinal), StringComparison.Ordinal)..];
        Assert.Contains("StartTrays(", fin[..fin.IndexOf("RecordInstalledSize", StringComparison.Ordinal)]);
        Assert.Contains("catch (Exception e)\n", i.Replace("\r\n", "\n"));
        Assert.Contains("UpgradePendingFile", i);
        Assert.Contains("MarkPending(", i);
        Assert.Contains("PurgeUpdateDownloads()", i);
        Assert.Contains("IsUpdateDownload(paths, path)", common);
        Assert.True(i.IndexOf("_traysStopped = true", StringComparison.Ordinal) < i.IndexOf("StopFreeEdrProcesses", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_verified_download_already_on_disk_is_not_downloaded_again_and_is_locked_while_checked()
    {
        var root = Folder("dl");
        var paths = new EdrPaths(root, Path.Combine(root, "user", "S-1-5-21-test"));
        var release = new AppRelease(paths, _ => null);
        var bytes = RandomNumberGenerator.GetBytes(4096);
        var sha = Convert.ToHexString(SHA256.HashData(bytes));
        var info = new AppUpdateInfo("v2026.11.8", new Version(2026, 11, 8, 0), "https://github.com/alonreich/FreeEDR/releases/tag/v2026.11.8",
                                     "https://invalid.invalid/never-fetched", sha, bytes.Length, "", null);
        Directory.CreateDirectory(release.UpdateDir);
        File.WriteAllBytes(release.SetupPath(info), bytes);
        File.WriteAllBytes(Path.Combine(release.UpdateDir, "FreeEDR-Setup-2026.11.1.0.exe"), [1]);
        var path = await release.Download(info, null, TestContext.Current.CancellationToken);
        Assert.Equal(release.SetupPath(info), path);
        Assert.Single(Directory.GetFiles(release.UpdateDir));

        var (ok, _, handle) = release.Verify(info, path);
        Assert.True(ok);
        Assert.NotNull(handle);
        Assert.ThrowsAny<IOException>(() => File.WriteAllBytes(path, [0]));
        handle.Dispose();

        File.WriteAllBytes(path, [0, 1, 2]);
        var (bad, msg, none) = release.Verify(info, path);
        Assert.False(bad);
        Assert.Null(none);
        Assert.Contains("changed", msg);

        var signed = new AppRelease(paths, f => f.EndsWith(EdrPaths.EngineExe, StringComparison.OrdinalIgnoreCase) ? "FreeEDR Project" : null);
        File.WriteAllBytes(path, bytes);
        var (unsigned, why, _) = signed.Verify(info, path);
        Assert.False(unsigned);
        Assert.Contains("not digitally signed", why);
        Directory.Delete(root, true);
    }

    [Fact]
    public void A_newer_Velociraptor_signed_by_its_publisher_is_kept_over_the_pin()
    {
        var v = Tools.Spec("Velociraptor")!;
        var pin = Tools.VersionOf(v.Tag);
        Assert.True(Tools.IsNewerSigned(v, v.Publisher, "0.99.0"));
        Assert.True(Tools.IsNewerSigned(v, v.Publisher, pin));
        Assert.False(Tools.IsNewerSigned(v, v.Publisher, "0.1.0"));
        Assert.False(Tools.IsNewerSigned(v, "Someone Else", "0.99.0"));
        Assert.False(Tools.IsNewerSigned(v, null, "0.99.0"));
        Assert.False(Tools.IsNewerSigned(v, v.Publisher, null));
        foreach (var t in Tools.Pinned.Where(t => !t.Updatable)) Assert.False(Tools.IsNewerSigned(t, "Anyone", "99.0"));
    }

    [Fact]
    public void Installer_keeps_the_Windows_settings_record_and_rolls_back_everything_it_replaces()
    {
        var i = File.ReadAllText(RepoFile(@"src\Edr.Setup\Installer.cs"));
        var u = File.ReadAllText(RepoFile(@"src\Edr.Setup\Uninstaller.cs"));
        var iss = File.ReadAllText(RepoFile(@"build\installer\FreeEDR-Setup.iss"));
        foreach (var dir in new[] { "\"config\"", "\"rules\"", "\"docs\"", "\"version.txt\"" }) Assert.Contains(dir, i[i.IndexOf("private bool Rollback()", StringComparison.Ordinal)..]);
        Assert.True(i.IndexOf("Backup();", StringComparison.Ordinal) < i.IndexOf("FactoryReset.Apply", StringComparison.Ordinal), "the backup must come before a clean install erases settings");
        Assert.Contains("AppVersion.IsDowngrade", i);
        Assert.Contains("EstimatedSize", i);
        Assert.Contains("RestoreIncomplete", u);
        Assert.DoesNotContain("[UninstallDelete]", iss);
        Assert.DoesNotContain("UninstallDisplaySize", iss);
        Assert.Contains("CurUninstallStepChanged", iss);
        Assert.Contains("InitializeSetup", iss);
        Assert.Contains("SyncDisplayVersion", iss);
    }
}
