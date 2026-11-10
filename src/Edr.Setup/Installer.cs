using System.Globalization;
using System.IO.Compression;
using System.Text.Json.Nodes;
using Edr.Core;
using Edr.Core.Native;
using Microsoft.Win32;

namespace Edr.Setup;

internal sealed class Installer(EdrPaths paths, string source, SetupOptions opt, SetupLog log)
{
    private const string OldTask = "FreeEDR";
    private static readonly string[] OldTasks = ["FreeEDR", "EDR", "start wail2ban onstartup", "LocalEDR-TrayWatcher", "LocalEDR-DailyScan"];
    private static readonly string[] OldScripts = ["EDR-Common.ps1", "EDR-Engine.ps1", "EDR-Scan.ps1", "EDR-Control.ps1", "EDR-Tray.ps1", "Install-EDR.ps1", "Uninstall-EDR.ps1", "Installation_Process.md"];

    private string? _backup;
    private List<ToolSpec> _replaceTools = [];
    private bool _fromPowerShell;
    private bool _sysmonForeign;
    private bool _traysStopped;
    private bool _traysStarted;

    public int Run()
    {
        var result = "FAILED";
        var prior = File.Exists(Path.Combine(paths.Root, "EDR-Engine.ps1")) || File.Exists(paths.EnginePath);
        _fromPowerShell = File.Exists(Path.Combine(paths.Root, "EDR-Engine.ps1"));
        try
        {
            log.Step("Pre-flight");
            if (!Win32.IsAdministrator()) throw new InvalidOperationException("Run the installer as administrator.");
            if (!Environment.Is64BitOperatingSystem || System.Runtime.InteropServices.RuntimeInformation.OSArchitecture != System.Runtime.InteropServices.Architecture.X64)
                throw new InvalidOperationException("FreeEDR supports 64-bit Intel/AMD Windows (x64) only.");
            foreach (var f in new[] { @"bin\" + EdrPaths.EngineExe, @"bin\" + EdrPaths.ControlExe, @"bin\" + EdrPaths.InstallerExe, @"bin\tray\" + EdrPaths.TrayExe, @"config\sysmonconfig.template.xml" })
                if (!File.Exists(Path.Combine(source, f))) throw new FileNotFoundException($"Missing setup file {Path.Combine(source, f)}");
            log.Ok("Running elevated, x64, all setup files present");
            var installedText = prior && File.Exists(paths.VersionFile) ? File.ReadAllText(paths.VersionFile).Trim() : "";
            if (!opt.AllowDowngrade && AppVersion.IsDowngrade(installedText, opt.Version))
                throw new InvalidOperationException($"The installed FreeEDR ({installedText}) is newer than this Setup ({opt.Version}). Nothing was changed. " +
                                                    "To install the older version anyway, run Setup again and confirm, or: FreeEDR-Setup.exe /AllowDowngrade=1");
            var sysmons = Sys.SysmonServices();
            var other = sysmons.FirstOrDefault(s => !Ps.Eq(s.Name, "Sysmon64") && !Ps.Eq(s.Name, "SysmonDrv"));
            if (other.Name is not null) throw new InvalidOperationException($"Another Sysmon is installed as service '{other.Name}' ({other.Image}). FreeEDR needs it as 'Sysmon64': remove it first ('<that exe> -u'), then run Setup again.");
            _sysmonForeign = Services.Exists("Sysmon64") && !prior;
            if (_sysmonForeign && !opt.ReplaceSysmonConfig)
                throw new InvalidOperationException("Sysmon is already installed with a configuration that is not FreeEDR's. Allow FreeEDR to replace it (it is saved and put back on uninstall): FreeEDR-Setup.exe /ReplaceSysmonConfig=1");

            log.Step("Stopping the running version");
            Services.Stop(EdrPaths.ServiceName, 30);
            foreach (var t in OldTasks) Sys.TaskDisable(t);
            _traysStopped = true;
            Sys.StopFreeEdrProcesses(paths, includeTools: true);
            log.Ok("Engine, scans, tools and trays stopped");

            var tools = new Tools(paths, s => log.Info(s));
            _replaceTools = Tools.Pinned.Where(t => !tools.KeepInstalled(t)).ToList();
            var pending = JsonFile.ReadObject(paths.UpgradePendingFile);
            if (pending is not null && pending.Str("backup") is { Length: > 0 } kept && Directory.Exists(kept))
            {
                _backup = kept;
                log.Warn($"The previous update (to {pending.Str("to")}, started {pending.Str("started")}) did not finish. Its backup of {pending.Str("from")} stays the roll-back point: {kept}");
            }
            else Backup();
            if (_backup is not null) MarkPending(pending?.Str("from") is { Length: > 0 } f ? f : installedText);

            if (opt.Clean && prior)
            {
                log.Step("Clean install: erasing the previous settings and data");
                foreach (var n in FactoryReset.Apply(paths, everything: true)) log.Note(n);
            }

            log.Step("Installing program files");
            CopyFiles();
            foreach (var d in new[] { paths.ConfigDir, paths.DataDir, paths.RulesDir, paths.BinDir, paths.ControlDir, paths.InboxDir, paths.UserDir }) Directory.CreateDirectory(d);
            File.WriteAllText(paths.VersionFile, opt.Version.Length > 0 ? opt.Version : $"installed {DateTime.Now:yyyy-MM-dd}");
            SaveBaseline(prior);

            log.Step("Tools (Hayabusa, YARA, OSV-Scanner, Velociraptor)");
            foreach (var t in Tools.Pinned)
            {
                if (FromPackage(tools, t)) continue;
                try { log.Note(tools.EnsurePinned(t).GetAwaiter().GetResult()); }
                catch (Exception e) when (e is IOException or InvalidDataException or HttpRequestException) { throw new IOException($"{t.Name}: {e.Message} (behind a proxy, Windows' proxy settings are used)"); }
            }

            Sysmon();
            Settings();
            UserFoldersAndAcl();
            DefenderAndFirewall();
            ServiceAndTray();

            log.Step("Starting the engine and checking every part");
            var verified = Verify(out var failed);
            if (verified)
            {
                EngineNote.Send(paths, "Info", "FreeEDR installation verified", detail: "All protection parts and tools were checked.", kind: "health");
                CleanupOldVersion();
                JsonFile.TryDelete(paths.UpgradePendingFile);
                PurgeUpdateDownloads();
                result = "SUCCESS";
                StartTrays("FreeEDR is active", "All protection parts were checked and are running.", "Info");
            }
            else
            {
                result = Rollback() ? "ROLLED BACK" : "FAILED";
                StartTrays("FreeEDR installation incomplete", $"Check failed: {string.Join(", ", failed)}. See install.log.", "Warning");
            }
        }
        catch (Exception e)
        {
            log.Error(e is IOException or InvalidOperationException or UnauthorizedAccessException or OperationCanceledException or InvalidDataException or HttpRequestException
                ? e.Message : $"{e.GetType().Name}: {e.Message}");
            if (_backup is not null && Rollback()) result = "ROLLED BACK";
            else result = "FAILED";
        }
        finally
        {
            if (result != "SUCCESS" && !prior) log.Info("To remove what this first install set up: Settings > Apps > FreeEDR > Uninstall.");
            if (_traysStopped && !_traysStarted && File.Exists(paths.TrayPath))
            {
                try
                {
                    if (result == "ROLLED BACK") StartTrays("FreeEDR update did not install", "Setup stopped with an error and put your previous version back; it is running. See install.log.", "Warning");
                    else StartTrays("FreeEDR update failed", "Setup stopped with an error and could not put everything back. Run FreeEDR Setup again: it finishes the update or rolls it back. See install.log.", "Error");
                }
                catch (Exception e) { log.Warn($"Could not start the tray: {e.Message}"); }
            }
            RecordInstalledSize();
            log.Result("INSTALL RESULT", result, result == "SUCCESS");
            try { if (Directory.Exists(paths.DownloadDir)) Directory.Delete(paths.DownloadDir, true); } catch (IOException) { }
        }
        return result == "SUCCESS" ? 0 : result.StartsWith("ROLLED BACK", StringComparison.Ordinal) ? 3 : 1;
    }

    public static (string? Installed, bool SysmonForeign, bool DesktopIcon) Inspect(EdrPaths paths)
    {
        var prior = File.Exists(Path.Combine(paths.Root, "EDR-Engine.ps1")) || File.Exists(paths.EnginePath);
        string? ver = null;
        if (prior) { try { ver = File.Exists(paths.VersionFile) ? File.ReadAllText(paths.VersionFile).Trim() : "an earlier version"; } catch (IOException) { ver = "an earlier version"; } }
        return (ver, Services.Exists("Sysmon64") && !prior, !prior || File.Exists(Path.Combine(Sys.CommonDesktop, "FreeEDR.lnk")));
    }

    private void MarkPending(string from)
    {
        JsonFile.WriteAtomic(paths.UpgradePendingFile, new JsonObject
        {
            ["started"] = DateTime.Now.ToString("s", CultureInfo.InvariantCulture), ["from"] = from, ["to"] = opt.Version,
            ["backup"] = _backup, ["pid"] = Environment.ProcessId,
        });
    }

    private void PurgeUpdateDownloads()
    {
        if (AppVersion.Parse(opt.Version) is not { } now || !Directory.Exists(paths.UserDir)) return;
        var n = 0;
        foreach (var d in Directory.GetDirectories(paths.UserDir)) n += AppRelease.PurgeDownloads(Path.Combine(d, "update"), now);
        if (n > 0) log.Ok($"Removed {n} downloaded FreeEDR installer(s) of versions that are now installed");
    }

    private void Backup()
    {
        if (!File.Exists(paths.EnginePath) && !_fromPowerShell) return;
        _backup = Path.Combine(paths.DataDir, $"backup-{DateTime.Now:yyyyMMdd-HHmmss}");
        Directory.CreateDirectory(_backup);
        foreach (var s in OldScripts.Select(n => Path.Combine(paths.Root, n)).Where(File.Exists)) File.Copy(s, Path.Combine(_backup, Path.GetFileName(s)), true);
        if (Directory.Exists(paths.BinDir))
            foreach (var f in Directory.GetFiles(paths.BinDir, "FreeEDR-*.exe")) { Directory.CreateDirectory(Path.Combine(_backup, "bin")); File.Copy(f, Path.Combine(_backup, "bin", Path.GetFileName(f)), true); }
        if (Directory.Exists(paths.TrayDir)) CopyTree(paths.TrayDir, Path.Combine(_backup, "bin", "tray"));
        var tools = new Tools(paths);
        foreach (var t in _replaceTools.Where(t => File.Exists(tools.ExePath(t))))
        {
            if (t.Name == "Hayabusa") { CopyTree(paths.HayabusaDir, Path.Combine(_backup, "bin", "hayabusa")); continue; }
            Directory.CreateDirectory(Path.Combine(_backup, "bin"));
            File.Copy(tools.ExePath(t), Path.Combine(_backup, "bin", Path.GetFileName(t.Exe)), true);
            if (t.Name == "YARA" && File.Exists(paths.YaracExe)) File.Copy(paths.YaracExe, Path.Combine(_backup, "bin", "yarac64.exe"), true);
        }
        if (Directory.Exists(paths.ConfigDir)) CopyTree(paths.ConfigDir, Path.Combine(_backup, "config"));
        if (Directory.Exists(paths.RulesDir))
            foreach (var y in Directory.GetFiles(paths.RulesDir, "*.yar")) { Directory.CreateDirectory(Path.Combine(_backup, "rules")); File.Copy(y, Path.Combine(_backup, "rules", Path.GetFileName(y)), true); }
        if (Directory.Exists(paths.DocsDir)) CopyTree(paths.DocsDir, Path.Combine(_backup, "docs"));
        foreach (var f in new[] { paths.VersionFile, Path.Combine(paths.Root, "README.md") }.Where(File.Exists)) File.Copy(f, Path.Combine(_backup, Path.GetFileName(f)), true);
        log.Ok($"Previous version backed up to {_backup} (programs, settings, rules, the tools it replaces, version)");
        foreach (var old in new DirectoryInfo(paths.DataDir).GetDirectories("backup-*").OrderByDescending(d => d.Name).Skip(3))
            try { old.Delete(true); log.Ok($"Removed old backup {old.Name}"); } catch (IOException e) { log.Warn($"Could not remove old backup {old.Name}: {e.Message}"); }
    }

    private bool FromPackage(Tools tools, ToolSpec t)
    {
        var target = tools.ExePath(t);
        if (!_replaceTools.Contains(t))
        {
            log.Ok(Ps.Eq(Tools.Sha256Of(target), t.Sha256) ? $"{t.Name} {t.Tag} present" : $"{t.Name} {tools.InstalledVersion(t)} kept (newer than {t.Tag} and signed by {t.Publisher})");
            return true;
        }
        var src = Path.Combine(source, "bin", t.Exe);
        if (!File.Exists(src)) return false;
        if (t.Name == "Hayabusa") CopyTree(Path.Combine(source, "bin", "hayabusa"), paths.HayabusaDir);
        else File.Copy(src, target, true);
        if (t.Name == "YARA" && File.Exists(Path.Combine(source, "bin", "yarac64.exe"))) File.Copy(Path.Combine(source, "bin", "yarac64.exe"), paths.YaracExe, true);
        if (!Ps.Eq(Tools.Sha256Of(target), t.Sha256)) { JsonFile.TryDelete(target); throw new InvalidDataException($"{t.Name}: the copy in the setup package does not match its pinned SHA256"); }
        log.Ok($"{t.Name} {t.Tag} installed from the setup package (SHA256 checked, nothing downloaded)");
        return true;
    }

    private void CopyFiles()
    {
        var src = Path.GetFullPath(source).TrimEnd('\\');
        if (Ps.Eq(src, paths.Root)) { log.Ok("Running from the install folder itself - files already in place"); return; }
        var n = 0;
        foreach (var f in Directory.GetFiles(src, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(src, f);
            if (Tools.IsPackagedToolFile(rel)) continue;
            var to = Path.Combine(paths.Root, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            for (var i = 0; ; i++)
            {
                try { File.Copy(f, to, true); break; }
                catch (IOException) when (i < 10) { Thread.Sleep(500); }
            }
            n++;
        }
        log.Ok($"{n} files copied from {src}");
    }

    private void SaveBaseline(bool prior)
    {
        if (File.Exists(paths.BaselineFile)) { log.Ok("Windows settings from before the first install are on record (the uninstaller restores them)"); return; }
        var known = !prior;
        var mp = known ? Defender.ReadPreferences() : null;
        string? sysmonBackup = null;
        if (_sysmonForeign)
        {
            sysmonBackup = Path.Combine(paths.DataDir, "sysmon-original.reg");
            Sys.Run(Sys.Sys32("reg.exe"), "export", @"HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters", sysmonBackup, "/y");
            if (File.Exists(sysmonBackup)) log.Ok($"Existing Sysmon configuration saved ({sysmonBackup})"); else { log.Warn("Could not save the existing Sysmon configuration"); sysmonBackup = null; }
        }
        bool? shadow = null;
        if (known && Firewall.AllRules().FirstOrDefault(r => r["Id"] == "RemoteDesktop-Shadow-In-TCP") is { } rule) shadow = Ps.Eq(rule.GetValueOrDefault("Active"), "TRUE");
        JsonFile.WriteAtomic(paths.BaselineFile, new JsonObject
        {
            ["recorded"] = DateTime.Now.ToString("s", CultureInfo.InvariantCulture), ["known"] = known, ["defenderRead"] = mp is not null,
            ["asr"] = mp?["asr"]?.DeepClone() ?? new JsonArray(), ["controlledFolderAccess"] = mp?.Int("cfa") ?? 0,
            ["cfaAllowedApps"] = mp?["cfaApps"]?.DeepClone() ?? new JsonArray(), ["asrExclusions"] = mp?["asrExclusions"]?.DeepClone() ?? new JsonArray(),
            ["threatIdActions"] = mp?["threatIds"]?.DeepClone() ?? new JsonArray(), ["rdpShadowEnabled"] = shadow,
            ["sysmonPreexisting"] = _sysmonForeign, ["sysmonConfigBackup"] = sysmonBackup,
            ["eventSourcePreexisting"] = known && Sys.EventSourceExists(EdrPaths.EventSource),
        });
        log.Ok($"Recorded the Windows settings FreeEDR changes ({(known ? "original values" : "an earlier install already changed them: the uninstaller removes what FreeEDR added")})");
    }

    private void Sysmon()
    {
        log.Step("Sysmon sensor and its configuration");
        var exe = Path.Combine(EdrPaths.SystemRoot, "Sysmon64.exe");
        var installed = Services.Exists("Sysmon64");
        if (!installed)
        {
            var zip = Path.Combine(paths.DownloadDir, "Sysmon.zip");
            var x = Path.Combine(paths.DownloadDir, "x-sysmon");
            Directory.CreateDirectory(paths.DownloadDir);
            new Tools(paths).Download("https://download.sysinternals.com/files/Sysmon.zip", zip).GetAwaiter().GetResult();
            if (Directory.Exists(x)) Directory.Delete(x, true);
            ZipFile.ExtractToDirectory(zip, x);
            exe = Path.Combine(x, "Sysmon64.exe");
            var signer = new AuthenticodeSigners().SignerOf(exe);
            if (signer is null || !signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Sysmon64.exe does not carry a valid Microsoft signature");
            log.Ok($"Sysmon downloaded (signed by {signer})");
        }
        else log.Ok("Sysmon is installed");
        var rendered = File.ReadAllText(paths.SysmonTemplate).Replace("{ROOT}", paths.Root);
        var prev = File.Exists(paths.SysmonConfig) ? File.ReadAllText(paths.SysmonConfig) : null;
        File.WriteAllText(paths.SysmonConfig, rendered, JsonFile.Utf8NoBom);
        var (rc, output) = Tools.RunCapture(exe, installed ? ["-accepteula", "-c", paths.SysmonConfig] : ["-accepteula", "-i", paths.SysmonConfig], timeoutSeconds: 300);
        if (rc == 0) log.Ok("Sysmon config applied (include-only rules, games and anti-cheat excluded)");
        else
        {
            log.Warn($"Sysmon rejected the new config (exit {rc}): {string.Join(" ", output.Trim().Split('\n').TakeLast(3))}");
            if (prev is not null) { File.WriteAllText(paths.SysmonConfig, prev, JsonFile.Utf8NoBom); Tools.RunCapture(exe, ["-c", paths.SysmonConfig], timeoutSeconds: 120); log.Warn("Previous Sysmon config restored"); }
        }
        if (Services.Query("SysmonDrv") is var d && d != Services.State.Running && d != Services.State.Missing) log.Warn($"Sysmon driver is {d} - restart the PC");
    }

    private void Settings()
    {
        log.Step("Settings, allow lists and trusted apps");
        var cfg = EdrConfig.Load(paths.ConfigFile, strict: true);
        if (cfg.InstalledAt.Length == 0) cfg.InstalledAt = DateTime.Now.ToString("s", CultureInfo.InvariantCulture);
        var x = JsonFile.ReadStrict(paths.ExclusionsFile) as JsonObject ?? new JsonObject();
        foreach (var l in new[] { "realtimePath", "realtime", "ioc", "yara", "sigma", "wail2ban", "cve", "defender" }) if (x[l] is not JsonArray) x[l] = new JsonArray();
        var rt = (JsonArray)x["realtime"]!;
        var before = rt.Count;
        foreach (var e in rt.OfType<JsonObject>().Where(e => (e.Str("rule") is "*" or "") && e.Str("parent").Length == 0 && e.Str("signer").Length == 0 &&
                                                              Ps.Match(Ps.Leaf(e.Str("image")), "^(pwsh|powershell|powershell_ise)\\.exe$")).ToList()) rt.Remove(e);
        if (rt.Count != before) log.Warn($"Removed {before - rt.Count} allow(s) of PowerShell itself for all rules - use Trusted apps instead");
        var rp = (JsonArray)x["realtimePath"]!;
        foreach (var e in rp.OfType<JsonObject>().Where(e => Ps.Match(e.Str("prefix"), @"\\(Epic Games|Epic|FreeEDR|EDR)\\$|\\AppData\\Local\\(EpicGamesLauncher|FortniteGame)\\$")).ToList()) rp.Remove(e);

        void AddProfile(AllowProfile p)
        {
            foreach (var op in Profiles.Ops(p))
            {
                var entry = new JsonObject { ["id"] = Guid.NewGuid().ToString("N"), ["added"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) };
                foreach (var (k, v) in op) if (k is not ("action" or "blade")) entry[k] = v?.DeepClone();
                ((JsonArray)x[op.Str("blade")]!).Add((JsonNode)entry);
            }
        }
        bool HasProfile(string id) => new[] { "realtime", "sigma" }.Any(l => ((JsonArray)x[l]!).OfType<JsonObject>().Any(e => e.Str("profile") == id));
        if (!cfg.AllowProfilesInitialized)
        {
            foreach (var p in Profiles.All.Where(p => p.Default && Profiles.IsInstalled(p))) { AddProfile(p); log.Ok($"Trusted app: {p.Name}"); }
            cfg.AllowProfilesInitialized = true;
        }
        else
        {
            foreach (var id in new[] { "claude-code", "vcpkg", "antigravity" })
            {
                if (!HasProfile(id) || Profiles.Get(id) is not { } p) continue;
                foreach (var l in new[] { "realtime", "sigma" }) foreach (var e in ((JsonArray)x[l]!).OfType<JsonObject>().Where(e => e.Str("profile") == id).ToList()) ((JsonArray)x[l]!).Remove(e);
                AddProfile(p);
            }
            foreach (var p in Profiles.All.Where(p => p.Id is ("wpbbin" or "freeedr-build" or "edge" or "zoom" or "teams" or "slack" or "webex" or "vscode" or "git" or "docker" or "chrome" or "dropbox") && p.Default && Profiles.IsInstalled(p) && !HasProfile(p.Id))) { AddProfile(p); log.Ok($"Trusted app: {p.Name}"); }
            log.Ok("Trusted apps kept as you set them");
        }
        JsonFile.WriteAtomic(paths.ExclusionsFile, x);
        cfg.Save(paths.ConfigFile);
        log.Ok($"edr-config.json (Wail2Ban: {(cfg.Wail2Ban.Block ? "blocks attackers" : "report only")}, Defender: {cfg.DefenderMode})");
        var seed = Path.Combine(source, "seed", "ioc_sha256.txt");
        if (!File.Exists(paths.IocFile) && File.Exists(seed))
        {
            Directory.CreateDirectory(paths.RulesDir);
            File.Copy(seed, paths.IocFile);
            log.Ok($"Malware hash list from the setup package ({File.GetLastWriteTime(seed):yyyy-MM-dd}; every scan updates it)");
        }
        if (!File.Exists(paths.IocFile))
        {
            try
            {
                var tmp = Path.Combine(paths.DownloadDir, "ioc-init.txt");
                Directory.CreateDirectory(paths.DownloadDir);
                new Tools(paths).Download(cfg.IocFeedUrl, tmp).GetAwaiter().GetResult();
                if (new FileInfo(tmp).Length >= 1000) { File.Move(tmp, paths.IocFile, true); log.Ok("Initial malware hash list downloaded"); }
            }
            catch (Exception e) when (e is IOException or HttpRequestException) { log.Warn($"Initial malware hash list: {e.Message} (the first scan retries)"); }
        }
        if (!Sys.EventSourceExists(EdrPaths.EventSource)) Sys.CreateEventSource(EdrPaths.EventSource);
    }

    private void UserFoldersAndAcl()
    {
        log.Step($"Locking down {paths.Root}");
        var icacls = Sys.Sys32("icacls.exe");
        foreach (var (sid, _) in AccountsList())
        {
            var d = paths.UserStateDir(sid);
            Directory.CreateDirectory(d);
        }
        Sys.Run(icacls, paths.Root, "/setowner", $"*{EdrPaths.AdminsSid}", "/T", "/C", "/Q");
        Sys.Run(icacls, paths.Root, "/reset", "/C", "/Q");
        var (rc, _) = Sys.Run(icacls, paths.Root, "/inheritance:r", "/grant:r", $"*{EdrPaths.AdminsSid}:(OI)(CI)F", $"*{EdrPaths.SystemSid}:(OI)(CI)F", $"*{EdrPaths.UsersSid}:(OI)(CI)RX");
        if (rc != 0) throw new IOException($"icacls on {paths.Root} failed");
        Sys.Run(icacls, Path.Combine(paths.Root, "*"), "/reset", "/T", "/C", "/Q");
        Sys.Run(icacls, paths.InboxDir, "/grant", $"*{EdrPaths.UsersSid}:(OI)(CI)(W,D)");
        Sys.Run(icacls, paths.UserDir, "/inheritance:r", "/grant:r", $"*{EdrPaths.AdminsSid}:(OI)(CI)F", $"*{EdrPaths.SystemSid}:(OI)(CI)F", $"*{EdrPaths.UsersSid}:(RX)");
        foreach (var (sid, _) in AccountsList()) Sys.Run(icacls, paths.UserStateDir(sid), "/grant", $"*{sid}:(OI)(CI)M");
        if (Directory.Exists(paths.QuarantineDir)) Sys.Run(icacls, paths.QuarantineDir, "/inheritance:r", "/grant:r", $"*{EdrPaths.SystemSid}:(OI)(CI)F", $"*{EdrPaths.AdminsSid}:(OI)(CI)F");
        log.Ok("Admins + SYSTEM: full | every account: read-only | inbox\\: resume/scan requests | user\\<SID>\\: each account its own tray files");
    }

    private static List<(string Sid, string Profile)> AccountsList()
    {
        var list = new List<(string, string)>();
        using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
        if (k is null) return list;
        foreach (var sid in k.GetSubKeyNames().Where(s => Ps.Rx(@"^S-1-(5-21|12-1)-[\d-]+$").IsMatch(s)))
        {
            using var s = k.OpenSubKey(sid);
            var p = Environment.ExpandEnvironmentVariables(s?.GetValue("ProfileImagePath") as string ?? "");
            if (p.Length > 0 && Directory.Exists(p)) list.Add((sid, p));
        }
        return list;
    }

    private void DefenderAndFirewall()
    {
        var cfg = EdrConfig.Load(paths.ConfigFile);
        log.Step($"Microsoft Defender ({(cfg.DefenderMode == "audit" ? "audit mode: reported, never blocked" : "left as it is")})");
        var games = Defender.GameExes().ToList();
        if (cfg.DefenderMode == "audit") foreach (var n in Defender.ApplyAudit(JsonFile.ReadObject(paths.BaselineFile), games)) log.Note(n);
        else log.Ok("Defender settings unchanged (Settings > Microsoft Defender)");
        PowerShellRunner.Run("Add-MpPreference -ThreatIDDefaultAction_Ids 2147731250 -ThreatIDDefaultAction_Actions 6 -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess 'FreeEDR-Setup.exe' -ErrorAction SilentlyContinue");
        log.Step("Firewall");
        var r = PowerShellRunner.Run("$r = @(Get-NetFirewallRule -Name 'RemoteDesktop-Shadow-In-TCP' -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' }); if ($r.Count) { $r | Disable-NetFirewallRule; 'disabled' } else { 'closed' }");
        if (r.ExitCode == 0) log.Ok(r.Output.Trim() == "disabled" ? "\"Remote Desktop - Shadow (TCP-In)\" disabled (session shadowing is not used)" : "Remote Desktop shadowing already closed");
        else log.Warn($"Remote Desktop shadow firewall rule: {r.Error.Trim()}");
        var managed = JsonFile.ReadObject(paths.ManagedFile) ?? new JsonObject();
        JsonFile.WriteAtomic(paths.ManagedFile, new JsonObject
        {
            ["asrRules"] = Defender.AsrRules.Concat((managed["asrRules"] as JsonArray)?.Select(Ps.Str) ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToJsonArray(),
            ["cfaApps"] = games.Concat((managed["cfaApps"] as JsonArray)?.Select(Ps.Str) ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToJsonArray(),
            ["shortcuts"] = new[] { Path.Combine(Sys.CommonPrograms, "FreeEDR.lnk"), Path.Combine(Sys.CommonDesktop, "FreeEDR.lnk") }.Concat((managed["shortcuts"] as JsonArray)?.Select(Ps.Str) ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToJsonArray(),
            ["services"] = new[] { EdrPaths.ServiceName }.ToJsonArray(),
            ["tasks"] = OldTasks.Take(2).Concat((managed["tasks"] as JsonArray)?.Select(Ps.Str) ?? []).Distinct().ToJsonArray(),
        });
    }

    private void ServiceAndTray()
    {
        log.Step($"Windows service \"{EdrPaths.ServiceName}\" (LocalSystem, automatic start, restarts on failure)");
        Services.CreateOrUpdate(EdrPaths.ServiceName, "FreeEDR engine", "FreeEDR: detect-only EDR (Sysmon, YARA/IOC, Sigma, CVE) and Wail2Ban. Dashboard: FreeEDR in the Start menu.",
                                $"\"{paths.EnginePath}\"", EdrPaths.EnginePrivileges, serviceSid: true);
        log.Ok($"Service registered: {paths.EnginePath}");
        log.Ok($"Least privilege: the engine keeps only {string.Join(", ", EdrPaths.EnginePrivileges)}");

        log.Step("Tray auto-start and shortcuts (every account)");
        using (var run = Registry.LocalMachine.CreateSubKey(EdrPaths.RunKey)) run.SetValue(EdrPaths.RunValue, $"\"{paths.TrayPath}\"");
        Sys.ForEachUserHive(h => { using var k = h.OpenSubKey(EdrPaths.RunKey, writable: true); k?.DeleteValue(EdrPaths.RunValue, false); k?.DeleteValue("EDR Tray", false); });
        var start = Path.Combine(Sys.CommonPrograms, "FreeEDR.lnk");
        var desk = Path.Combine(Sys.CommonDesktop, "FreeEDR.lnk");
        Shortcut(start);
        if (opt.NoDesktopIcon) { JsonFile.TryDelete(desk); log.Ok("No desktop icon (as chosen)"); } else { Shortcut(desk); log.Ok("Desktop icon \"FreeEDR\" for all users"); }
        log.Ok("The tray starts at every sign-in; \"FreeEDR\" is in the Start menu of every account");
    }

    private void Shortcut(string lnk)
    {
        var r = PowerShellRunner.Run("""
            $s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:EDR_LNK)
            $s.TargetPath = $env:EDR_TARGET; $s.Arguments = '--show'; $s.WorkingDirectory = $env:EDR_DIR
            $s.IconLocation = "$env:EDR_TARGET,0"; $s.Description = 'FreeEDR dashboard'; $s.Save()
            """, new Dictionary<string, string> { ["EDR_LNK"] = lnk, ["EDR_TARGET"] = paths.TrayPath, ["EDR_DIR"] = paths.TrayDir });
        if (r.ExitCode != 0) log.Warn($"Shortcut {lnk}: {r.Error.Trim()}");
    }

    private bool Verify(out List<string> failed)
    {
        failed = [];
        var stamp = DateTime.Now;
        Services.Stop(EdrPaths.ServiceName, 30);
        Services.Start(EdrPaths.ServiceName, 30);
        JsonObject? st = null;
        for (var i = 0; i < 45; i++)
        {
            Thread.Sleep(2000);
            st = JsonFile.ReadObject(paths.StatusFile);
            if (st is not null && Ps.ToDate(st.Str("engineStarted")) is { } es && es >= stamp.AddSeconds(-5) && Ps.ToDate(st.Str("heartbeat")) is { } hb && (DateTime.Now - hb).TotalSeconds < 30) break;
            st = null;
        }
        string S(string blade, string key = "state") => (st?[blade] as JsonObject)?.Str(key) ?? "unknown";
        var svcOk = Services.Query("Sysmon64") == Services.State.Running;
        var yarc = File.Exists(paths.CompiledYara) && new FileInfo(paths.CompiledYara).Length > 0;
        var missing = Tools.Pinned.Where(t => !File.Exists(Path.Combine(paths.BinDir, t.Exe))).Select(t => t.Name).ToList();
        var checks = new (string Name, bool Ok, string Detail)[]
        {
            ("Engine service & heartbeat", st is not null, st is not null ? $"Heartbeat {st.Str("heartbeat")}, lag {st.Str("lagSeconds")}s" : "no fresh heartbeat within 90 s"),
            ("Real-time detection (Sysmon)", S("edr") == "on" && svcOk, $"Sysmon service: {(svcOk ? "running" : "DOWN")}, state: {S("edr")}"),
            ("Wail2Ban (failed sign-ins)", S("wail2ban") == "on", $"state: {S("wail2ban")}{(S("wail2ban", "error") is { Length: > 0 } e ? ", " + e : "")}"),
            ("Anti-Malware (YARA & IOC)", S("malware") == "on" && yarc, $"state: {S("malware")}, rules compiled: {(yarc ? "yes" : "NO")}"),
            ("Sigma event-log scan", S("sigma") == "on" && File.Exists(paths.HayabusaExe), $"state: {S("sigma")}, Hayabusa: {(File.Exists(paths.HayabusaExe) ? "ready" : "missing")}"),
            ("Vulnerability scan", S("cve") == "on" && File.Exists(paths.OsvExe), $"state: {S("cve")}, OSV-Scanner: {(File.Exists(paths.OsvExe) ? "ready" : "missing")}"),
            ("All tools present", missing.Count == 0, missing.Count == 0 ? $"{Tools.Pinned.Length} tools in bin\\" : $"missing: {string.Join(", ", missing)}"),
        };
        foreach (var c in checks)
        {
            if (c.Ok) log.Ok($"{c.Name}: {c.Detail}");
            else { log.Warn($"{c.Name}: {c.Detail} - FAILED"); failed.Add(c.Name); }
        }
        return failed.Count == 0;
    }

    private void CleanupOldVersion()
    {
        log.Step("Removing what older versions left behind");
        foreach (var t in OldTasks) if (Sys.TaskExists(t) && Sys.TaskDelete(t)) log.Ok($"Deleted the scheduled task '{t}'");
        foreach (var s in OldScripts.Select(n => Path.Combine(paths.Root, n)).Where(File.Exists)) { JsonFile.TryDelete(s); }
        foreach (var d in new[] { @"C:\EDR", @"C:\LocalEDR", @"C:\Wail2Ban" }.Where(Directory.Exists))
            try { Directory.Delete(d, true); log.Ok($"Deleted {d}"); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { log.Warn($"Could not delete {d}: {e.Message}"); }
        log.Ok("PowerShell scripts of the previous version removed");
    }

    private bool Rollback()
    {
        if (_backup is null || !Directory.Exists(_backup)) return false;
        log.Step("Verification failed - rolling back to the previous version");
        try
        {
            Services.Stop(EdrPaths.ServiceName, 30);
            if (Directory.Exists(Path.Combine(_backup, "bin"))) CopyTree(Path.Combine(_backup, "bin"), paths.BinDir);
            foreach (var s in Directory.GetFiles(_backup, "*.ps1")) File.Copy(s, Path.Combine(paths.Root, Path.GetFileName(s)), true);
            foreach (var (dir, to) in new[] { ("config", paths.ConfigDir), ("rules", paths.RulesDir), ("docs", paths.DocsDir) })
                if (Directory.Exists(Path.Combine(_backup, dir))) CopyTree(Path.Combine(_backup, dir), to);
            foreach (var name in new[] { "version.txt", "README.md" })
                if (File.Exists(Path.Combine(_backup, name))) File.Copy(Path.Combine(_backup, name), Path.Combine(paths.Root, name), true);
            JsonFile.TryDelete(paths.CompiledYara);
            if (File.Exists(Path.Combine(_backup, "config", "sysmonconfig.xml"))) Tools.RunCapture(Path.Combine(EdrPaths.SystemRoot, "Sysmon64.exe"), ["-c", paths.SysmonConfig], timeoutSeconds: 120);
            if (_fromPowerShell)
            {
                Services.Stop(EdrPaths.ServiceName, 30);
                Services.Delete(EdrPaths.ServiceName);
                Sys.TaskEnable(OldTask);
                using var run = Registry.LocalMachine.CreateSubKey(EdrPaths.RunKey);
                run.SetValue(EdrPaths.RunValue, $"\"{EdrPaths.WindowsPowerShell}\" -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File \"{paths.Root}\\EDR-Tray.ps1\"");
            }
            else Services.Start(EdrPaths.ServiceName, 30);
            JsonFile.TryDelete(paths.UpgradePendingFile);
            log.Ok($"Previous version restored: programs, settings, rules, tools, version {(File.Exists(paths.VersionFile) ? File.ReadAllText(paths.VersionFile).Trim() : "?")}");
            return true;
        }
        catch (Exception e) { log.Warn($"Roll-back incomplete: {e.GetType().Name}: {e.Message} (run Setup again: it rolls back from the same backup)"); return false; }
    }

    private void RecordInstalledSize()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(EdrPaths.SetupUninstallKey, writable: true);
            if (key is null || !Directory.Exists(paths.Root)) return;
            var bytes = new DirectoryInfo(paths.Root).EnumerateFiles("*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }).Sum(f => f.Length);
            key.SetValue("EstimatedSize", (int)Math.Min(int.MaxValue, bytes / 1024), RegistryValueKind.DWord);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { log.Warn($"Installed size not recorded: {e.Message}"); }
    }

    private void StartTrays(string title, string text, string level)
    {
        _traysStarted = true;
        log.Step("Starting the tray for the signed-in users");
        var r = PowerShellRunner.Run("""
            $name = 'FreeEDR tray start'
            $users = ([Security.Principal.SecurityIdentifier]'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value
            $act  = New-ScheduledTaskAction -Execute $env:EDR_TRAY -Argument ('--toast-title "{0}" --toast-text "{1}" --toast-level {2}' -f $env:EDR_T, $env:EDR_X, $env:EDR_L) -WorkingDirectory $env:EDR_DIR
            $prin = New-ScheduledTaskPrincipal -GroupId $users -RunLevel Limited
            $set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances Parallel -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
            Register-ScheduledTask -TaskName $name -Action $act -Principal $prin -Settings $set -Force | Out-Null
            Start-ScheduledTask -TaskName $name; Start-Sleep -Seconds 3
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            """, new Dictionary<string, string> { ["EDR_TRAY"] = paths.TrayPath, ["EDR_DIR"] = paths.TrayDir, ["EDR_T"] = title.Replace("\"", "'"), ["EDR_X"] = text.Replace("\"", "'"), ["EDR_L"] = level });
        if (r.ExitCode == 0) log.Ok("Tray started for the signed-in users (unelevated)"); else log.Warn($"Could not start the tray now ({r.Error.Trim()}) - it starts at the next sign-in");
    }

    private static void CopyTree(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var d in Directory.GetDirectories(from, "*", SearchOption.AllDirectories)) Directory.CreateDirectory(Path.Combine(to, Path.GetRelativePath(from, d)));
        foreach (var f in Directory.GetFiles(from, "*", SearchOption.AllDirectories)) File.Copy(f, Path.Combine(to, Path.GetRelativePath(from, f)), true);
    }
}
