namespace Edr.Core;

public sealed class EdrPaths
{
    public EdrPaths(string? root = null, string? localDir = null)
    {
        Root = root ?? DefaultRoot;
        LocalDir = localDir ?? Path.Combine(Root, "user", CurrentUserSid);
    }

    public const string ProductName = "FreeEDR";
    public const string ServiceName = "FreeEDR";
    public const string EngineMutex = @"Global\FreeEDR-Engine";
    public const string EventSource = "wail2ban";
    public const string FwRulePrefix = "a a a wail2ban block IP:";
    public const string FwGroup = "EDR Wail2Ban";
    public const string UsersSid = "S-1-5-32-545";
    public const string AdminsSid = "S-1-5-32-544";
    public const string SystemSid = "S-1-5-18";
    public const string SetupUninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6F0E2C1A-4B7D-4E59-9A33-0E2D5C8B7A41}_is1";
    public const string FinishRemovalKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FreeEDR-FinishRemoval";
    public const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    public const string RunValue = "FreeEDR Tray";
    public const string EngineExe = "FreeEDR-Engine.exe";
    public const string ControlExe = "FreeEDR-Control.exe";
    public const string InstallerExe = "FreeEDR-Installer.exe";
    public const string TrayExe = "FreeEDR-Tray.exe";

    public static readonly string[] EnginePrivileges =
        ["SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeSecurityPrivilege"];

    public static string CurrentUserSid
    {
        get
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return id.User?.Value ?? "unknown";
        }
    }

    public static string DefaultRoot => Path.Combine(ProgramFiles, ProductName);

    public static string ProgramFiles => Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    public static string ProgramFilesX86 => Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? ProgramFiles + " (x86)";
    public static string SystemRoot => Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
    public static string System32 => Path.Combine(SystemRoot, "System32");
    public static string WindowsPowerShell => Path.Combine(System32, "WindowsPowerShell", "v1.0", "powershell.exe");

    public static string ProfilesRoot
    {
        get
        {
            try
            {
                using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
                if (k?.GetValue("ProfilesDirectory") is string s && s.Length > 0) return Environment.ExpandEnvironmentVariables(s);
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
            return Path.Combine(Path.GetPathRoot(SystemRoot) ?? @"C:\", "Users");
        }
    }

    public string Root { get; }
    public string LocalDir { get; }

    public string BinDir => Path.Combine(Root, "bin");
    public string TrayDir => Path.Combine(BinDir, "tray");
    public string ConfigDir => Path.Combine(Root, "config");
    public string DataDir => Path.Combine(Root, "data");
    public string RulesDir => Path.Combine(Root, "rules");
    public string ControlDir => Path.Combine(Root, "control");
    public string InboxDir => Path.Combine(Root, "inbox");
    public string UserDir => Path.Combine(Root, "user");
    public string QuarantineDir => Path.Combine(Root, "quarantine");
    public string DownloadDir => Path.Combine(DataDir, "download");
    public string DocsDir => Path.Combine(Root, "docs");

    public string ConfigFile => Path.Combine(ConfigDir, "edr-config.json");
    public string StatusFile => Path.Combine(DataDir, "status.json");
    public string StateFile => Path.Combine(DataDir, "state.json");
    public string EventsFile => Path.Combine(DataDir, "events.jsonl");
    public string StrikesFile => Path.Combine(DataDir, "wail2ban_strikes.txt");
    public string BookmarksFile => Path.Combine(DataDir, "bookmarks.json");
    public string EngineLog => Path.Combine(DataDir, "engine.log");
    public string ScanLog => Path.Combine(DataDir, "scan.log");
    public string ScanResultFile => Path.Combine(DataDir, "scan-result.json");
    public string CveFile => Path.Combine(DataDir, "cve-current.json");
    public string BaselineFile => Path.Combine(DataDir, "preinstall.json");
    public string ManagedFile => Path.Combine(DataDir, "managed.json");
    public string UpgradePendingFile => Path.Combine(DataDir, "upgrade-pending.json");
    public string CompiledYara => Path.Combine(DataDir, "rules.yarc");
    public string ExclusionsFile => Path.Combine(ConfigDir, "exclusions.json");
    public string BlocklistFile => Path.Combine(ConfigDir, "blocklist.json");
    public string SysmonConfig => Path.Combine(ConfigDir, "sysmonconfig.xml");
    public string SysmonTemplate => Path.Combine(ConfigDir, "sysmonconfig.template.xml");
    public string IocFile => Path.Combine(RulesDir, "ioc_sha256.txt");
    public string VersionFile => Path.Combine(Root, "version.txt");
    public string InstallLog => Path.Combine(Root, "install.log");

    public string EnginePath => Path.Combine(BinDir, EngineExe);
    public string ControlPath => Path.Combine(BinDir, ControlExe);
    public string InstallerPath => Path.Combine(BinDir, InstallerExe);
    public string TrayPath => Path.Combine(TrayDir, TrayExe);
    public string YaraExe => Path.Combine(BinDir, "yara64.exe");
    public string YaracExe => Path.Combine(BinDir, "yarac64.exe");
    public string HayabusaDir => Path.Combine(BinDir, "hayabusa");
    public string HayabusaExe => Path.Combine(HayabusaDir, "hayabusa.exe");
    public string OsvExe => Path.Combine(BinDir, "osv-scanner.exe");
    public string VelociraptorExe => Path.Combine(BinDir, "velociraptor.exe");

    public string UserStateDir(string sid) => Path.Combine(UserDir, sid);

    public string ReviewedFile => Path.Combine(LocalDir, "reviewed.txt");
    public string IgnoredAppsFile => Path.Combine(LocalDir, "ignored-apps.txt");
    public string HistoryFile => Path.Combine(LocalDir, "history.json");
    public string PreferencesFile => Path.Combine(LocalDir, "preferences.json");
    public string WingetFile => Path.Combine(LocalDir, "winget.txt");
    public string TrayLog => Path.Combine(LocalDir, "tray.log");
}
