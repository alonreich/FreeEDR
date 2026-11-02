namespace Edr.Core;

/// <summary>
/// File locations shared with the engine (EDR-Common.ps1). Everything FreeEDR keeps is under <see cref="Root"/>
/// (C:\Program Files\FreeEDR); the tray only writes to its own <see cref="LocalDir"/> (user\) and inbox\.
/// </summary>
public sealed class EdrPaths
{
    public EdrPaths(string? root = null, string? localDir = null)
    {
        Root = root ?? DefaultRoot;
        LocalDir = localDir ?? Path.Combine(Root, "user");
    }

    /// <summary>C:\Program Files\FreeEDR - the 64-bit Program Files folder, as $Root in EDR-Common.ps1.</summary>
    public static string DefaultRoot =>
        Path.Combine(Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FreeEDR");

    public string Root { get; }
    public string LocalDir { get; }

    public string ConfigDir => Path.Combine(Root, "config");
    public string DataDir => Path.Combine(Root, "data");
    public string InboxDir => Path.Combine(Root, "inbox");
    public string ControlScript => Path.Combine(Root, "EDR-Control.ps1");

    public string StatusFile => Path.Combine(DataDir, "status.json");
    public string EventsFile => Path.Combine(DataDir, "events.jsonl");
    public string ScanResultFile => Path.Combine(DataDir, "scan-result.json");
    public string CveFile => Path.Combine(DataDir, "cve-current.json");
    public string ExclusionsFile => Path.Combine(ConfigDir, "exclusions.json");
    public string BlocklistFile => Path.Combine(ConfigDir, "blocklist.json");
    public string SysmonConfig => Path.Combine(ConfigDir, "sysmonconfig.xml");

    public string ReviewedFile => Path.Combine(LocalDir, "reviewed.txt");
    public string IgnoredAppsFile => Path.Combine(LocalDir, "ignored-apps.txt");
    public string HistoryFile => Path.Combine(LocalDir, "history.json");
    public string TrayLog => Path.Combine(LocalDir, "tray.log");
}
