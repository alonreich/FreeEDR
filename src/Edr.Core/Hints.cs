namespace Edr.Core;

public static class Hints
{
    public static readonly Dictionary<string, (string What, string Do)> Rules = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Encoded PowerShell command"] = ("PowerShell was started with a hidden (base64-encoded) command. Malware uses this to hide what it runs. Some legitimate tools also do it, for example AI coding assistants and installers.",
            "Look at \"Started by\". If it is a program you trust (for example claude.exe or an installer), allow everything it starts. Otherwise flag it and scan the program with Microsoft Defender."),
        ["PowerShell download or in-memory execution"] = ("PowerShell downloaded something or ran code straight from memory (DownloadString, Invoke-Expression, IEX, FromBase64String). This is the classic first step of a malware infection.",
            "If you did not just run a script yourself, check \"Started by\" and the command line. Allow it only if the parent program is one you trust."),
        ["Shadow copy or recovery tampering"] = ("Something tried to delete Windows backup snapshots or disable recovery. Ransomware does this right before encrypting files.",
            "URGENT unless you did this yourself: disconnect from the network, run a full Microsoft Defender scan, check the program and what started it."),
        ["Credential dumping tool"] = ("A command line contained commands of a well-known Windows password-stealing tool.",
            "URGENT: disconnect, run a Defender offline scan, change your passwords from another device."),
        ["LSASS memory dump"] = ("Something tried to dump the memory of LSASS, the Windows process that holds your passwords.",
            "URGENT unless you ran it yourself for debugging: disconnect, run a Defender offline scan, change passwords."),
        ["Code injected into LSASS"] = ("A program injected code into LSASS, the Windows process that holds your credentials.",
            "URGENT unless it is security software: disconnect and run a Defender offline scan."),
        ["LSASS memory read (credential theft)"] = ("A program opened LSASS (where Windows keeps credentials) with rights that allow reading passwords. Security and anti-cheat software sometimes do this too.",
            "If the program is antivirus, anti-cheat or a known Windows component, allow it. Otherwise treat it as urgent."),
        ["Defender tampering"] = ("A command tried to switch off or weaken Microsoft Defender.",
            "Unless you did this on purpose, treat it as urgent: check Windows Security settings and run a full scan."),
        ["Defender exclusion added"] = ("A new Microsoft Defender exclusion was added. Malware adds exclusions so Defender will not scan it.",
            "If you did not add it, open Windows Security > Virus & threat protection > Exclusions and remove it."),
        ["Event log cleared"] = ("Windows event logs were cleared. Attackers do this to hide their tracks.",
            "Unless you cleared them yourself, investigate: check other alerts around the same time."),
        ["Office app started a shell"] = ("Word/Excel/PowerPoint/Outlook started a command prompt or script engine. This is how malicious documents infect PCs.",
            "Close the document you just opened, do not enable macros, run a Defender scan."),
        ["Winlogon hijack"] = ("The Windows sign-in program settings (Winlogon) were changed. Malware uses this to run at every sign-in.",
            "Unless you just installed system software, investigate the value shown below."),
        ["Debugger hijack (IFEO)"] = ("A \"debugger\" was attached to a program through Image File Execution Options. Malware uses this to run instead of the real program.",
            "Check the registry path below. It is legitimate only for developer tools."),
        ["Unsigned driver loaded"] = ("A kernel driver without a valid signature was loaded. Rootkits and some cheats/hacking tools do this.",
            "If you did not just install hardware or development drivers, investigate the driver path."),
        ["mshta script execution"] = ("mshta.exe ran. It is a built-in Windows program that malware abuses to run scripts from web pages or files.",
            "Legitimate use is rare on a home PC. Check the command line and the program that started it."),
        ["certutil download or decode"] = ("certutil.exe (a certificate tool) was used to download or decode a file - a well-known malware trick.",
            "Investigate unless you ran it yourself."),
        ["regsvr32/rundll32 script abuse"] = ("regsvr32/rundll32 was used to run a script or load something from the internet - a well-known malware trick.",
            "Investigate unless you recognise the command."),
        ["bitsadmin download"] = ("bitsadmin.exe downloaded a file. Some installers do this, malware does too.", "Check the command line for the download address."),
        ["Script run from Downloads or Temp"] = ("A .js/.vbs script was run from Downloads or a temp folder. Email/web malware often arrives this way.",
            "If you did not open a script on purpose, delete it and run a Defender scan."),
        ["New user or admin group change"] = ("A user account was created or someone was added to the Administrators group.",
            "Unless you did this, treat it as urgent: check Settings > Accounts > Other users."),
        ["Windows script/LOLBin made a network connection"] = ("A Windows tool that normally never goes online (mshta, rundll32, certutil, ...) made a network connection. Malware uses these to download payloads.",
            "Check the destination address. Allow it only if you know the program."),
        ["Startup entry added or changed (Run key)"] = ("A program added or changed something that starts automatically when you sign in.",
            "Fine if you just installed or configured an app. Otherwise check the value - it shows what will start with Windows."),
        ["File added to a Startup folder"] = ("A file was placed in a Startup folder, so it will run every time you sign in.", "Fine if you just installed an app. Otherwise check the file name."),
        ["Scheduled task created from command line"] = ("A scheduled task was created with schtasks.exe. Installers do this; so does malware, to survive reboots.",
            "Check the command line for what the task runs."),
        ["Executable launched from Downloads"] = ("A program was started directly from your Downloads folder.", "Usually this is you running an installer. Only worry if you did not open it yourself."),
        ["WMI persistence"] = ("A permanent WMI event subscription was created. This is a stealthy way for malware to run automatically.",
            "Rare on a home PC - investigate unless you know the software that did it."),
        ["Command line imitates FreeEDR's own scripts"] = ("A command line pretends to be one of FreeEDR's own programs, which are never reported. Malware may try this to stay hidden.",
            "Investigate the program and what started it. Run a Microsoft Defender scan."),
    };

    public static readonly Dictionary<string, (string What, string Do)> Blades = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ioc"] = ("This program's file fingerprint (SHA256) is on a public list of known malware (Neo23x0 signature-base).",
            "Scan it with Microsoft Defender (button below), which can remove it. Then flag it so it stays on record."),
        ["yara"] = ("The program file matched a YARA pattern of known hacking tools or ransomware.",
            "Scan it with Microsoft Defender unless it is a security tool you installed on purpose (then allow it)."),
        ["sigma"] = ("The scheduled scan of the Windows event logs matched a Sigma rule rated high or critical. It describes something that was already logged, possibly hours ago.",
            "If it was you (installing software, admin work), ignore the rule. If not, confirm it as a threat and look for the program in the other lists."),
        ["wail2ban"] = ("A computer tried to sign in to this PC over the network (Remote Desktop / file sharing). After repeated failures Wail2Ban blocks the address in Windows Firewall for a while.",
            "If you do not know this address, ban it permanently. If it is one of your own devices, trust it."),
        ["cve"] = ("A Python package on this PC has a known security hole (CVE) that is fixed in a newer version.",
            "Click Update now: a window opens and installs the fixed version. \"Read about it\" opens the public advisory."),
        ["patch"] = ("A newer version is available. Updates often contain security fixes.", "Click Update now."),
        ["system"] = ("Status message from FreeEDR itself.", ""),
    };

    public static readonly Dictionary<string, (string What, string Do)> DefenderKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["malware"] = ("Microsoft Defender detected malware and handled it (usually quarantined).",
            "Nothing to do. Windows Security > Protection history shows the details. Only if you are sure it is a false alarm: allow it."),
        ["asr"] = ("Microsoft Defender attack surface reduction blocked a risky action.", "If this is a program you trust and need, allow it."),
        ["cfa"] = ("Controlled folder access (ransomware protection) blocked an app from changing files in your protected folders.", "If you trust the app, allow it."),
        ["asr-audit"] = ("Microsoft Defender attack surface reduction would have blocked this action. It runs in audit mode, so nothing was stopped.",
            "If this is a program you trust, allow it so it is no longer listed. Otherwise investigate the program."),
        ["cfa-audit"] = ("Controlled folder access (ransomware protection) would have stopped this app from changing files in your protected folders. It runs in audit mode, so the change went through.",
            "If you trust the app, allow it. If you do not know it, investigate - ransomware changes many files quickly."),
    };

    public static (string What, string Do) For(Rec? e)
    {
        if (e is null) return ("", "");
        if (e.T("rule") && Rules.TryGetValue(e.S("rule"), out var r)) return r;
        if (Ps.Eq(e.S("blade"), "defender") && DefenderKinds.TryGetValue(e.S("kind"), out var d)) return d;
        if (Ps.Eq(e.S("blade"), "wail2ban") && Ps.Eq(e.S("kind"), "login"))
            return ("Someone signed in to this PC from the internet with a valid password (Remote Desktop or file sharing).",
                    "If it was you (for example from your phone or another network), answer \"Yes, it was me\". If not, ban the address, change that account's password and limit Remote Desktop to your network or a VPN.");
        if (Ps.Eq(e.S("blade"), "realtime") && Rules.TryGetValue(e.S("title"), out var t)) return t;
        return Blades.TryGetValue(e.S("blade"), out var b) ? b : ("", "");
    }
}
