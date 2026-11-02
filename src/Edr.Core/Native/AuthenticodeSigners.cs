using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace Edr.Core.Native;

/// <summary>
/// Publisher of a file with a valid embedded Authenticode signature (WinVerifyTrust, no UI, no revocation check),
/// as Get-AuthenticodeSignature reports it. Catalog-signed Windows files return null; the tray never allows
/// Microsoft's own publishers anyway (<see cref="Catalog.UnsafeSigners"/>).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class AuthenticodeSigners : ISignerLookup
{
    public string? SignerOf(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        try
        {
            if (!IsTrusted(path)) return null;
#pragma warning disable SYSLIB0057   // CreateFromSignedFile is the documented way to read the Authenticode signer
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            var name = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrEmpty(name) ? null : name;
        }
        catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool IsTrusted(string path)
    {
        var file = Marshal.StringToHGlobalUni(path);
        var fileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(new WinTrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(), pcwszFilePath = file }, fileInfo, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2,            // WTD_UI_NONE
                fdwRevocationChecks = 0,   // WTD_REVOKE_NONE
                dwUnionChoice = 1,         // WTD_CHOICE_FILE
                pFile = fileInfo,
                dwStateAction = 0,         // WTD_STATEACTION_IGNORE
                dwProvFlags = 0x1000,      // WTD_CACHE_ONLY_URL_RETRIEVAL: never go online
            };
            var action = GenericVerifyV2;
            return WinVerifyTrust(-1, ref action, ref data) == 0;   // INVALID_HANDLE_VALUE: no UI parent
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfo);
            Marshal.FreeHGlobal(file);
        }
    }

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [LibraryImport("wintrust.dll")]
    private static partial int WinVerifyTrust(nint hwnd, ref Guid pgActionId, ref WinTrustData pWVTData);

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public nint pcwszFilePath;
        public nint hFile;
        public nint pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public nint pPolicyCallbackData;
        public nint pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public nint pFile;
        public uint dwStateAction;
        public nint hWVTStateData;
        public nint pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public nint pSignatureSettings;
    }
}
