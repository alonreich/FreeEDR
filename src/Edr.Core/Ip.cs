using System.Net;
using System.Net.Sockets;

namespace Edr.Core;

/// <summary>IP helpers of EDR-Common.ps1 (Test-IpInCidr, Test-PrivateIp).</summary>
public static class Ip
{
    private static readonly string[] PrivateRanges =
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"];

    public static bool InCidr(string? ip, string? cidr)
    {
        var parts = (cidr ?? "").Trim().Split('/');
        if (!IPAddress.TryParse(ip, out var a) || !IPAddress.TryParse(parts[0], out var n)) return false;
        if (a.AddressFamily != n.AddressFamily) return false;
        if (parts.Length < 2) return a.Equals(n);
        if (!int.TryParse(parts[1], out var bits)) return false;
        var ab = a.GetAddressBytes();
        var nb = n.GetAddressBytes();
        for (var i = 0; i < ab.Length; i++)
        {
            var take = Math.Min(8, Math.Max(0, bits - 8 * i));
            if (take == 0) break;
            var mask = (byte)((0xFF << (8 - take)) & 0xFF);
            if ((ab[i] & mask) != (nb[i] & mask)) return false;
        }
        return true;
    }

    public static bool IsPrivate(string? ip) => PrivateRanges.Any(r => InCidr(ip, r));

    /// <summary>Get-NetLabel of the tray.</summary>
    public static string NetLabel(string? ip) => IsPrivate(ip) ? "Private / LAN" : "Public internet";

    public static bool IsV6(string? ip) => IPAddress.TryParse(ip, out var a) && a.AddressFamily == AddressFamily.InterNetworkV6;
}
