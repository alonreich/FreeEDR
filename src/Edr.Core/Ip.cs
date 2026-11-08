using System.Net;
using System.Net.Sockets;

namespace Edr.Core;

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

    public static string? Normalize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var s = text.Trim().Trim('[', ']');
        var m = Ps.Rx(@"^::ffff:(\d{1,3}(\.\d{1,3}){3})$").Match(s);
        if (m.Success) s = m.Groups[1].Value;
        s = s.Split('%')[0];
        if (!(Ps.Rx(@"^\d{1,3}(\.\d{1,3}){3}$").IsMatch(s) || s.Contains(':'))) return null;
        return IPAddress.TryParse(s, out var ip) ? ip.ToString() : null;
    }

    public static bool IsValidCidr(string? cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr)) return false;
        var parts = cidr.Split('/');
        if (parts.Length > 2 || Normalize(parts[0]) is not { } baseIp) return false;
        if (parts.Length == 1) return true;
        if (!int.TryParse(parts[1], out var bits) || parts[1].Length > 3) return false;
        var max = baseIp.Contains(':') ? 128 : 32;
        return bits >= 0 && bits <= max;
    }

    public static string NetLabel(string? ip) => IsPrivate(ip) ? "Private / LAN" : "Public internet";
}
