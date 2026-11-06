namespace Edr.Core;

/// <summary>Compares Python package versions by their numeric parts ("2.31.0" &lt; "2.32.1"; "1.0" == "1.0.0").</summary>
public static class PyVersion
{
    public static long[] Parts(string v) => Ps.Rx(@"\d+").Matches(v ?? "").Select(m => long.TryParse(m.Value, out var n) ? n : 0).ToArray();

    public static int Compare(string a, string b)
    {
        var x = Parts(a);
        var y = Parts(b);
        for (var i = 0; i < Math.Max(x.Length, y.Length); i++)
        {
            var p = i < x.Length ? x[i] : 0;
            var q = i < y.Length ? y[i] : 0;
            if (p != q) return p > q ? 1 : -1;
        }
        return 0;
    }
}
