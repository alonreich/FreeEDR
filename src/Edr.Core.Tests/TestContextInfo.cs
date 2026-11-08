using System.Security.Principal;
using System.Text.Json.Nodes;
using Edr.Core.Native;
using Xunit;

namespace Edr.Core.Tests;

// Facts about the account the tests run under. The tests normally run unelevated on a developer PC; the release
// workflow runs them on a hosted runner as an elevated administrator, where some checks mean something else.
internal static class TestAccount
{
    public static bool Elevated { get; } = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public static bool IsSystem { get; } = WindowsIdentity.GetCurrent().User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;

    // A named pipe created by an elevated administrator is owned by BUILTIN\Administrators, not by the user.
    public static Func<SecurityIdentifier, bool> OwnsTestPipes(WindowsIdentity me) =>
        o => o == me.User || (Elevated && o.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));

    // The sandbox runs from SYSTEM (engine) and from an unelevated account (tray, these tests on a PC). From an
    // elevated non-SYSTEM session (a hosted CI runner) the restricted low-integrity child can fail to start; that
    // context is not one FreeEDR runs the sandbox in, so the test is skipped there, showing the child's exit code.
    public static void SkipIfSandboxCannotStartHere(Sandbox.Result r)
    {
        if (!Elevated || IsSystem) return;
        if (r.Started && r.Output.Length == 0 && r.Exit != 0)
            Assert.Skip($"elevated non-SYSTEM test session: the sandboxed program did not start (exit 0x{r.Exit:X8}); FreeEDR runs the sandbox as SYSTEM or unelevated, where this test runs");
    }
}

// Signatures for the golden model fixtures, recorded once from the PC that made the golden files
// (FREEEDR_RECORD_SIGNERS=1), so the result does not depend on which programs the test machine has.
internal sealed class FixtureSigners : ISignerLookup
{
    private readonly Dictionary<string, string?> _map = new(StringComparer.OrdinalIgnoreCase);
    private readonly ISignerLookup? _live;
    private readonly string _file;

    public FixtureSigners(string fixtureDir, bool record)
    {
        _file = Path.Combine(fixtureDir, "signers.json");
        _live = record ? new AuthenticodeSigners() : null;
        if (!record && File.Exists(_file) && JsonNode.Parse(File.ReadAllText(_file)) is JsonObject o)
            foreach (var (k, v) in o) _map[k] = v?.GetValue<string>();
    }

    public string? SignerOf(string path)
    {
        if (_live is null) return _map.TryGetValue(path, out var s) ? s : null;
        var got = _live.SignerOf(path);
        if (got is not null) _map[path] = got;
        return got;
    }

    public void Save(string sourceDir)
    {
        var o = new JsonObject();
        foreach (var (k, v) in _map.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase)) o[k] = v;
        File.WriteAllText(Path.Combine(sourceDir, "signers.json"), o.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }) + "\n");
    }
}
