using Edr.Core.Native;
using Xunit;

namespace Edr.Core.Tests;

public class SignerTests
{
    private static readonly AuthenticodeSigners Signers = new();

    [Fact]
    public void Embedded_signature_gives_the_publisher()
    {
        // pwsh.exe carries an embedded Microsoft signature on every PowerShell 7 install
        var pwsh = @"C:\Program Files\PowerShell\7\pwsh.exe";
        Assert.SkipUnless(File.Exists(pwsh), "PowerShell 7 not installed");
        Assert.Equal("Microsoft Corporation", Signers.SignerOf(pwsh));
    }

    [Fact]
    public void Unsigned_or_missing_files_have_no_publisher()
    {
        var tmp = Path.Combine(AppContext.BaseDirectory, $"unsigned-{Guid.NewGuid():N}.exe");   // inside the dev folder, not %TEMP%
        File.WriteAllBytes(tmp, [0x4D, 0x5A, 0, 0]);
        try { Assert.Null(Signers.SignerOf(tmp)); }
        finally { File.Delete(tmp); }
        Assert.Null(Signers.SignerOf(@"C:\does\not\exist.exe"));
        Assert.Null(Signers.SignerOf(""));
    }
}
