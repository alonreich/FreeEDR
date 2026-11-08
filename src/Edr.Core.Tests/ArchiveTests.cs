using Edr.Core.Native;
using Edr.Engine;
using Xunit;

namespace Edr.Core.Tests;

public class ArchiveTests
{
    [Fact]
    public void Archive_appends_gzip_members_and_reads_every_record_back()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "archive", Guid.NewGuid().ToString("N"));
        var ctx = new Context(new EdrPaths(root, Path.Combine(root, "user", "x")));
        using var a = new EventArchive(ctx);
        var day = new DateTime(2026, 11, 6, 10, 0, 0);
        a.Append("security", "<Event><System><EventID>4624</EventID></System></Event>", day);
        a.Append("security", "<Event><Data>line1\r\nline2</Data></Event>", day);
        var file = Path.Combine(root, "data", "archive", "2026-11-06", "security.xml.gz");
        var lines = EventArchive.ReadFile(file).ToList();
        Assert.Equal(2, lines.Count);
        Assert.Contains("4624", lines[0]);
        Assert.Contains("line1&#13;&#10;line2", lines[1]);
        Assert.Equal(2, ctx.Paths.DataDir.Length > 0 ? (int)a.Status()["written"]!.GetValue<long>() : 0);
        Directory.Delete(root, true);
    }

    [Fact]
    public void Log_cleared_event_userdata_is_parsed()
    {
        const string xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><EventID>104</EventID><TimeCreated SystemTime="2026-11-06T15:25:37.2710000Z"/><Channel>System</Channel></System>
              <UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
                <SubjectUserName>alon</SubjectUserName><SubjectDomainName>ALON-DESKTOP</SubjectDomainName><Channel>Windows PowerShell</Channel>
              </LogFileCleared></UserData>
            </Event>
            """;
        var r = EventRecord.FromXml(xml)!;
        Assert.Equal(104, r.Id);
        Assert.Equal("alon", r["SubjectUserName"]);
        Assert.Equal("Windows PowerShell", r["Channel"]);
        Assert.Equal("System", r.Channel);
    }

    [Fact]
    public void Every_archived_log_has_a_valid_query()
    {
        Assert.All(EventArchive.Sources, s => Assert.True(s.XPath == "*" || s.XPath.StartsWith("*[System[(EventID=", StringComparison.Ordinal), s.Key));
        Assert.Equal(EventArchive.Sources.Length, EventArchive.Sources.Select(s => s.Key).Distinct().Count());
    }
}
