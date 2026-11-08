namespace EdrBuild;

internal sealed class BuildLog(string path) : IDisposable
{
    private readonly List<string> _lines = [];
    private int _warnings;
    private bool _closed;

    public void Info(string text) => Write(text, null);
    public void Banner(string text) => Write(text, ConsoleColor.Cyan);
    public void Success(string text) => Write(text, ConsoleColor.Green);
    public void Warn(string text) { _warnings++; Write("WARN: " + text, ConsoleColor.Yellow); }
    public void Error(string text) => Write("ERROR: " + text, ConsoleColor.Red);

    public void Child(string text) => Write("    " + text, ConsoleColor.DarkGray);

    private void Write(string text, ConsoleColor? color)
    {
        _lines.Add($"{DateTime.Now:HH:mm:ss} {text}");
        if (color is { } c) Console.ForegroundColor = c;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    public void Close(bool ok, TimeSpan took)
    {
        if (_closed) return;
        _closed = true;
        var verdict = !ok ? "FAIL" : _warnings > 0 ? $"WARN ({_warnings} warning(s))" : "OK";
        try { File.WriteAllLines(path, [$"{verdict}  {DateTime.Now:yyyy-MM-dd HH:mm:ss}  took {took:mm\\:ss}", "", .. _lines]); }
        catch (IOException) { }
    }

    public void Dispose() => Close(false, TimeSpan.Zero);
}
