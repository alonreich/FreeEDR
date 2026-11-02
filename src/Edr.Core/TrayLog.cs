namespace Edr.Core;

/// <summary>Appends "yyyy-MM-dd HH:mm:ss text" lines to C:\Program Files\FreeEDR\user\tray.log, like Write-TrayLog. Never throws.</summary>
public sealed class TrayLog(string path)
{
    private readonly Lock _gate = new();

    public void Write(string text)
    {
        try
        {
            lock (_gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.AppendAllText(path, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {text}{Environment.NewLine}");
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
