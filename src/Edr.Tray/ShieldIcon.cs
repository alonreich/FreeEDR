using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;

namespace Edr.Tray;

/// <summary>Shield states: protected (green check), attention (amber !), paused (grey pause), broken (red X).</summary>
public enum ShieldState { Protected, Attention, Paused, Broken }

/// <summary>Draws the shield at runtime (no image files to ship): a soft gradient shield with a white glyph.</summary>
public static class ShieldIcon
{
    private static readonly Geometry Shield = Geometry.Parse("M16,1.5 L28.5,6 L28.5,15 C28.5,22.8 23,28 16,30.5 C9,28 3.5,22.8 3.5,15 L3.5,6 Z");
    private static readonly Dictionary<(ShieldState, int), RenderTargetBitmap> Cache = [];

    public static (Color Top, Color Bottom) Colors(ShieldState s) => s switch
    {
        ShieldState.Protected => (Color.Parse("#3DDC8A"), Color.Parse("#1E9E5C")),
        ShieldState.Attention => (Color.Parse("#FFC24D"), Color.Parse("#E08A0B")),
        ShieldState.Paused => (Color.Parse("#AEB9CC"), Color.Parse("#6F7C95")),
        _ => (Color.Parse("#FF6B78"), Color.Parse("#C9303F")),
    };

    public static RenderTargetBitmap Bitmap(ShieldState state, int size = 32)
    {
        if (Cache.TryGetValue((state, size), out var c)) return c;
        var (top, bottom) = Colors(state);
        var bmp = new RenderTargetBitmap(new PixelSize(size, size), new Vector(96, 96));
        using (var ctx = bmp.CreateDrawingContext())
        using (ctx.PushTransform(Matrix.CreateScale(size / 32.0, size / 32.0)))
        {
            var fill = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative), EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                GradientStops = { new GradientStop(top, 0), new GradientStop(bottom, 1) },
            };
            ctx.DrawGeometry(fill, new Pen(new SolidColorBrush(Color.FromArgb(0xCC, 255, 255, 255)), 1.2), Shield);
            var pen = new Pen(Brushes.White, 3.2, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
            switch (state)
            {
                case ShieldState.Protected:
                    ctx.DrawLine(pen, new Point(10.5, 16), new Point(14.5, 20));
                    ctx.DrawLine(pen, new Point(14.5, 20), new Point(21.5, 11.5));
                    break;
                case ShieldState.Attention:
                    ctx.DrawLine(pen, new Point(16, 9.5), new Point(16, 17.5));
                    ctx.DrawEllipse(Brushes.White, null, new Point(16, 22.5), 1.9, 1.9);
                    break;
                case ShieldState.Paused:
                    ctx.DrawLine(pen, new Point(13, 10.5), new Point(13, 21.5));
                    ctx.DrawLine(pen, new Point(19, 10.5), new Point(19, 21.5));
                    break;
                default:
                    ctx.DrawLine(pen, new Point(11.5, 11), new Point(20.5, 21));
                    ctx.DrawLine(pen, new Point(20.5, 11), new Point(11.5, 21));
                    break;
            }
        }
        Cache[(state, size)] = bmp;
        return bmp;
    }

    public static WindowIcon Create(ShieldState state, int size = 32)
    {
        var ms = new MemoryStream();
        Bitmap(state, size).Save(ms, PngBitmapEncoderOptions.Default);
        ms.Position = 0;
        return new WindowIcon(ms);
    }

    public static void SavePng(ShieldState state, int size, string path)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var fs = File.Create(path);
            Bitmap(state, size).Save(fs, PngBitmapEncoderOptions.Default);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    public static ShieldState From(string overallKey) => overallKey switch
    {
        "ok" => ShieldState.Protected, "attention" => ShieldState.Attention, "paused" => ShieldState.Paused, _ => ShieldState.Broken,
    };
}
