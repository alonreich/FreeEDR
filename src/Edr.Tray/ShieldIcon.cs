using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;

namespace Edr.Tray;

/// <summary>Tray shield states, as in EDR-Tray.ps1: green check, amber "!", grey pause, red X.</summary>
public enum ShieldState { Protected, Attention, Paused, Broken }

/// <summary>Draws the shield at runtime (no image files to ship).</summary>
public static class ShieldIcon
{
    private static readonly Geometry Shield = Geometry.Parse("M16,2 L28,6.5 L28,15 C28,22.5 22.5,27.5 16,30 C9.5,27.5 4,22.5 4,15 L4,6.5 Z");

    public static WindowIcon Create(ShieldState state, int size = 32)
    {
        var (fill, glyph) = state switch
        {
            ShieldState.Protected => (Color.FromRgb(46, 125, 50), "check"),
            ShieldState.Attention => (Color.FromRgb(239, 140, 0), "bang"),
            ShieldState.Paused => (Color.FromRgb(117, 117, 117), "pause"),
            _ => (Color.FromRgb(198, 40, 40), "cross"),
        };
        using var bmp = new RenderTargetBitmap(new PixelSize(size, size), new Vector(96, 96));
        using (var ctx = bmp.CreateDrawingContext())
        {
            using (ctx.PushTransform(Matrix.CreateScale(size / 32.0, size / 32.0)))
            {
                ctx.DrawGeometry(new SolidColorBrush(fill), new Pen(Brushes.White, 1.5), Shield);
                var pen = new Pen(Brushes.White, 3.2, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
                switch (glyph)
                {
                    case "check":
                        ctx.DrawLine(pen, new Point(10.5, 16), new Point(14.5, 20));
                        ctx.DrawLine(pen, new Point(14.5, 20), new Point(21.5, 11.5));
                        break;
                    case "bang":
                        ctx.DrawLine(pen, new Point(16, 9.5), new Point(16, 17.5));
                        ctx.DrawEllipse(Brushes.White, null, new Point(16, 22.5), 1.9, 1.9);
                        break;
                    case "pause":
                        ctx.DrawLine(pen, new Point(13, 10.5), new Point(13, 21.5));
                        ctx.DrawLine(pen, new Point(19, 10.5), new Point(19, 21.5));
                        break;
                    default:
                        ctx.DrawLine(pen, new Point(11.5, 11), new Point(20.5, 21));
                        ctx.DrawLine(pen, new Point(20.5, 11), new Point(11.5, 21));
                        break;
                }
            }
        }
        var ms = new MemoryStream();
        bmp.Save(ms, PngBitmapEncoderOptions.Default);
        ms.Position = 0;
        return new WindowIcon(ms);
    }
}
