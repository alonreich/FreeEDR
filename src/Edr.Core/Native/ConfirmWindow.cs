using System.Runtime.InteropServices;

namespace Edr.Core.Native;

public static unsafe partial class ConfirmWindow
{
    public const string ClassName = "FreeEDR.Confirm";
    public const int IdYes = 6, IdNo = 7, IdText = 100;

    private static readonly Lock Gate = new();
    private static bool _answer;
    private static nint _yes, _no, _text, _editProc;

    public static bool Ask(string title, string intro, string request, string footer, bool warning)
    {
        lock (Gate)
        {
            _answer = false;
            var inst = GetModuleHandleW(0);
            fixed (char* cls = ClassName)
            {
                var wc = new WndClassEx
                {
                    Size = (uint)sizeof(WndClassEx), WndProc = (nint)(delegate* unmanaged<nint, uint, nint, nint, nint>)&WndProc, Instance = inst,
                    Cursor = LoadCursorW(0, 32512), Background = 15 + 1, ClassName = (nint)cls,
                };
                RegisterClassExW(&wc);
            }

            var dpi = (int)Math.Max(96, GetDpiForSystem());
            int S(int px) => px * dpi / 96;
            RECT work;
            SystemParametersInfoW(0x30, 0, &work, 0);
            var font = CreateFontW(-(9 * dpi / 72), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe UI");

            const uint style = 0x00C00000 | 0x00080000;
            const uint exStyle = 0x8 | 0x1 | 0x10000 | 0x40000;
            var margin = S(16);
            var icon = S(32);
            var nonClient = new RECT();
            AdjustWindowRectEx(&nonClient, style, 0, exStyle);
            var frameW = nonClient.Right - nonClient.Left;
            var frameH = nonClient.Bottom - nonClient.Top;

            var clientW = Math.Min(S(720), work.Right - work.Left - S(40) - frameW);
            var textW = clientW - 2 * margin;
            var introH = Math.Max(icon, Measure(font, intro, textW - icon - S(12)));
            var footerH = Measure(font, footer, textW);
            var buttonH = S(30);
            var chrome = margin + introH + S(10) + S(10) + footerH + S(14) + buttonH + margin;
            var shown = request.Replace("\r\n", "\n").Replace("\n", "\r\n");
            var wanted = Measure(font, shown, textW - GetSystemMetrics(2) - S(12)) + S(14);
            var maxClientH = (work.Bottom - work.Top) * 85 / 100 - frameH;
            var textH = Math.Clamp(wanted, S(72), Math.Max(S(72), maxClientH - chrome));
            var clientH = chrome + textH;

            var w = clientW + frameW;
            var h = clientH + frameH;
            var x = work.Left + (work.Right - work.Left - w) / 2;
            var y = work.Top + Math.Max(0, (work.Bottom - work.Top - h) / 2);
            var hwnd = CreateWindowExW(exStyle, ClassName, title, style, x, y, w, h, 0, 0, inst, 0);
            if (hwnd == 0) { DeleteObject(font); return false; }

            const uint child = 0x40000000 | 0x10000000;
            var iconCtl = CreateWindowExW(0, "STATIC", "", child | 0x3, margin, margin, icon, icon, hwnd, 0, inst, 0);
            SendMessageW(iconCtl, 0x170, LoadIconW(0, warning ? 32515 : 32514), 0);
            var introCtl = CreateWindowExW(0, "STATIC", intro, child | 0x80, margin + icon + S(12), margin, textW - icon - S(12), introH, hwnd, 0, inst, 0);
            var top = margin + introH + S(10);
            _text = CreateWindowExW(0x200, "EDIT", shown, child | 0x4 | 0x40 | 0x800 | 0x200000 | 0x10000, margin, top, textW, textH, hwnd, IdText, inst, 0);
            _editProc = SetWindowLongPtrW(_text, -4, (nint)(delegate* unmanaged<nint, uint, nint, nint, nint>)&EditProc);
            top += textH + S(10);
            var footerCtl = CreateWindowExW(0, "STATIC", footer, child | 0x80, margin, top, textW, footerH, hwnd, 0, inst, 0);
            var bw = S(110);
            var by = clientH - margin - buttonH;
            _no = CreateWindowExW(0, "BUTTON", "No", child | 0x10000 | 0x20000 | 0x1, clientW - margin - bw, by, bw, buttonH, hwnd, IdNo, inst, 0);
            _yes = CreateWindowExW(0, "BUTTON", "Yes", child | 0x10000, clientW - margin - 2 * bw - S(10), by, bw, buttonH, hwnd, IdYes, inst, 0);
            foreach (var c in new[] { introCtl, _text, footerCtl, _no, _yes }) SendMessageW(c, 0x30, font, 1);

            if (warning) MessageBeep(0x30);
            ShowWindow(hwnd, 5);
            SetForegroundWindow(hwnd);
            SetFocus(_no);
            MSG msg;
            while (GetMessageW(&msg, 0, 0, 0) > 0)
            {
                if (IsDialogMessageW(hwnd, &msg) != 0) continue;
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            DeleteObject(font);
            _yes = _no = _text = _editProc = 0;
            return _answer;
        }
    }

    private static int Measure(nint font, string text, int width)
    {
        var dc = GetDC(0);
        var old = SelectObject(dc, font);
        var r = new RECT { Right = Math.Max(1, width) };
        DrawTextW(dc, text.Length == 0 ? " " : text, -1, &r, 0x400 | 0x10 | 0x2000 | 0x800 | 0x40);
        SelectObject(dc, old);
        ReleaseDC(0, dc);
        return r.Bottom - r.Top;
    }

    [UnmanagedCallersOnly]
    private static nint WndProc(nint h, uint m, nint w, nint l)
    {
        switch (m)
        {
            case 0x400: return (nint)((0x534B << 16) | IdNo);
            case 0x111:
            {
                var id = (int)(w & 0xFFFF);
                if ((w >> 16 & 0xFFFF) != 0 || id is not (IdYes or IdNo or 1 or 2)) break;
                _answer = id == IdYes;
                DestroyWindow(h);
                return 0;
            }
            case 0x10: _answer = false; DestroyWindow(h); return 0;
            case 0x2: PostQuitMessage(0); return 0;
        }
        return DefWindowProcW(h, m, w, l);
    }

    [UnmanagedCallersOnly]
    private static nint EditProc(nint h, uint m, nint w, nint l)
    {
        var r = CallWindowProcW(_editProc, h, m, w, l);
        return m == 0x87 ? r & ~(nint)(0x4 | 0x2) : r;
    }

    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG { public nint Hwnd; public uint Message; public nint WParam, LParam; public uint Time; public int X, Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct WndClassEx
    {
        public uint Size, Style;
        public nint WndProc;
        public int ClsExtra, WndExtra;
        public nint Instance, Icon, Cursor, Background, MenuName, ClassName, IconSm;
    }

    [LibraryImport("kernel32.dll")] private static partial nint GetModuleHandleW(nint name);
    [LibraryImport("user32.dll")] private static partial ushort RegisterClassExW(WndClassEx* wc);
    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CreateWindowExW(uint exStyle, string cls, string title, uint style, int x, int y, int w, int h, nint parent, nint menu, nint inst, nint param);
    [LibraryImport("user32.dll")] private static partial nint DefWindowProcW(nint h, uint m, nint w, nint l);
    [LibraryImport("user32.dll")] private static partial nint CallWindowProcW(nint proc, nint h, uint m, nint w, nint l);
    [LibraryImport("user32.dll")] private static partial nint SetWindowLongPtrW(nint h, int index, nint value);
    [LibraryImport("user32.dll")] private static partial int ShowWindow(nint h, int cmd);
    [LibraryImport("user32.dll")] private static partial int SetForegroundWindow(nint h);
    [LibraryImport("user32.dll")] private static partial nint SetFocus(nint h);
    [LibraryImport("user32.dll")] private static partial int GetMessageW(MSG* m, nint h, uint min, uint max);
    [LibraryImport("user32.dll")] private static partial int IsDialogMessageW(nint h, MSG* m);
    [LibraryImport("user32.dll")] private static partial int TranslateMessage(MSG* m);
    [LibraryImport("user32.dll")] private static partial nint DispatchMessageW(MSG* m);
    [LibraryImport("user32.dll")] private static partial void PostQuitMessage(int code);
    [LibraryImport("user32.dll")] private static partial int DestroyWindow(nint h);
    [LibraryImport("user32.dll")] private static partial nint SendMessageW(nint h, uint m, nint w, nint l);
    [LibraryImport("user32.dll")] private static partial nint LoadCursorW(nint inst, nint id);
    [LibraryImport("user32.dll")] private static partial nint LoadIconW(nint inst, nint id);
    [LibraryImport("user32.dll")] private static partial int SystemParametersInfoW(uint action, uint param, RECT* value, uint ini);
    [LibraryImport("user32.dll")] private static partial uint GetDpiForSystem();
    [LibraryImport("user32.dll")] private static partial int AdjustWindowRectEx(RECT* r, uint style, int menu, uint exStyle);
    [LibraryImport("user32.dll")] private static partial int GetSystemMetrics(int index);
    [LibraryImport("user32.dll")] private static partial int MessageBeep(uint type);
    [LibraryImport("user32.dll")] private static partial nint GetDC(nint h);
    [LibraryImport("user32.dll")] private static partial int ReleaseDC(nint h, nint dc);
    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial int DrawTextW(nint dc, string text, int count, RECT* r, uint format);
    [LibraryImport("gdi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CreateFontW(int h, int w, int esc, int orient, int weight, uint italic, uint underline, uint strike, uint charset, uint outPrec, uint clipPrec, uint quality, uint pitch, string face);
    [LibraryImport("gdi32.dll")] private static partial nint SelectObject(nint dc, nint obj);
    [LibraryImport("gdi32.dll")] private static partial int DeleteObject(nint obj);
}
