using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;

namespace Edr.Tray;

public partial class App : Application
{
    private readonly TrayContext? _context;
    private TrayIcon? _tray;
    private MainWindow? _window;
    private bool _exiting;

    public App() : this(null) { }   // XAML previewer

    internal App(TrayContext? context) => _context = context;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop && _context is not null)
        {
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;   // the tray lives on with the dashboard closed
            _tray = CreateTray();
            TrayIcon.SetIcons(this, [_tray]);
            _context.Instance.Listen(
                onShow: () => Dispatcher.UIThread.Post(ShowDashboard),
                onExit: () => Dispatcher.UIThread.Post(Exit));
            if (_context.Options.Show) ShowDashboard();
        }
        base.OnFrameworkInitializationCompleted();
    }

    private TrayIcon CreateTray()
    {
        var open = new NativeMenuItem("Open dashboard");
        open.Click += (_, _) => ShowDashboard();
        var exit = new NativeMenuItem("Exit tray (protection keeps running)");
        exit.Click += (_, _) => Exit();

        var tray = new TrayIcon
        {
            Icon = ShieldIcon.Create(ShieldState.Protected),
            ToolTipText = _context!.Options.Dev ? "FreeEDR (dev build)" : "FreeEDR",
            Menu = [open, new NativeMenuItemSeparator(), exit],
            IsVisible = true,
        };
        tray.Clicked += (_, _) => ShowDashboard();
        return tray;
    }

    private void ShowDashboard()
    {
        if (_exiting) return;
        if (_window is null)
        {
            _window = new MainWindow();
            _window.Closing += (_, e) =>
            {
                if (_exiting) return;
                e.Cancel = true;   // closing the dashboard only hides it, as in the PowerShell tray
                _window.Hide();
            };
        }
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    private void Exit()
    {
        if (_exiting) return;
        _exiting = true;
        if (_tray is not null) _tray.IsVisible = false;
        _window?.Close();
        (ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown();
    }
}
