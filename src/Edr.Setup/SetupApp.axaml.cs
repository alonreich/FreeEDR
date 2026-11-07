using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace Edr.Setup;

public partial class SetupApp : Application
{
    internal static SetupContext? Context { get; set; }

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop && Context is not null)
        {
            desktop.ShutdownMode = Avalonia.Controls.ShutdownMode.OnMainWindowClose;
            var w = new SetupWindow(Context);
            w.Finished += code => desktop.Shutdown(code);
            desktop.MainWindow = w;
        }
        base.OnFrameworkInitializationCompleted();
    }
}
