using Avalonia.Controls;

namespace Edr.Tray;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Icon = ShieldIcon.Create(ShieldState.Protected);
    }
}
