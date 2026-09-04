using Microsoft.UI.Xaml;

namespace LiquidVault.App;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();
        RequestedTheme = ApplicationTheme.Dark;
        UnhandledException += (_, args) =>
        {
            // Never write exception details to disk: they may contain paths or sensitive context.
            args.Handled = false;
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = new MainWindow();
        _window.Activate();
    }
}
