using System.Windows;

namespace Sentinel.Gui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += (_, args) =>
        {
            var ex = args.Exception;
            while (ex.InnerException is not null)
            {
                ex = ex.InnerException;
            }
            MessageBox.Show($"Unexpected error:\n{ex.Message}\n\n{ex.StackTrace}", "Sentinel",
                MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
    }
}