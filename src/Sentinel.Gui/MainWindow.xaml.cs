using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using Sentinel.Gui.Services;
using Sentinel.Gui.Views;

namespace Sentinel.Gui;

public partial class MainWindow : Window
{
    private readonly ServiceClient _client = new();
    private readonly Dictionary<string, FrameworkElement> _views = new();
    private string _current = "dashboard";

    // DWM dark title bar (Windows 10 1809+ / 11)
    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWCP_ROUND = 2;

    public MainWindow()
    {
        InitializeComponent();

        SourceInitialized += (_, _) =>
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            int dark = 1;
            _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref dark, sizeof(int));
            int round = DWMWCP_ROUND;
            _ = DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref round, sizeof(int));
        };

        _views["dashboard"] = new DashboardView(_client);
        _views["scan"] = new ScanView(_client);
        _views["threats"] = new ThreatsView(_client);
        _views["processes"] = new ProcessesView(_client);
        _views["network"] = new NetworkView(_client);
        _views["memory"] = new MemoryView(_client);
        _views["persistence"] = new PersistenceView(_client);
        _views["files"] = new FilesView(_client);
        _views["system"] = new SystemView(_client);
        _views["events"] = new EventsView(_client);
        _views["quarantine"] = new QuarantineView(_client);
        _views["settings"] = new SettingsView(_client);

        Loaded += async (_, _) =>
        {
            if (_client.Connect(5000))
            {
                ConnDot.Fill = (Brush)FindResource("GoodBrush");
                ConnText.Text = "Connected to service";
                ConnText.Foreground = (Brush)FindResource("TextBrush");
            }
            else
            {
                ConnDot.Fill = (Brush)FindResource("BadBrush");
                ConnText.Text = "Service not running";
            }
            Navigate("dashboard");
            await RefreshAllAsync();
        };

        Closed += (_, _) => _client.Dispose();
    }

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.Tag is string tag)
        {
            Navigate(tag);
        }
    }

    private void Navigate(string tag)
    {
        _current = tag;
        ContentHost.Content = _views[tag];
        foreach (var child in NavPanel.Children.OfType<Button>())
        {
            child.Background = child.Tag?.ToString() == tag
                ? (Brush)FindResource("AccentDimBrush")
                : new SolidColorBrush(Color.FromRgb(0x21, 0x26, 0x2D));
        }
    }

    private async Task RefreshAllAsync()
    {
        foreach (var v in _views.Values.OfType<IRefreshable>())
        {
            await v.RefreshAsync();
        }
    }
}