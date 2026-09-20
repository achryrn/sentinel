using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class FilesView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<JsonElement> _files = [];

    public FilesView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        FilesGrid.ItemsSource = _files;
        _client.FileReport += OnFileReport;
    }

    public Task RefreshAsync() => Task.CompletedTask;

    private void OnFileReport(JsonElement r)
    {
        if (FilesGrid.IsVisible && _files.Count < 2000)
        {
            _files.Add(r);
        }
    }

    private async void ScanPath_Click(object sender, RoutedEventArgs e)
    {
        var path = PathBox.Text.Trim();
        if (string.IsNullOrEmpty(path))
        {
            // No explicit target: fall back to a general-location scan with confirmation.
            var choice = MessageBox.Show(
                "No path was entered.\n\nWould you like to run a Quick scan instead (user profile + program data)?\n\nClick Yes to scan those general locations, or No to enter a path manually.",
                "Sentinel - No scan target",
                MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Yes)
            {
                _files.Clear();
                try
                {
                    var resp = await _client.RequestAsync(IpcCommand.ScanQuick);
                    StatusText.Text = resp.Code == 0 ? "Scan complete." : resp.Error ?? "Scan failed";
                }
                catch (Exception ex)
                {
                    StatusText.Text = $"Error: {ex.Message}";
                }
            }
            return;
        }
        _files.Clear();
        var cmd = Directory.Exists(path) ? IpcCommand.ScanFolder : IpcCommand.ScanFile;
        try
        {
            var resp = await _client.RequestAsync(cmd, new { Path = path });
            StatusText.Text = resp.Code == 0 ? "Scan complete." : resp.Error ?? "Scan failed";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Error: {ex.Message}";
        }
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog();
        if (dlg.ShowDialog() == true)
        {
            PathBox.Text = dlg.FolderName;
        }
    }
}