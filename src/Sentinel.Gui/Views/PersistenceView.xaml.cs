using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class PersistenceView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<PersistenceEntry> _entries = [];

    public PersistenceView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        PersGrid.ItemsSource = _entries;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.ScanPersistence);
            if (resp.Code != 0)
            {
                CountText.Text = resp.Error ?? "error";
                return;
            }
            var result = resp.PayloadJson is null
                ? null
                : JsonSerializer.Deserialize<PersistenceScanResult>(resp.PayloadJson, IpcProtocol.JsonOptions);
            _entries.Clear();
            if (result?.Entries is not null)
            {
                foreach (var e in result.Entries.OrderBy(e => e.Category).ThenBy(e => e.Name))
                {
                    _entries.Add(e);
                }
            }
            CountText.Text = $"{_entries.Count} persistence entries";
        }
        catch (Exception ex)
        {
            CountText.Text = $"error: {ex.Message}";
        }
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        ScanBtn.IsEnabled = false;
        await RefreshAsync();
        ScanBtn.IsEnabled = true;
    }
}