using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class ProcessesView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<ProcessInfo> _procs = [];

    public ProcessesView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        ProcGrid.ItemsSource = _procs;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.ScanProcess);
            if (resp.Code != 0)
            {
                CountText.Text = resp.Error ?? "error";
                return;
            }
            var procs = resp.PayloadJson is null
                ? null
                : JsonSerializer.Deserialize<List<ProcessInfo>>(resp.PayloadJson, IpcProtocol.JsonOptions);
            _procs.Clear();
            if (procs is not null)
            {
                foreach (var p in procs.OrderBy(p => p.Pid))
                {
                    _procs.Add(p);
                }
            }
            CountText.Text = $"{_procs.Count} processes";
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