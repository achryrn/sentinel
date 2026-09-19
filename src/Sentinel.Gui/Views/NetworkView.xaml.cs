using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class NetworkView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<NetworkConnection> _all = [];
    private readonly ObservableCollection<NetworkConnection> _visible = [];

    public NetworkView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        NetGrid.ItemsSource = _visible;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.ScanNetwork);
            if (resp.Code != 0)
            {
                CountText.Text = resp.Error ?? "error";
                return;
            }
            var snap = resp.PayloadJson is null
                ? null
                : JsonSerializer.Deserialize<NetworkSnapshot>(resp.PayloadJson, IpcProtocol.JsonOptions);
            _all.Clear();
            if (snap?.Connections is not null)
            {
                foreach (var c in snap.Connections)
                {
                    _all.Add(c);
                }
            }
            ApplyFilter();
        }
        catch (Exception ex)
        {
            CountText.Text = $"error: {ex.Message}";
        }
    }

    private void ApplyFilter()
    {
        _visible.Clear();
        var hideLoopback = HideLoopback.IsChecked == true;
        foreach (var c in _all.Where(c => !hideLoopback || !c.IsLoopback).OrderBy(c => c.ProcessName))
        {
            _visible.Add(c);
        }
        // CountText may not exist yet when the Checked event fires during XAML load.
        if (CountText is not null)
        {
            CountText.Text = $"{_visible.Count} connections";
        }
    }

    private void FilterChanged(object sender, RoutedEventArgs e) => ApplyFilter();

    private async void ScanBtn_Click(object sender, RoutedEventArgs e)
    {
        ScanBtn.IsEnabled = false;
        await RefreshAsync();
        ScanBtn.IsEnabled = true;
    }
}