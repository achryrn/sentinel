using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class MemoryView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<MemoryAnalysisResult> _results = [];
    private readonly ObservableCollection<MemoryRegion> _regions = [];

    public MemoryView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        MemGrid.ItemsSource = _results;
        RegionGrid.ItemsSource = _regions;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.ScanMemory);
            if (resp.Code != 0)
            {
                CountText.Text = resp.Error ?? "error";
                return;
            }
            var results = resp.PayloadJson is null
                ? null
                : JsonSerializer.Deserialize<List<MemoryAnalysisResult>>(resp.PayloadJson, IpcProtocol.JsonOptions);
            _results.Clear();
            if (results is not null)
            {
                foreach (var r in results.OrderBy(r => r.Pid))
                {
                    _results.Add(r);
                }
            }
            CountText.Text = $"{_results.Count} processes analyzed";
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

    private async void ScanOne_Click(object sender, RoutedEventArgs e)
    {
        if (!uint.TryParse(PidBox.Text.Trim(), out uint pid))
        {
            // No valid PID: fall back to the all-processes analysis instead of failing silently.
            var choice = MessageBox.Show(
                "No valid PID was entered.\n\nWould you like to analyze all processes instead?\n\nClick Yes to run a full memory analysis, or No to enter a PID manually.",
                "Sentinel — No PID entered",
                MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Yes)
            {
                await RefreshAsync();
            }
            return;
        }
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.ScanMemory, new { Pid = pid });
            if (resp.Code != 0)
            {
                CountText.Text = resp.Error ?? "error";
                return;
            }
            var results = resp.PayloadJson is null
                ? null
                : JsonSerializer.Deserialize<List<MemoryAnalysisResult>>(resp.PayloadJson, IpcProtocol.JsonOptions);
            _results.Clear();
            if (results is not null)
            {
                foreach (var r in results)
                {
                    _results.Add(r);
                }
            }
            CountText.Text = $"{_results.Count} processes analyzed";
        }
        catch (Exception ex)
        {
            CountText.Text = $"error: {ex.Message}";
        }
    }

    private void MemGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _regions.Clear();
        if (MemGrid.SelectedItem is MemoryAnalysisResult r)
        {
            foreach (var region in r.SuspiciousRegions)
            {
                _regions.Add(region);
            }
        }
    }
}