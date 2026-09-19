using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Sentinel.Core.Ipc;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class ScanView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<JsonElement> _results = [];

    public ScanView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        ResultsGrid.ItemsSource = _results;

        _client.ScanProgress += OnScanProgress;
        _client.FileReport += OnFileReport;
    }

    public Task RefreshAsync() => Task.CompletedTask;

    private void OnScanProgress(JsonElement p)
    {
        // 'state' is a ScanState enum which serializes as a NUMBER (1 = Running, 4 = Completed, ...).
        // Older payloads / future string names are tolerated: read either kind defensively.
        var state = GetStringSafe(p, "state");
        ProgressState.Text = state switch
        {
            "enumerating" => "Enumerating files…",
            "scanning" => $"Scanning — {PercentOf(p):0.0}%",
            "hashing" => "Computing hashes…",
            "done" => "Complete",
            "completed" or "4" => "Complete",
            "running" or "1" => $"Scanning — {PercentOf(p):0.0}%",
            "queued" or "0" => "Queued…",
            "paused" or "2" => "Paused",
            "cancelled" or "3" => "Cancelled",
            "failed" or "5" => "Failed",
            _ => state ?? "…",
        };
        ProgressBar.Value = p.TryGetProperty("percent", out var pc) && pc.ValueKind == JsonValueKind.Number ? pc.GetDouble() : 0;
        var item = GetStringSafe(p, "currentItem");
        ProgressDetail.Text = string.IsNullOrEmpty(item) ? "" : (item.Length > 80 ? "…" + item[^80..] : item);
        ProgressSub.Text = $"{FilesOf(p)} files · {BytesOf(p)} · {FpsOf(p):0.0}/s · eta {EtaOf(p)}";
    }

    /// <summary>Reads a property as a string whether the service sent a string or an enum-as-number.</summary>
    private static string? GetStringSafe(JsonElement p, string prop)
    {
        if (!p.TryGetProperty(prop, out var v))
        {
            return null;
        }
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetInt32().ToString(),
            _ => null,
        };
    }

    private void OnFileReport(JsonElement r)
    {
        // Keep the grid bounded: drop oldest beyond 2000 rows.
        if (_results.Count >= 2000)
        {
            _results.RemoveAt(0);
        }
        _results.Add(r);
    }

    private void SetBusy(bool busy)
    {
        QuickBtn.IsEnabled = !busy;
        FullBtn.IsEnabled = !busy;
        ScanPathBtn.IsEnabled = !busy;
        CancelBtn.IsEnabled = busy;
    }

    private async Task RunAsync(IpcCommand cmd, object? payload)
    {
        SetBusy(true);
        _results.Clear();
        ProgressBar.Value = 0;
        try
        {
            var resp = await _client.RequestAsync(cmd, payload);
            if (resp.Code != 0)
            {
                ProgressState.Text = resp.Error ?? "Scan failed";
            }
            else
            {
                ProgressState.Text = "Complete";
            }
        }
        catch (Exception ex)
        {
            ProgressState.Text = $"Error: {ex.Message}";
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void Quick_Click(object sender, RoutedEventArgs e) => _ = RunAsync(IpcCommand.ScanQuick, null);
    private void Full_Click(object sender, RoutedEventArgs e) => _ = RunAsync(IpcCommand.ScanFull, null);

    private async void ScanPath_Click(object sender, RoutedEventArgs e)
    {
        var path = PathBox.Text.Trim();
        if (string.IsNullOrEmpty(path))
        {
            // No explicit target: give the user a choice instead of silently failing.
            var choice = MessageBox.Show(
                "No path was entered.\n\nWould you like to run a Quick scan instead (user profile + program data)?\n\nClick Yes to scan those general locations, or No to enter a path manually.",
                "Sentinel — No scan target",
                MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Yes)
            {
                await RunAsync(IpcCommand.ScanQuick, null);
            }
            return; // No = user goes back to the box; Cancel = dismissed
        }
        var cmd = Directory.Exists(path) ? IpcCommand.ScanFolder : IpcCommand.ScanFile;
        await RunAsync(cmd, new { Path = path });
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog() == true)
        {
            PathBox.Text = dlg.FolderName;
        }
    }

    private async void Cancel_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await _client.RequestAsync(IpcCommand.CancelScan);
        }
        catch (Exception ex)
        {
            ProgressState.Text = $"Cancel failed: {ex.Message}";
        }
    }

    private static double PercentOf(JsonElement p)
        => p.TryGetProperty("percent", out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;

    private static string FilesOf(JsonElement p)
        => p.TryGetProperty("filesProcessed", out var v) ? $"{v.GetInt64():N0}" : "0";

    private static string BytesOf(JsonElement p)
        => p.TryGetProperty("bytesProcessed", out var v) && v.ValueKind == JsonValueKind.Number
            ? FormatBytes(v.GetInt64())
            : "0 B";

    private static double FpsOf(JsonElement p)
        => p.TryGetProperty("filesPerSecond", out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;

    private static string EtaOf(JsonElement p)
    {
        // ETA is a TimeSpan, which serializes as a STRING ("00:01:23"); a bare number is tolerated as seconds.
        if (p.TryGetProperty("eta", out var v))
        {
            if (v.ValueKind == JsonValueKind.String && TimeSpan.TryParse(v.GetString(), out var ts))
            {
                return ts.ToString(@"hh\:mm\:ss");
            }
            if (v.ValueKind == JsonValueKind.Number)
            {
                return TimeSpan.FromSeconds(v.GetDouble()).ToString(@"hh\:mm\:ss");
            }
        }
        return "—";
    }

    private static string FormatBytes(long b)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = b;
        int i = 0;
        while (v >= 1024 && i < units.Length - 1)
        {
            v /= 1024;
            i++;
        }
        return $"{v:0.#} {units[i]}";
    }
}