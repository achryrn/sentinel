using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class SettingsView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<Exclusion> _exclusions = [];

    public SettingsView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        ExclGrid.ItemsSource = _exclusions;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var status = await _client.RequestAsync<ServiceStatus>(IpcCommand.Status);
            if (status is not null)
            {
                ServiceText.Text = $"{(status.Running ? "Online" : "Offline")} · active scan: {status.ActiveScanId ?? "none"} · realtime: {(status.RealtimeRunning ? "on" : "off")}";
                StoreText.Text = status.StorePath ?? "—";
            }
            var exclusions = await _client.RequestAsync<List<Exclusion>>(IpcCommand.GetExclusions);
            _exclusions.Clear();
            if (exclusions is not null)
            {
                foreach (var e in exclusions)
                {
                    _exclusions.Add(e);
                }
            }
        }
        catch (Exception ex)
        {
            ServiceText.Text = $"error: {ex.Message}";
        }
    }

    private async void AddExclusion_Click(object sender, RoutedEventArgs e)
    {
        var value = ValueBox.Text.Trim();
        if (string.IsNullOrEmpty(value))
        {
            // No fallback exists for exclusions (a value is mandatory) — warn clearly so the user
            // is never left wondering why nothing happened.
            MessageBox.Show(
                "An exclusion needs a value — a full file path, a 64-char SHA-256 hash, or a signer name.\n\nExample path:  C:\\Program Files\\SomeApp\nExample hash: 4f6a2b9c… (SHA-256, 64 hex chars)\nExample signer: Microsoft Corporation",
                "Sentinel — Exclusion value required",
                MessageBoxButton.OK, MessageBoxImage.Information);
            ValueBox.Focus();
            return;
        }
        var type = (TypeCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() switch
        {
            "hash" => ExclusionType.Hash,
            "signer" => ExclusionType.Signer,
            _ => ExclusionType.Path,
        };
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.AddExclusion, new
            {
                Id = Guid.NewGuid().ToString("n"),
                Type = type,
                Value = value,
                AddedBy = "gui",
                AddedAtUtc = DateTime.UtcNow,
            });
            if (resp.Code != 0)
            {
                MessageBox.Show(resp.Error, "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            ValueBox.Clear();
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void RemoveExclusion_Click(object sender, RoutedEventArgs e)
    {
        if (ExclGrid.SelectedItem is not Exclusion ex)
        {
            MessageBox.Show("Select an exclusion first.", "Sentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            await _client.RequestAsync(IpcCommand.RemoveExclusion, new { Id = ex.Id });
            await RefreshAsync();
        }
        catch (Exception ex2)
        {
            MessageBox.Show(ex2.Message, "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}