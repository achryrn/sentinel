using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class QuarantineView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<QuarantineItem> _items = [];

    public QuarantineView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        QuarGrid.ItemsSource = _items;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var items = await _client.RequestAsync<List<QuarantineItem>>(IpcCommand.GetQuarantine);
            _items.Clear();
            if (items is not null)
            {
                foreach (var q in items.OrderByDescending(q => q.QuarantinedAtUtc))
                {
                    _items.Add(q);
                }
            }
            CountText.Text = $"{_items.Count} items";
        }
        catch (Exception ex)
        {
            CountText.Text = $"error: {ex.Message}";
        }
    }

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (QuarGrid.SelectedItem is not QuarantineItem q)
        {
            MessageBox.Show("Select a quarantined item first.", "Sentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show($"Restore '{q.OriginalPath}' to its original location?", "Sentinel",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.RestoreQuarantine, new { Id = q.Id });
            MessageBox.Show(resp.Code == 0 ? "Restored." : $"Failed: {resp.Error}", "Sentinel",
                MessageBoxButton.OK, resp.Code == 0 ? MessageBoxImage.Information : MessageBoxImage.Error);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (QuarGrid.SelectedItem is not QuarantineItem q)
        {
            MessageBox.Show("Select a quarantined item first.", "Sentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show($"Permanently delete the stored copy of '{q.OriginalPath}'?", "Delete",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            return;
        }
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.DeleteQuarantine, new { Id = q.Id });
            MessageBox.Show(resp.Code == 0 ? "Deleted." : $"Failed: {resp.Error}", "Sentinel",
                MessageBoxButton.OK, resp.Code == 0 ? MessageBoxImage.Information : MessageBoxImage.Error);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}