using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class EventsView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<SentinelEvent> _events = [];

    public EventsView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        EventsGrid.ItemsSource = _events;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var events = await _client.RequestAsync<List<SentinelEvent>>(IpcCommand.GetEvents, new { Limit = 500 });
            _events.Clear();
            if (events is not null)
            {
                foreach (var e in events.OrderByDescending(e => e.TimestampUtc))
                {
                    _events.Add(e);
                }
            }
            CountText.Text = $"{_events.Count} events";
        }
        catch (Exception ex)
        {
            CountText.Text = $"error: {ex.Message}";
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();
}