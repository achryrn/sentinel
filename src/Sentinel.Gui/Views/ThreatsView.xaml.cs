using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class ThreatsView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;
    private readonly ObservableCollection<StoredFinding> _findings = [];
    private readonly ObservableCollection<Evidence> _evidence = [];

    public ThreatsView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        FindingsGrid.ItemsSource = _findings;
        EvidenceGrid.ItemsSource = _evidence;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var findings = await _client.RequestAsync<List<StoredFinding>>(IpcCommand.GetFindings, new { Limit = 500 });
            _findings.Clear();
            if (findings is not null)
            {
                foreach (var f in findings.OrderByDescending(f => f.RiskScore))
                {
                    _findings.Add(f);
                }
            }
            CountText.Text = $"{_findings.Count} findings";
        }
        catch (Exception ex)
        {
            CountText.Text = $"error: {ex.Message}";
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not StoredFinding f)
        {
            return;
        }
        try
        {
            var evidence = await _client.RequestAsync<List<Evidence>>(IpcCommand.GetEvidence, new { EntityId = f.EntityKey });
            _evidence.Clear();
            if (evidence is not null)
            {
                foreach (var ev in evidence.OrderByDescending(ev => ev.Timestamp))
                {
                    _evidence.Add(ev);
                }
            }
        }
        catch (Exception)
        {
            // ignore; evidence panel stays empty
        }
    }

    private async void MarkReviewed_Click(object sender, RoutedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not StoredFinding f)
        {
            MessageBox.Show("Select a finding first.", "Sentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            await _client.RequestAsync(IpcCommand.UpdateFindingStatus, new { Id = f.Id, Status = FindingStatus.Reviewed });
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (FindingsGrid.SelectedItem is not StoredFinding f)
        {
            MessageBox.Show("Select a finding first.", "Sentinel", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show($"Quarantine '{f.EntityKey}'?", "Sentinel", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.QuarantineFile, new { Path = f.EntityKey, Reason = "Quarantined from Threats view" });
            MessageBox.Show(resp.Code == 0 ? "Quarantined." : $"Failed: {resp.Error}", "Sentinel",
                MessageBoxButton.OK, resp.Code == 0 ? MessageBoxImage.Information : MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}