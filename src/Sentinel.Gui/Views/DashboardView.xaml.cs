using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Core.Realtime;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class DashboardView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;

    public DashboardView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        _client.RealtimeEventReceived += ev => RealtimeGrid.Items.Add(ev);
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var status = await _client.RequestAsync<ServiceStatus>(IpcCommand.Status);
            if (status is not null)
            {
                ServiceStat.Text = status.Running ? "Online" : "Offline";
                ServiceStat.Foreground = status.Running
                    ? (System.Windows.Media.Brush)FindResource("GoodBrush")
                    : (System.Windows.Media.Brush)FindResource("BadBrush");
                ServiceSub.Text = $"realtime {(status.RealtimeRunning ? "on" : "off")} · store: {status.StorePath}";
            }

            var findings = await _client.RequestAsync<List<StoredFinding>>(IpcCommand.GetFindings, new { Limit = 200, MinSeverity = Severity.Info });
            FindingsStat.Text = findings?.Count.ToString() ?? "—";
            var critical = findings?.Count(f => f.Severity >= Severity.High) ?? 0;
            FindingsSub.Text = critical > 0 ? $"{critical} high/critical" : "no high severity";

            var quarantine = await _client.RequestAsync<List<QuarantineItem>>(IpcCommand.GetQuarantine);
            var active = quarantine?.Count(q => q.Status == QuarantineStatus.Quarantined) ?? 0;
            QuarantineStat.Text = active.ToString();
            QuarantineSub.Text = quarantine is null ? "not loaded" : $"{quarantine.Count} total records";

            var realtime = await _client.RequestAsync<List<RealtimeEvent>>(IpcCommand.GetRealtimeEvents);
            RealtimeStat.Text = realtime?.Count.ToString() ?? "—";
            RealtimeSub.Text = "last 500 buffered";

            // Live posture from a fresh system audit
            var auditResp = await _client.RequestAsync(IpcCommand.AuditSystem);
            if (auditResp.Code == 0 && auditResp.PayloadJson is not null)
            {
                var audit = System.Text.Json.JsonSerializer.Deserialize<SystemAuditResult>(auditResp.PayloadJson, IpcProtocol.JsonOptions);
                if (audit is not null)
                {
                    DefenderStat.Text = audit.DefenderEnabled == true ? "Enabled" : "Disabled";
                    DefenderStat.Foreground = audit.DefenderEnabled == true
                        ? (System.Windows.Media.Brush)FindResource("GoodBrush")
                        : (System.Windows.Media.Brush)FindResource("BadBrush");
                    FirewallStat.Text = audit.FirewallEnabled == true ? "Enabled" : "Disabled";
                    FirewallStat.Foreground = audit.FirewallEnabled == true
                        ? (System.Windows.Media.Brush)FindResource("GoodBrush")
                        : (System.Windows.Media.Brush)FindResource("BadBrush");
                    UacStat.Text = audit.UacEnabled == true ? $"Level {audit.UacLevel}" : "Disabled";
                    UacStat.Foreground = audit.UacEnabled == true
                        ? (System.Windows.Media.Brush)FindResource("GoodBrush")
                        : (System.Windows.Media.Brush)FindResource("BadBrush");
                    AuditStat.Text = audit.AuditedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
                }
            }
        }
        catch (Exception ex)
        {
            ServiceSub.Text = $"error: {ex.Message}";
        }
    }
}