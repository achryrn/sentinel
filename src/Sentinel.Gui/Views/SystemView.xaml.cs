using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Gui.Services;

namespace Sentinel.Gui.Views;

public partial class SystemView : UserControl, IRefreshable
{
    private readonly ServiceClient _client;

    public SystemView(ServiceClient client)
    {
        InitializeComponent();
        _client = client;
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var resp = await _client.RequestAsync(IpcCommand.AuditSystem);
            if (resp.Code != 0)
            {
                StatusText.Text = resp.Error ?? "audit failed";
                return;
            }
            var a = resp.PayloadJson is null
                ? null
                : JsonSerializer.Deserialize<SystemAuditResult>(resp.PayloadJson, IpcProtocol.JsonOptions);
            if (a is null)
            {
                StatusText.Text = "No audit data.";
                return;
            }

            OsText.Text = $"{a.OsVersion} (build {a.OsBuild}, {a.OsEdition})";
            BootText.Text = a.LastBootUtc is { } boot ? boot.ToLocalTime().ToString("yyyy-MM-dd HH:mm") : "—";
            UpdateText.Text = a.LastUpdateInstalledUtc is { } upd
                ? $"{upd.ToLocalTime():yyyy-MM-dd} ({a.DaysSinceLastUpdate ?? -1} days ago)"
                : "never / unknown";
            DefenderText.Text = a.DefenderEnabled == true ? "Enabled" : "Disabled";
            DefenderText.Foreground = a.DefenderEnabled == true ? GoodBrush() : BadBrush();
            FirewallText.Text = a.FirewallEnabled == true ? "Enabled" : "Disabled";
            FirewallText.Foreground = a.FirewallEnabled == true ? GoodBrush() : BadBrush();
            UacText.Text = a.UacEnabled == true ? $"Enabled (level {a.UacLevel})" : "Disabled";
            UacText.Foreground = a.UacEnabled == true ? GoodBrush() : BadBrush();
            AdminText.Text = $"{a.LocalAdminCount} — {string.Join(", ", a.LocalAdmins.Take(3))}";
            GuestText.Text = a.GuestEnabled ? "Enabled" : "Disabled";
            GuestText.Foreground = a.GuestEnabled ? BadBrush() : GoodBrush();
            RdpText.Text = a.RdpEnabled ? $"Enabled{(a.RdpExposedToPublic ? " · exposed to public" : "")}" : "Disabled";
            RdpText.Foreground = a.RdpEnabled ? (a.RdpExposedToPublic ? BadBrush() : WarnBrush()) : GoodBrush();
            SmbText.Text = a.SmbEnabled ? $"Enabled{(a.SmbExposedToPublic ? " · exposed" : "")}" : "Disabled";
            SmbText.Foreground = a.SmbEnabled ? (a.SmbExposedToPublic ? BadBrush() : WarnBrush()) : GoodBrush();
            SecBootText.Text = a.SecureBootEnabled ? "Enabled" : "Not enabled";
            TpmText.Text = a.TpmPresent ? "Present" : "Not detected";
            BitlockerText.Text = a.BitLockerEnabled ? "Enabled" : "Not enabled";

            FindingsBox.ItemsSource = a.Findings;
            StatusText.Text = $"Audited {a.AuditedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} · {a.Findings.Count} findings";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Error: {ex.Message}";
        }
    }

    private async void Reaudit_Click(object sender, RoutedEventArgs e)
    {
        ReauditBtn.IsEnabled = false;
        await RefreshAsync();
        ReauditBtn.IsEnabled = true;
    }

    private System.Windows.Media.Brush GoodBrush() => (System.Windows.Media.Brush)FindResource("GoodBrush");
    private System.Windows.Media.Brush BadBrush() => (System.Windows.Media.Brush)FindResource("BadBrush");
    private System.Windows.Media.Brush WarnBrush() => (System.Windows.Media.Brush)FindResource("WarnBrush");
}