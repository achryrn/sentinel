using System.Text.Json;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Core.Realtime;

namespace Sentinel.Gui.Services;

/// <summary>
/// GUI-side gateway to the Sentinel service. Owns the IPC session, subscribes
/// to events (scan progress, file reports, realtime events) and re-raises them
/// on the UI thread. The GUI never opens the database directly.
/// </summary>
public sealed class ServiceClient : IDisposable
{
    private readonly IpcSession _session = new();
    private readonly System.Windows.Threading.Dispatcher _dispatcher;
    private readonly CancellationTokenSource _cts = new();

    public ServiceClient()
    {
        _dispatcher = System.Windows.Application.Current.Dispatcher;
        _session.EventReceived += msg => _dispatcher.BeginInvoke(() => OnEvent(msg));
    }

    public event Action<JsonElement>? ScanProgress;
    public event Action<JsonElement>? FileReport;
    public event Action<RealtimeEvent>? RealtimeEventReceived;
    public event Action<string>? Disconnected;

    public bool Connect(int timeoutMs = 5000) => _session.Connect(timeoutMs);

    public async Task<IpcMessage> RequestAsync(IpcCommand command, object? payload = null, CancellationToken ct = default)
        => await _session.RequestAsync(command, payload, ct);

    public async Task<T?> RequestAsync<T>(IpcCommand command, object? payload = null, CancellationToken ct = default)
        => await _session.RequestAsync<T>(command, payload, ct);

    private void OnEvent(IpcMessage msg)
    {
        try
        {
            if (msg.EventType == "scan-progress" && msg.PayloadJson is not null)
            {
                ScanProgress?.Invoke(JsonSerializer.Deserialize<JsonElement>(msg.PayloadJson, IpcProtocol.JsonOptions));
            }
            else if (msg.EventType == "file-report" && msg.PayloadJson is not null)
            {
                FileReport?.Invoke(JsonSerializer.Deserialize<JsonElement>(msg.PayloadJson, IpcProtocol.JsonOptions));
            }
            else if (msg.EventType == "realtime-event" && msg.PayloadJson is not null)
            {
                var ev = JsonSerializer.Deserialize<RealtimeEvent>(msg.PayloadJson, IpcProtocol.JsonOptions);
                if (ev is not null)
                {
                    RealtimeEventReceived?.Invoke(ev);
                }
            }
        }
        catch (Exception)
        {
            // A malformed event payload must never crash the GUI (it runs on the UI thread).
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _session.Dispose();
    }
}

/// <summary>Live status snapshot from the service.</summary>
public sealed record ServiceStatus(
    bool Running,
    string? ActiveScanId,
    int QueuedScans,
    int ActiveScans,
    bool RealtimeRunning,
    string? StorePath,
    int FindingsCount);