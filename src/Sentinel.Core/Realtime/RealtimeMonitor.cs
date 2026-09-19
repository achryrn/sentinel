using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;
using Sentinel.Core.Native;

namespace Sentinel.Core.Realtime;

/// <summary>One realtime event observed by a monitor.</summary>
public sealed record RealtimeEvent
{
    public required DateTime TimestampUtc { get; init; }
    public required string Kind { get; init; }        // file-created | file-changed | process-created | registry-changed | network-delta
    public required string Entity { get; init; }
    public required string Message { get; init; }
    public string? DetailsJson { get; init; }
}

/// <summary>
/// Real-time monitoring: ReadDirectoryChangesW on curated roots, WMI process
/// creation events, RegNotifyChangeKeyValue on curated persistence keys, and
/// bounded network polling. All monitors are event-driven or bounded-poll;
/// no full-disk polling loops.
/// </summary>
public sealed class RealtimeMonitor : IDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _tasks = [];
    private readonly Channel<RealtimeEvent> _events = Channel.CreateBounded<RealtimeEvent>(new BoundedChannelOptions(4096)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
    });

    public RealtimeMonitor()
    {
    }

    public IReadOnlyList<string> CuratedWatchRoots { get; } =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.Startup),
        Path.GetTempPath(),
    ];

    public IReadOnlyList<(string Hive, string Key)> CuratedRegistryKeys { get; } =
    [
        (@"HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (@"HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (@"HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (@"HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (@"HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (@"HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        (@"HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
        (@"HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        (@"HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager"),
    ];

    /// <summary>Starts all monitors. Returns immediately; events flow via <see cref="ReadAllAsync"/>.</summary>
    public void Start()
    {
        IsRunning = true;
        _tasks.Add(Task.Run(() => WatchDirectoriesAsync(_cts.Token)));
        _tasks.Add(Task.Run(() => WatchRegistryAsync(_cts.Token)));
        _tasks.Add(Task.Run(() => WatchProcessesAsync(_cts.Token)));
        _tasks.Add(Task.Run(() => PollNetworkAsync(_cts.Token)));
    }

    /// <summary>True once <see cref="Start"/> has been called (before Dispose).</summary>
    public bool IsRunning { get; private set; }

    public ChannelReader<RealtimeEvent> Reader => _events.Reader;

    public async IAsyncEnumerable<RealtimeEvent> ReadAllAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var e in _events.Reader.ReadAllAsync(ct))
        {
            yield return e;
        }
    }

    // ---------- file watcher (ReadDirectoryChangesW) ----------

    private async Task WatchDirectoriesAsync(CancellationToken ct)
    {
        var roots = CuratedWatchRoots.Where(Directory.Exists).Distinct().ToList();
        foreach (var root in roots)
        {
            _ = Task.Run(() => WatchOneDirectoryAsync(root, ct), ct);
        }
        await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
    }

    private async Task WatchOneDirectoryAsync(string root, CancellationToken ct)
    {
        IntPtr hDir = IntPtr.Zero;
        try
        {
            hDir = NativeMethods.CreateFileW(root, NativeMethods.FILE_LIST_DIRECTORY,
                NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE | NativeMethods.FILE_SHARE_DELETE,
                IntPtr.Zero, NativeMethods.OPEN_EXISTING,
                NativeMethods.FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (hDir == IntPtr.Zero || hDir == new IntPtr(-1))
            {
                return;
            }

            var buffer = new byte[64 * 1024];
            while (!ct.IsCancellationRequested)
            {
                uint returned = 0;
                bool ok = NativeMethods.ReadDirectoryChangesW(hDir, buffer, (uint)buffer.Length,
                    bWatchSubtree: true,
                    NativeMethods.FILE_NOTIFY_CHANGE_FILE_NAME | NativeMethods.FILE_NOTIFY_CHANGE_DIR_NAME |
                    NativeMethods.FILE_NOTIFY_CHANGE_LAST_WRITE | NativeMethods.FILE_NOTIFY_CHANGE_CREATION,
                    out returned, IntPtr.Zero, IntPtr.Zero);
                if (!ok)
                {
                    await Task.Delay(2000, ct).ConfigureAwait(false);
                    continue;
                }
                if (returned == 0)
                {
                    continue;
                }

                ParseFileNotifyBuffer(buffer, (int)returned, root);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
            // Directory removed or access denied — monitor stops for this root.
        }
        finally
        {
            if (hDir != IntPtr.Zero && hDir != new IntPtr(-1))
            {
                NativeMethods.CloseHandle(hDir);
            }
        }
    }

    private void ParseFileNotifyBuffer(byte[] buffer, int length, string root)
    {
        int offset = 0;
        while (offset + 12 <= length)
        {
            uint next = BitConverter.ToUInt32(buffer, offset);
            uint action = BitConverter.ToUInt32(buffer, offset + 4);
            uint nameLen = BitConverter.ToUInt32(buffer, offset + 8);
            if (nameLen == 0 || offset + 12 + nameLen > length)
            {
                break;
            }
            string name = Encoding.Unicode.GetString(buffer, offset + 12, (int)nameLen);
            string full = Path.Combine(root, name);
            string kind = action switch
            {
                1 => "file-created",
                2 => "file-deleted",
                3 => "file-modified",
                4 => "file-renamed-old",
                5 => "file-renamed-new",
                _ => "file-changed",
            };
            _events.Writer.TryWrite(new RealtimeEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Kind = kind,
                Entity = full,
                Message = $"{kind}: {full}",
            });
            if (next == 0)
            {
                break;
            }
            offset += (int)next;
        }
    }

    // ---------- registry watcher (RegNotifyChangeKeyValue) ----------

    private async Task WatchRegistryAsync(CancellationToken ct)
    {
        foreach (var (hive, key) in CuratedRegistryKeys)
        {
            _ = Task.Run(() => WatchOneRegistryKeyAsync(hive, key, ct), ct);
        }
        await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
    }

    private async Task WatchOneRegistryKeyAsync(string hive, string key, CancellationToken ct)
    {
        IntPtr hKey = IntPtr.Zero;
        try
        {
            IntPtr root = hive switch
            {
                "HKLM" => NativeMethods.HKEY_LOCAL_MACHINE,
                "HKCU" => NativeMethods.HKEY_CURRENT_USER,
                _ => NativeMethods.HKEY_LOCAL_MACHINE,
            };
            int rc = NativeMethods.RegOpenKeyExW(root, key, 0, NativeMethods.KEY_READ | NativeMethods.KEY_NOTIFY, out hKey);
            if (rc != 0)
            {
                return;
            }

            while (!ct.IsCancellationRequested)
            {
                int notify = NativeMethods.RegNotifyChangeKeyValue(hKey, true,
                    NativeMethods.REG_NOTIFY_CHANGE_LAST_SET | NativeMethods.REG_NOTIFY_CHANGE_NAME,
                    IntPtr.Zero, false);
                if (notify != 0)
                {
                    await Task.Delay(2000, ct).ConfigureAwait(false);
                    continue;
                }
                _events.Writer.TryWrite(new RealtimeEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Kind = "registry-changed",
                    Entity = $"{hive}\\{key}",
                    Message = $"Registry key changed: {hive}\\{key}",
                });
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
        }
        finally
        {
            if (hKey != IntPtr.Zero)
            {
                NativeMethods.RegCloseKey(hKey);
            }
        }
    }

    // ---------- process watcher (WMI) ----------

    private async Task WatchProcessesAsync(CancellationToken ct)
    {
        try
        {
            var scope = new System.Management.ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            var query = new System.Management.WqlEventQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'");
            using var watcher = new System.Management.ManagementEventWatcher(scope, query);
            watcher.EventArrived += (_, e) =>
            {
                try
                {
                    using var target = (System.Management.ManagementBaseObject)e.NewEvent["TargetInstance"];
                    string? name = target["Name"]?.ToString();
                    string? pid = target["ProcessId"]?.ToString();
                    string? cmd = target["CommandLine"]?.ToString();
                    _events.Writer.TryWrite(new RealtimeEvent
                    {
                        TimestampUtc = DateTime.UtcNow,
                        Kind = "process-created",
                        Entity = pid ?? "?",
                        Message = $"Process created: {name} (PID {pid})",
                        DetailsJson = cmd is null ? null : System.Text.Json.JsonSerializer.Serialize(new { commandLine = cmd }),
                    });
                }
                catch (Exception)
                {
                }
            };
            watcher.Start();
            try
            {
                await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            }
            finally
            {
                watcher.Stop();
            }
        }
        catch (Exception)
        {
            // WMI unavailable — snapshot reconciliation is the backstop.
        }
    }

    // ---------- network polling (bounded, 2 s) ----------

    private DateTime _lastNetworkSnapshot = DateTime.MinValue;
    private HashSet<string> _knownConnections = new(StringComparer.Ordinal);

    private async Task PollNetworkAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var snap = new Sentinel.Core.Scanning.NetworkScanner().Capture();
                var current = new HashSet<string>(snap.Connections.Select(c =>
                    $"{c.Protocol}|{c.LocalAddress}:{c.LocalPort}->{c.RemoteAddress}:{c.RemotePort}|{c.OwningPid}"), StringComparer.Ordinal);
                if (_lastNetworkSnapshot != DateTime.MinValue)
                {
                    foreach (var key in current)
                    {
                        if (!_knownConnections.Contains(key))
                        {
                            var parts = key.Split('|');
                            _events.Writer.TryWrite(new RealtimeEvent
                            {
                                TimestampUtc = DateTime.UtcNow,
                                Kind = "network-new",
                                Entity = key,
                                Message = $"New connection: {parts[0]} {parts[1]} -> {parts[2]}",
                            });
                        }
                    }
                }
                _knownConnections = current;
                _lastNetworkSnapshot = DateTime.UtcNow;
            }
            catch (Exception)
            {
            }
            await Task.Delay(2000, ct).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try
        {
            Task.WaitAll(_tasks.ToArray(), TimeSpan.FromSeconds(3));
        }
        catch (Exception)
        {
        }
        _cts.Dispose();
    }
}