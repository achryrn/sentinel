using System.Diagnostics;
using System.ServiceProcess;
using System.Text.Json;
using System.Threading.Channels;
using Sentinel.Core.Detection;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;
using Sentinel.Core.Native;
using Sentinel.Core.Quarantine;
using Sentinel.Core.Realtime;
using Sentinel.Core.Scanning;
using Sentinel.Core.Storage;

namespace Sentinel.Service;

/// <summary>
/// Sentinel service host (LocalSystem). Owns the store, the pipe server, the
/// realtime monitor, and all privileged operations. Scanners run on a bounded
/// scheduler; one scan at a time per job. The GUI/CLI are thin IPC clients.
/// Realtime events are drained in small batches, re-keyed on the evidence dedupe
/// key (entity+event) so repeated churn collapses, and persisted as one
/// transaction every ~2 s. A 60 s store-cleanup loop trims rows to cap and
/// checkpoints/vacuums the WAL, so high-rate file churn cannot drive unbounded
/// DB growth (the 2026-08 self-feedback loop: the monitor watched its own DB
/// directory, and every WAL write generated a new event, ballooning to 52 GB).
/// </summary>
public sealed class SentinelService : ServiceBase
{
    private const int RealtimeRingCapacity = 500;
    private const int RealtimeDrainBatch = 64;
    private SentinelStore? _store;
    private QuarantineManager? _quarantine;
    private RealtimeMonitor? _realtime;
    private IpcServer? _server;
    private ScanScheduler? _scheduler;
    private CancellationTokenSource? _cts;
    private readonly object _scanLock = new();
    private string? _activeScanId;
    private DetectionServices? _detection;
    private IReadOnlyList<string> _enabledPrivileges = [];

    public SentinelService()
    {
        ServiceName = "Sentinel";
        CanStop = true;
        CanShutdown = true;
    }

    protected override void OnStart(string[] args)
    {
        try
        {
            StartCore();
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry("Sentinel", $"Failed to start: {ex}", EventLogEntryType.Error);
            throw;
        }
    }

    /// <summary>Starts the service core (also used by console mode).</summary>
    public void StartCore()
    {
        _cts = new CancellationTokenSource();
        _store = new SentinelStore();
        _quarantine = new QuarantineManager(_store);

        // System-wide visibility: enable the privileges a deep scanner needs
        // (SeDebug to open processes, SeBackup/SeRestore/SeTakeOwnership for
        // ACL-independent file inspection). Without them the scanners degrade
        // gracefully and report access-denied rather than failing.
        _enabledPrivileges = Privileges.Enable(Privileges.ScannerPrivileges);

        _detection = new DetectionServices(_store);
        _realtime = new RealtimeMonitor();
        _scheduler = new ScanScheduler(maxConcurrent: 1);

        _realtime.Start();

        _server = new IpcServer(HandleRequestAsync);
        _server.Start();

        _ = Task.Run(() => RealtimePumpAsync(_cts.Token));
        _ = Task.Run(() => RealtimeAuditAsync(_cts.Token));
        _ = Task.Run(() => StoreCleanupLoopAsync(_cts.Token));

        _store.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "system",
            Message = "Sentinel service started.",
            Severity = EventSeverity.Info,
        });
        _store.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "system",
            Message = $"Enabled privileges: {(string.Join(", ", _enabledPrivileges).Length == 0 ? "NONE — run elevated/LocalSystem for full system visibility" : string.Join(", ", _enabledPrivileges))}. Rules: {_detection.Rules.Count}. AMSI: {(_detection.AmsiAvailable ? "available" : "unavailable")}.",
            Severity = _enabledPrivileges.Count == Privileges.ScannerPrivileges.Length ? EventSeverity.Info : EventSeverity.Warning,
        });
    }

    /// <summary>Stops the service core (also used by console mode).</summary>
    public void StopCore()
    {
        try
        {
            _cts?.Cancel();
            _server?.Dispose();
            _realtime?.Dispose();
            _scheduler?.Dispose();
            _store?.Dispose();
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry("Sentinel", $"Error during stop: {ex.Message}", EventLogEntryType.Error);
        }
    }

    protected override void OnStop() => StopCore();

    protected override void OnShutdown() => OnStop();

    // ---------------- realtime pump: realtime events → evidence + findings ----------------

    private async Task RealtimePumpAsync(CancellationToken ct)
    {
        var correlation = new CorrelationEngine();
        var writer = CreateStoreWriter();
        long flushed = 0;
        long evidenceWrites = 0;
        long eventWrites = 0;
        var flushTimer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        try
        {
            while (!ct.IsCancellationRequested)
            {
                ClearRealtimeEvents(); // drain the monitor channel into the UI ring first
                for (int i = 0; i < RealtimeDrainBatch && _realtime!.Reader.TryRead(out var ev); i++)
                {
                    EnqueueRealtimeEvent(ev);
                    writer.Add(ev);

                    // Deep analysis on the interesting half of the stream:
                    //  - process-created  -> behavioral process-chain rules
                    //  - file-created     -> content rules / script heuristics / AMSI
                    // (The watcher is on persistence locations, so this is cheap.)
                    if (ev.Kind == "process-created")
                    {
                        foreach (var e in _detection!.ObserveProcessEvent(ev))
                        {
                            writer.AddEvidence(e);
                        }
                    }
                    else if (ev.Kind == "file-created" || ev.Kind == "file-changed")
                    {
                        foreach (var e in _detection!.AnalyzeFileContent(ev.Entity))
                        {
                            writer.AddEvidence(e);
                        }
                    }
                }
                if (writer.Count > 0)
                {
                    flushed += writer.Count;
                    var findings = correlation.Correlate(writer.Evidence);
                    PersistFindings(findings);
                    var txn = await writer.CommitAsync(ct).ConfigureAwait(false);
                    evidenceWrites += txn.Evidence;
                    eventWrites += txn.Events;
                }
                bool timeout = await flushTimer.WaitForNextTickAsync(ct).ConfigureAwait(false);
                if (!timeout)
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            // Final flush so a shutdown never drops queued telemetry.
            if (writer.Count > 0)
            {
                var txn = writer.CommitAsync(CancellationToken.None).GetAwaiter().GetResult();
                evidenceWrites += txn.Evidence;
                eventWrites += txn.Events;
            }
            _store!.AppendEvent(new SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "realtime",
                Message = $"Realtime monitor stopped (coalesced {flushed} events, wrote {eventWrites} events, {evidenceWrites} evidence).",
                Severity = EventSeverity.Info,
            });
        }
    }

    private sealed class BufferedStoreWriter
    {
        private readonly SentinelStore _store;
        private readonly List<Evidence> _evidence = new(RealtimeDrainBatch);
        private readonly List<SentinelEvent> _events = new(RealtimeDrainBatch * 2);

        public BufferedStoreWriter(SentinelStore store) => _store = store;

        public int Count => _evidence.Count + _events.Count;

        public IReadOnlyList<Evidence> Evidence => _evidence;

        public void AddEvidence(Evidence e) => _evidence.Add(e);

        public void Add(RealtimeEvent ev)
        {
            var evidence = EvidenceFromRealtime(ev);
            if (evidence is not null)
            {
                _evidence.Add(evidence);
            }
            _events.Add(new SentinelEvent
            {
                TimestampUtc = ev.TimestampUtc,
                Category = "realtime",
                Message = ev.Message,
                Severity = EventSeverity.Info,
                Entity = ev.Entity,
                DetailsJson = ev.DetailsJson,
            });
        }

        public async Task<(int Evidence, int Events)> CommitAsync(CancellationToken ct)
        {
            (int, int) counts = (_evidence.Count, _events.Count);
            if (counts.Item1 == 0 && counts.Item2 == 0)
            {
                return counts;
            }
            await _store.InsertBatchAsync(_evidence, _events, ct).ConfigureAwait(false);
            _evidence.Clear();
            _events.Clear();
            return counts;
        }
    }

    private BufferedStoreWriter CreateStoreWriter() => new(_store!);

    private static Evidence? EvidenceFromRealtime(RealtimeEvent ev)
    {
        // Realtime events are low-confidence signals; they feed correlation but
        // never produce a finding on their own. Deleted/renamed churn stays in
        // the event log only — it would only add noise to correlation.
        string entityId = ev.Entity;
        string? evt = ev.Kind switch
        {
            "file-created" => "realtime-file-created",
            "file-changed" => "realtime-file-changed",
            "process-created" => "realtime-process-created",
            "registry-changed" => "realtime-registry-changed",
            "network-new" => "realtime-network-delta",
            _ => null,
        };
        if (evt is null)
        {
            return null;
        }
        return new Evidence
        {
            Source = "realtime",
            Timestamp = ev.TimestampUtc,
            EntityType = "realtime",
            EntityId = ev.Entity,
            Event = evt,
            Severity = Severity.Low,
            Confidence = 0.3,
            Explanation = ev.Message,
            DetailsJson = ev.DetailsJson,
        };
    }

    private void PersistFindings(IReadOnlyList<Finding> findings)
    {
        foreach (var f in findings)
        {
            _store!.UpsertFindingConverged(new StoredFinding
            {
                Id = f.Id,
                EntityKey = f.EntityKey,
                Title = f.Title,
                Severity = f.Severity,
                Confidence = f.Confidence,
                RiskScore = f.RiskScore,
                ReasonsJson = JsonSerializer.Serialize(f.Reasons, IpcProtocol.JsonOptions),
                MitreTacticsJson = JsonSerializer.Serialize(f.MitreTactics, IpcProtocol.JsonOptions),
                RecommendedAction = f.RecommendedAction,
                Status = FindingStatus.New,
                FirstSeenUtc = f.FirstSeenUtc,
                LastSeenUtc = f.LastSeenUtc,
                OccurrenceCount = f.OccurrenceCount,
            });
        }
    }

    // ---------------- periodic system audit ----------------

    /// <summary>Batched store maintenance: rows, WAL, VACUUM once per minute.</summary>
    private async Task StoreCleanupLoopAsync(CancellationToken ct)
    {
        try
        {
            await _store!.CleanupAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (Exception ex)
        {
            _store!.AppendEvent(new SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "system",
                Message = $"Store cleanup failed: {ex.Message}",
                Severity = EventSeverity.Error,
            });
        }

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try
            {
                await _store!.CleanupAsync(ct).ConfigureAwait(false);
                CleanupDumps();
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                _store!.AppendEvent(new SentinelEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Category = "system",
                    Message = $"Store cleanup failed: {ex.Message}",
                    Severity = EventSeverity.Error,
                });
            }
        }
    }

    /// <summary>
    /// Memory dumps can be gigabytes each; they are diagnostic artifacts, not
    /// detection data. Aged dumps are deleted and the directory is capped so a
    /// box that was repeatedly dumped cannot fill the disk (part of the
    /// "tens of GB" storage fix).
    /// </summary>
    private static void CleanupDumps()
    {
        string dir = Path.Combine(Path.GetDirectoryName(SentinelStore.DefaultDbPath)!, "dumps");
        try
        {
            if (!Directory.Exists(dir))
            {
                return;
            }
            DateTime cutoff = DateTime.UtcNow.AddDays(-14);
            foreach (string f in Directory.EnumerateFiles(dir, "*.dmp"))
            {
                try
                {
                    if (File.GetLastWriteTimeUtc(f) < cutoff)
                    {
                        File.Delete(f);
                    }
                }
                catch (Exception)
                {
                }
            }
            // Keep at most the 20 newest dumps regardless of age.
            var newest = Directory.EnumerateFiles(dir, "*.dmp")
                .OrderByDescending(f => { try { return File.GetLastWriteTimeUtc(f); } catch { return DateTime.MinValue; } })
                .Skip(20);
            foreach (string f in newest)
            {
                try
                {
                    File.Delete(f);
                }
                catch (Exception)
                {
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private async Task RealtimeAuditAsync(CancellationToken ct)
    {
        var auditor = new SystemAuditor();
        var correlation = new CorrelationEngine();
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(30), ct).ConfigureAwait(false);
                var result = auditor.Audit();
                var evidence = DetectionEngine.Normalize(system: result);
                var auditEvent = new SentinelEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Category = "system",
                    Message = $"System audit complete: {result.Findings.Count} findings.",
                    Severity = EventSeverity.Info,
                };
                await _store!.InsertBatchAsync(evidence, [auditEvent], ct).ConfigureAwait(false);
                var findings = correlation.Correlate(evidence);
                PersistFindings(findings);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _store!.AppendEvent(new SentinelEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Category = "system",
                    Message = $"System audit failed: {ex.Message}",
                    Severity = EventSeverity.Error,
                });
            }
        }
    }

    // ---------------- IPC request handling ----------------

    private async Task<IpcMessage> HandleRequestAsync(IpcMessage request)
    {
        var cmd = request.Command ?? IpcCommand.Ping;
        try
        {
            return cmd switch
            {
                IpcCommand.Ping => IpcMessages.Response(request.Id, new { ok = true, version = "1.0" }),
                IpcCommand.Status => IpcMessages.Response(request.Id, GetStatus()),
                IpcCommand.ScanFile => await ScanFileAsync(request),
                IpcCommand.ScanFolder => await ScanFolderAsync(request),
                IpcCommand.ScanQuick => await ScanQuickAsync(request),
                IpcCommand.ScanFull => await ScanFullAsync(request),
                IpcCommand.ScanProcess => await ScanProcessAsync(request),
                IpcCommand.ScanNetwork => await ScanNetworkAsync(request),
                IpcCommand.ScanPersistence => await ScanPersistenceAsync(request),
                IpcCommand.ScanMemory => await ScanMemoryAsync(request),
                IpcCommand.AuditSystem => await AuditSystemAsync(request),
                IpcCommand.CancelScan => CancelScan(),
                IpcCommand.GetFindings => GetFindings(request),
                IpcCommand.GetEvidence => GetEvidence(request),
                IpcCommand.UpdateFindingStatus => UpdateFindingStatus(request),
                IpcCommand.GetExclusions => IpcMessages.Response(request.Id, _store!.GetExclusions()),
                IpcCommand.AddExclusion => AddExclusion(request),
                IpcCommand.RemoveExclusion => RemoveExclusion(request),
                IpcCommand.GetQuarantine => IpcMessages.Response(request.Id, _store!.GetQuarantine()),
                IpcCommand.QuarantineFile => QuarantineFile(request),
                IpcCommand.RestoreQuarantine => RestoreQuarantine(request),
                IpcCommand.DeleteQuarantine => DeleteQuarantine(request),
                IpcCommand.GetEvents => IpcMessages.Response(request.Id, _store!.GetEvents()),
                IpcCommand.GetScanJobs => IpcMessages.Response(request.Id, _store!.GetScanJobs()),
                IpcCommand.GetRealtimeEvents => IpcMessages.Response(request.Id, GetRealtimeEvents()),
                IpcCommand.DumpProcessMemory => DumpProcessMemory(request),
                IpcCommand.GetBlacklist => IpcMessages.Response(request.Id, _store!.GetBlacklist()),
                IpcCommand.AddBlacklist => AddBlacklist(request),
                IpcCommand.RemoveBlacklist => RemoveBlacklist(request),
                IpcCommand.ReloadRules => ReloadRules(request),
                _ => IpcMessages.Response(request.Id, error: "Unknown command"),
            };
        }
        catch (Exception ex)
        {
            return IpcMessages.Response(request.Id, error: ex.Message);
        }
    }

    private object GetStatus()
    {
        return new
        {
            Running = true,
            ActiveScanId = _activeScanId,
            QueuedScans = _scheduler?.QueuedCount ?? 0,
            ActiveScans = _scheduler?.ActiveCount ?? 0,
            RealtimeRunning = _realtime?.IsRunning ?? false,
            StorePath = SentinelStore.DefaultDbPath,
            FindingsCount = _store?.GetFindings(limit: 1).Count ?? 0,
            EnabledPrivileges = _enabledPrivileges,
            RulesCount = _detection?.Rules.Count ?? 0,
            AmsiAvailable = _detection?.AmsiAvailable ?? false,
            BlacklistCount = _store?.GetBlacklist(limit: 1000).Count ?? 0,
        };
    }

    private IpcMessage GetEvidence(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<EvidenceRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        return IpcMessages.Response(request.Id, _store!.GetEvidence(payload?.EntityId ?? ""));
    }

    private IpcMessage GetFindings(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<FindingsRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        return IpcMessages.Response(request.Id, _store!.GetFindings(payload?.Limit ?? 500, payload?.MinSeverity));
    }

    private IpcMessage AddBlacklist(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<BlacklistAddRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrWhiteSpace(payload.Sha256))
        {
            return IpcMessages.Response(request.Id, error: "Missing sha256.");
        }
        _store!.UpsertBlacklist(payload.Sha256, payload.Verdict ?? "malware", payload.Label ?? "user-added", payload.Category, "cli");
        _store!.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "detection",
            Message = $"Blacklist entry added: {payload.Sha256} ({payload.Label})",
            Severity = EventSeverity.Warning,
        });
        return IpcMessages.Response(request.Id, new { ok = true });
    }

    private sealed record BlacklistAddRequest(string? Sha256, string? Verdict, string? Label, string? Category);

    private IpcMessage RemoveBlacklist(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<ShaRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrWhiteSpace(payload.Sha256))
        {
            return IpcMessages.Response(request.Id, error: "Missing sha256.");
        }
        _store!.RemoveBlacklist(payload.Sha256);
        _store!.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "detection",
            Message = $"Blacklist entry removed: {payload.Sha256}",
            Severity = EventSeverity.Info,
        });
        return IpcMessages.Response(request.Id, new { ok = true });
    }

    private sealed record ShaRequest(string? Sha256);

    private IpcMessage ReloadRules(IpcMessage request)
    {
        int count = _detection!.ReloadUserRules();
        _store!.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "detection",
            Message = $"Rule engine reloaded: {count} rules active.",
            Severity = EventSeverity.Info,
        });
        return IpcMessages.Response(request.Id, new { rules = count });
    }

    private sealed record EvidenceRequest(string? EntityId);

    private sealed record FindingsRequest(int? Limit, Severity? MinSeverity);

    private IpcMessage UpdateFindingStatus(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<StatusRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrEmpty(payload.Id))
        {
            return IpcMessages.Response(request.Id, error: "Missing finding id.");
        }
        _store!.UpdateFindingStatus(payload.Id, payload.Status);
        return IpcMessages.Response(request.Id, new { ok = true });
    }

    private sealed record StatusRequest(string? Id, FindingStatus Status);

    private IpcMessage AddExclusion(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<Exclusion>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrEmpty(payload.Value))
        {
            return IpcMessages.Response(request.Id, error: "Missing exclusion value.");
        }
        _store!.AddExclusion(payload);
        _store!.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "exclusion",
            Message = $"Exclusion added: {payload.Type} {payload.Value}",
            Severity = EventSeverity.Info,
        });
        return IpcMessages.Response(request.Id, new { ok = true });
    }

    private IpcMessage RemoveExclusion(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<IdRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrEmpty(payload.Id))
        {
            return IpcMessages.Response(request.Id, error: "Missing exclusion id.");
        }
        _store!.RemoveExclusion(payload.Id);
        _store!.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "exclusion",
            Message = $"Exclusion removed: {payload.Id}",
            Severity = EventSeverity.Info,
        });
        return IpcMessages.Response(request.Id, new { ok = true });
    }

    private sealed record IdRequest(string? Id);

    private IpcMessage QuarantineFile(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<QuarantineRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrEmpty(payload.Path))
        {
            return IpcMessages.Response(request.Id, error: "Missing path.");
        }
        var item = _quarantine!.Quarantine(payload.Path, payload.Reason ?? "User requested", payload.SignerName, payload.EvidenceIdsJson);
        if (item is null)
        {
            return IpcMessages.Response(request.Id, error: "Quarantine failed (see event log).");
        }
        return IpcMessages.Response(request.Id, item);
    }

    private sealed record QuarantineRequest(string? Path, string? Reason, string? SignerName, string? EvidenceIdsJson);

    private IpcMessage RestoreQuarantine(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<IdRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrEmpty(payload.Id))
        {
            return IpcMessages.Response(request.Id, error: "Missing quarantine id.");
        }
        bool ok = _quarantine!.Restore(payload.Id);
        return IpcMessages.Response(request.Id, new { ok });
    }

    private IpcMessage DeleteQuarantine(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<IdRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrEmpty(payload.Id))
        {
            return IpcMessages.Response(request.Id, error: "Missing quarantine id.");
        }
        bool ok = _quarantine!.Delete(payload.Id);
        return IpcMessages.Response(request.Id, new { ok });
    }

    private IpcMessage DumpProcessMemory(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<DumpRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || payload.Pid == 0)
        {
            return IpcMessages.Response(request.Id, error: "Missing pid.");
        }
        var scanner = new MemoryScanner();
        // Dumps live under the store's own data dir, which is deliberately NOT a
        // realtime watch root — writing to %TEMP% (a watch root) would self-trigger
        // file-created events and leak each dump on top of the DB bloat we fixed.
        string dumpDir = Path.Combine(Path.GetDirectoryName(SentinelStore.DefaultDbPath)!, "dumps");
        Directory.CreateDirectory(dumpDir);
        string output = Path.Combine(dumpDir, $"sentinel-dump-{payload.Pid}-{DateTime.UtcNow:yyyyMMddHHmmss}.dmp");
        var result = scanner.Dump(payload.Pid, output, payload.FullMemory);
        return IpcMessages.Response(request.Id, result);
    }

    private sealed record DumpRequest(uint Pid, bool FullMemory);

    private IpcMessage CancelScan()
    {
        lock (_scanLock)
        {
            _scanCts?.Cancel();
        }
        return IpcMessages.Response("cancel", new { ok = true });
    }

    private CancellationTokenSource? _scanCts;

    private IpcMessage GetRealtimeEvents()
    {
        // The GUI polls for recent realtime events; we keep a small ring buffer.
        var events = _realtimeEvents.ToArray();
        return IpcMessages.Response("realtime", events);
    }

    private readonly System.Collections.Concurrent.ConcurrentQueue<RealtimeEvent> _realtimeEvents = new();

    private void EnqueueRealtimeEvent(RealtimeEvent ev)
    {
        lock (_realtimeEvents)
        {
            _realtimeEvents.Enqueue(ev);
            while (_realtimeEvents.Count > RealtimeRingCapacity)
            {
                _realtimeEvents.TryDequeue(out _);
            }
        }
    }

    private void ClearRealtimeEvents()
    {
        lock (_realtimeEvents)
        {
            _realtimeEvents.Clear();
        }
    }

    private void BroadcastFileReport(string scanId, FileReport r)
    {
        _server?.Broadcast(IpcMessages.Event(Guid.NewGuid().ToString("n"), "file-report", new
        {
            ScanId = scanId,
            r.Path,
            r.FileName,
            r.Size,
            r.Sha256,
            r.SignatureStatus,
            r.SignerName,
            r.Entropy,
            r.HasMotw,
            AdsCount = r.AlternateDataStreams.Count,
            PeTimestampAnomaly = r.Pe?.TimestampAnomaly,
            r.IsHiddenOrSystem,
            r.IsReparsePoint,
            r.Notes,
        }));
    }

    // ---------------- scan commands ----------------

    private async Task<IpcMessage> ScanFileAsync(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<PathRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrEmpty(payload.Path))
        {
            return IpcMessages.Response(request.Id, error: "Missing path.");
        }
        return await RunScanAsync(request.Id, "file", async (scanId, progress, ct) =>
        {
            var options = new FileScanOptions
            {
                Targets = [payload.Path],
                Recurse = false,
                Exclusions = _store!.GetExclusions(),
                Store = _store,
            };
            var scanner = new FileScanner(options, progress, ct);
            var reports = new List<FileReport>();
            await foreach (var r in scanner.ScanAsync())
            {
                BroadcastFileReport(scanId, r);
                reports.Add(r);
            }
            return reports;
        });
    }

    private async Task<IpcMessage> ScanFolderAsync(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<PathRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        if (payload is null || string.IsNullOrEmpty(payload.Path))
        {
            return IpcMessages.Response(request.Id, error: "Missing path.");
        }
        return await RunScanAsync(request.Id, "folder", async (scanId, progress, ct) =>
        {
            var options = new FileScanOptions
            {
                Targets = [payload.Path],
                Recurse = true,
                Exclusions = _store!.GetExclusions(),
                Store = _store,
            };
            var scanner = new FileScanner(options, progress, ct);
            return await StreamFileScanAsync(scanId, "folder", scanner, ct);
        });
    }

    private async Task<IpcMessage> ScanQuickAsync(IpcMessage request)
    {
        return await RunScanAsync(request.Id, "quick", async (scanId, progress, ct) =>
        {
            var targets = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            };
            var options = new FileScanOptions
            {
                Targets = targets,
                Recurse = true,
                Exclusions = _store!.GetExclusions(),
                SkipDirectoryNames = ["Windows", "node_modules", ".git", "AppData\\Local\\Temp"],
                Store = _store,
            };
            var scanner = new FileScanner(options, progress, ct);
            return await StreamFileScanAsync(scanId, "quick", scanner, ct);
        });
    }

    private async Task<IpcMessage> ScanFullAsync(IpcMessage request)
    {
        return await RunScanAsync(request.Id, "full", async (scanId, progress, ct) =>
        {
            var targets = new List<string> { "C:\\" };
            var options = new FileScanOptions
            {
                Targets = targets,
                Recurse = true,
                Exclusions = _store!.GetExclusions(),
                SkipDirectoryNames = ["Windows", "node_modules", ".git"],
                Store = _store,
            };
            var scanner = new FileScanner(options, progress, ct);
            return await StreamFileScanAsync(scanId, "full", scanner, ct);
        });
    }

    /// <summary>Summary returned for streaming scans (folder/quick/full).</summary>
    private sealed record ScanSummary(string Mode, long FilesScanned, long BytesScanned, int EvidenceCount);

    /// <summary>
    /// Streaming file scan: never materializes the full report list in memory.
    /// Per-file detection evidence is accumulated in small bounded batches,
    /// correlated and persisted incrementally (with a per-scan correlation
    /// window), and the IPC response carries only a summary — the per-file
    /// reports were already streamed as events. 500k-file scans now use flat
    /// memory instead of gigabytes of report objects.
    /// </summary>
    private async Task<ScanSummary> StreamFileScanAsync(string scanId, string mode, FileScanner scanner, CancellationToken ct)
    {
        var evidence = new List<Evidence>(2048);
        var correlation = new CorrelationEngine();
        long files = 0, bytes = 0;
        int totalEvidence = 0;
        await foreach (var r in scanner.ScanAsync())
        {
            ct.ThrowIfCancellationRequested();
            if (InterestingForUi(r))
            {
                BroadcastFileReport(scanId, r);
            }
            files++;
            bytes += r.Size;
            var ev = DetectionEngine.Normalize(file: r);
            if (ev.Count > 0)
            {
                evidence.AddRange(ev);
            }
            evidence.AddRange(_detection!.AnalyzeFileContent(r.Path));
            if (evidence.Count >= 10_000)
            {
                totalEvidence += evidence.Count;
                await FlushScanEvidenceAsync(correlation, evidence, ct).ConfigureAwait(false);
            }
        }
        totalEvidence += evidence.Count;
        await FlushScanEvidenceAsync(correlation, evidence, ct).ConfigureAwait(false);
        return new ScanSummary(mode, files, bytes, totalEvidence);
    }

    /// <summary>Correlates + persists one bounded evidence batch.</summary>
    private async Task FlushScanEvidenceAsync(CorrelationEngine correlation, List<Evidence> evidence, CancellationToken ct)
    {
        if (evidence.Count == 0)
        {
            return;
        }
        var findings = correlation.Correlate(evidence);
        PersistFindings(findings);
        await _store!.InsertBatchAsync(evidence, [], ct).ConfigureAwait(false);
        evidence.Clear();
    }

    /// <summary>Which per-file reports are worth streaming to the UI (PEs, flagged files).</summary>
    private static bool InterestingForUi(FileReport r) =>
        r.IsPe || r.Notes.Count > 0 || r.HasMotw || r.IsHiddenOrSystem || r.KnownMalwareLabel is not null;

    private async Task<IpcMessage> ScanProcessAsync(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<PidRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        return await RunScanAsync(request.Id, "process", async (scanId, progress, ct) =>
        {
            var scanner = new ProcessScanner();
            var results = new List<ProcessInfo>();
            if (payload?.Pid is > 0)
            {
                var p = scanner.ScanOne(payload.Pid.Value);
                if (p is not null)
                {
                    results.Add(await scanner.AnalyzeAsync(p, computeHash: true, ct));
                }
            }
            else
            {
                foreach (var p in scanner.ScanAll())
                {
                    ct.ThrowIfCancellationRequested();
                    results.Add(await scanner.AnalyzeAsync(p, computeHash: false, ct));
                }
            }
            return results;
        });
    }

    private sealed record PidRequest(uint? Pid);

    private async Task<IpcMessage> ScanNetworkAsync(IpcMessage request)
    {
        return await RunScanAsync(request.Id, "network", async (scanId, progress, ct) =>
        {
            var scanner = new NetworkScanner();
            return scanner.Capture();
        });
    }

    private async Task<IpcMessage> ScanPersistenceAsync(IpcMessage request)
    {
        return await RunScanAsync(request.Id, "persistence", async (scanId, progress, ct) =>
        {
            var scanner = new PersistenceScanner();
            return scanner.Scan();
        });
    }

    private async Task<IpcMessage> ScanMemoryAsync(IpcMessage request)
    {
        var payload = JsonSerializer.Deserialize<PidRequest>(request.PayloadJson ?? "{}", IpcProtocol.JsonOptions);
        return await RunScanAsync(request.Id, "memory", async (scanId, progress, ct) =>
        {
            var scanner = new MemoryScanner();
            var results = new List<MemoryAnalysisResult>();
            if (payload?.Pid is > 0)
            {
                var p = new ProcessScanner().ScanOne(payload.Pid.Value);
                results.Add(scanner.Analyze(payload.Pid.Value, p?.Name ?? $"pid-{payload.Pid}"));
            }
            else
            {
                foreach (var p in new ProcessScanner().ScanAll())
                {
                    ct.ThrowIfCancellationRequested();
                    results.Add(scanner.Analyze(p.Pid, p.Name));
                }
            }
            return results;
        });
    }

    private async Task<IpcMessage> AuditSystemAsync(IpcMessage request)
    {
        return await RunScanAsync(request.Id, "system", async (scanId, progress, ct) =>
        {
            var auditor = new SystemAuditor();
            return auditor.Audit();
        });
    }

    private sealed record PathRequest(string? Path);

    // ---------------- scan runner: bounded scheduler + evidence pipeline ----------------

    /// <summary>
    /// Scans run at BelowNormal process priority so an active scan never makes
    /// the machine feel sluggish (quiet operation); restored when the scan ends.
    /// </summary>
    private static IDisposable? QuietScanScope()
    {
        try
        {
            var p = Process.GetCurrentProcess();
            if (p.PriorityClass == ProcessPriorityClass.Normal)
            {
                p.PriorityClass = ProcessPriorityClass.BelowNormal;
                return new PriorityRestore(p);
            }
        }
        catch
        {
            // Not fatal: priority is an optimization, not a requirement.
        }
        return null;
    }

    private sealed class PriorityRestore : IDisposable
    {
        private readonly Process _p;
        internal PriorityRestore(Process p) => _p = p;
        public void Dispose()
        {
            try
            {
                _p.PriorityClass = ProcessPriorityClass.Normal;
            }
            catch
            {
            }
        }
    }

    private async Task<IpcMessage> RunScanAsync<T>(string requestId, string mode, Func<string, IProgress<ScanProgress>, CancellationToken, Task<T>> scan)
    {
        string scanId = Guid.NewGuid().ToString("n");
        lock (_scanLock)
        {
            if (_activeScanId is not null)
            {
                return IpcMessages.Response(requestId, error: "A scan is already running.");
            }
            _activeScanId = scanId;
            _scanCts = new CancellationTokenSource();
        }

        _store!.InsertScanJob(new ScanJobRecord
        {
            Id = scanId,
            Mode = mode,
            StartedUtc = DateTime.UtcNow,
            Status = "Running",
        });

        var progress = new Progress<ScanProgress>(p =>
        {
            // Progress is delivered as IPC events; the GUI subscribes to them.
            _server?.Broadcast(IpcMessages.Event(Guid.NewGuid().ToString("n"), "scan-progress", new
            {
                ScanId = scanId,
                p.State,
                p.FilesTotal,
                p.FilesProcessed,
                p.BytesProcessed,
                p.CurrentItem,
                p.Percent,
                p.FilesPerSecond,
                p.Eta,
            }));
        });

        try
        {
            using var quiet = QuietScanScope();
            T? data = default;
            await _scheduler!.Enqueue(async ct =>
            {
                data = await scan(scanId, progress, ct).ConfigureAwait(false);
                await ProcessScanResultsAsync(scanId, mode, data, ct).ConfigureAwait(false);
            }, _scanCts.Token);

            _store!.UpdateScanJob(scanId, "Completed", 0, 0);
            return IpcMessages.Response(requestId, data);
        }
        catch (OperationCanceledException)
        {
            _store!.UpdateScanJob(scanId, "Cancelled", 0, 0);
            return IpcMessages.Response(requestId, error: "Scan cancelled.");
        }
        catch (Exception ex)
        {
            _store!.UpdateScanJob(scanId, "Failed", 0, 0);
            return IpcMessages.Response(requestId, error: ex.Message);
        }
        finally
        {
            lock (_scanLock)
            {
                _activeScanId = null;
                _scanCts?.Dispose();
                _scanCts = null;
            }
        }
    }

    private async Task ProcessScanResultsAsync<T>(string scanId, string mode, T data, CancellationToken ct)
    {
        // Streaming file scans already persisted their evidence incrementally.
        if (data is ScanSummary)
        {
            return;
        }

        var correlation = new CorrelationEngine();
        var evidence = new List<Evidence>(1024);

        switch (data)
        {
            case List<FileReport> files:
                foreach (var f in files)
                {
                    evidence.AddRange(DetectionEngine.Normalize(file: f));
                    evidence.AddRange(_detection!.AnalyzeFileContent(f.Path));
                }
                break;
            case List<ProcessInfo> procs:
                foreach (var p in procs)
                {
                    evidence.AddRange(DetectionEngine.Normalize(process: p));
                }
                // Cross-check two independent process views — a process visible
                // in only one enumeration surface may be hiding itself.
                evidence.AddRange(DetectionEngine.NormalizeProcessViews(new ProcessScanner().CompareProcessViews()));
                break;
            case NetworkSnapshot net:
                evidence.AddRange(DetectionEngine.Normalize(network: net));
                break;
            case PersistenceScanResult pers:
                evidence.AddRange(DetectionEngine.Normalize(persistence: pers));
                break;
            case List<MemoryAnalysisResult> mems:
                foreach (var m in mems)
                {
                    evidence.AddRange(DetectionEngine.Normalize(memory: m));
                }
                break;
            case SystemAuditResult sys:
                evidence.AddRange(DetectionEngine.Normalize(system: sys));
                break;
        }

        var findings = correlation.Correlate(evidence);
        PersistFindings(findings);
        await _store!.InsertBatchAsync(evidence, [], ct).ConfigureAwait(false);

        _store!.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "scan",
            Message = $"Scan {mode} ({scanId}) complete: {evidence.Count} evidence items, {findings.Count} findings.",
            Severity = EventSeverity.Info,
        });
    }
}