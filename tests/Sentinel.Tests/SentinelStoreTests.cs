using Sentinel.Core.Models;
using Sentinel.Core.Storage;

namespace Sentinel.Tests;

/// <summary>
/// Store tests against a temporary SQLite database — never touches the real
/// %ProgramData%\Sentinel\sentinel.db.
/// </summary>
public class SentinelStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SentinelStore _store;

    public SentinelStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"sentinel-store-{Guid.NewGuid():n}.db");
        _store = new SentinelStore(_dbPath);
    }

    public void Dispose()
    {
        _store.Dispose();
        TryDelete(_dbPath);
        TryDelete(_dbPath + "-wal");
        TryDelete(_dbPath + "-shm");
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // WAL files may be briefly locked; ignore.
        }
    }

    private static StoredFinding Finding(string id, string entity, Severity sev = Severity.Medium, double risk = 50)
    {
        return new StoredFinding
        {
            Id = id,
            EntityKey = entity,
            Title = $"Finding {id}",
            Severity = sev,
            Confidence = 0.7,
            RiskScore = risk,
            ReasonsJson = "[\"reason\"]",
            MitreTacticsJson = "[\"Persistence\"]",
            RecommendedAction = "Review.",
            Status = FindingStatus.New,
            FirstSeenUtc = DateTime.UtcNow,
        };
    }

    // ---------- findings ----------

    [Fact]
    public void UpsertAndGetFindings_RoundTrips()
    {
        _store.UpsertFinding(Finding("f1", @"C:\evil\evil.exe", Severity.High, 80));

        var findings = _store.GetFindings();

        var f = Assert.Single(findings);
        Assert.Equal("f1", f.Id);
        Assert.Equal(@"C:\evil\evil.exe", f.EntityKey);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(80, f.RiskScore);
        Assert.Equal(FindingStatus.New, f.Status);
    }

    [Fact]
    public void GetFindings_OrdersByRiskDesc()
    {
        _store.UpsertFinding(Finding("low", "a", Severity.Low, 10));
        _store.UpsertFinding(Finding("high", "b", Severity.High, 90));
        _store.UpsertFinding(Finding("mid", "c", Severity.Medium, 50));

        var findings = _store.GetFindings();

        Assert.Equal(["high", "mid", "low"], findings.Select(f => f.Id).ToArray());
    }

    [Fact]
    public void GetFindings_MinSeverityFilters()
    {
        _store.UpsertFinding(Finding("low", "a", Severity.Low, 10));
        _store.UpsertFinding(Finding("high", "b", Severity.High, 90));

        var findings = _store.GetFindings(minSeverity: Severity.Medium);

        var f = Assert.Single(findings);
        Assert.Equal("high", f.Id);
    }

    [Fact]
    public void GetFindings_LimitApplies()
    {
        for (int i = 0; i < 10; i++)
        {
            _store.UpsertFinding(Finding($"f{i}", $"e{i}", Severity.Info, i));
        }

        var findings = _store.GetFindings(limit: 3);

        Assert.Equal(3, findings.Count);
    }

    [Fact]
    public void UpdateFindingStatus_Persists()
    {
        _store.UpsertFinding(Finding("f1", "a"));
        _store.UpdateFindingStatus("f1", FindingStatus.Reviewed);

        var f = Assert.Single(_store.GetFindings());
        Assert.Equal(FindingStatus.Reviewed, f.Status);
    }

    [Fact]
    public void UpsertFinding_UpdatesOccurrence()
    {
        var f = Finding("f1", "a");
        _store.UpsertFinding(f);
        _store.UpsertFinding(f with { OccurrenceCount = 5, LastSeenUtc = DateTime.UtcNow });

        var loaded = Assert.Single(_store.GetFindings());
        Assert.Equal(5, loaded.OccurrenceCount);
    }

    // ---------- evidence ----------

    [Fact]
    public void InsertAndGetEvidence_RoundTrips()
    {
        var e = new Evidence
        {
            Source = "file",
            Timestamp = DateTime.UtcNow,
            EntityType = "file",
            EntityId = @"C:\evil\evil.exe",
            Event = "unsigned-executable",
            Severity = Severity.Low,
            Confidence = 0.5,
            Explanation = "Executable 'evil.exe' is unsigned.",
        };
        _store.InsertEvidence(e);

        var loaded = _store.GetEvidence(@"C:\evil\evil.exe");

        var item = Assert.Single(loaded);
        Assert.Equal("unsigned-executable", item.Event);
        Assert.Equal(Severity.Low, item.Severity);
        Assert.Equal(0.5, item.Confidence);
        Assert.Equal("Executable 'evil.exe' is unsigned.", item.Explanation);
    }

    [Fact]
    public void GetEvidence_ScopedByEntity()
    {
        var now = DateTime.UtcNow;
        _store.InsertEvidence(new Evidence { Source = "file", Timestamp = now, EntityType = "file", EntityId = "a", Event = "e1", Severity = Severity.Info, Confidence = 0.5, Explanation = "x" });
        _store.InsertEvidence(new Evidence { Source = "file", Timestamp = now, EntityType = "file", EntityId = "b", Event = "e2", Severity = Severity.Info, Confidence = 0.5, Explanation = "y" });

        var loaded = _store.GetEvidence("a");

        var item = Assert.Single(loaded);
        Assert.Equal("e1", item.Event);
    }

    // ---------- exclusions ----------

    [Fact]
    public void AddAndRemoveExclusion_RoundTrips()
    {
        var ex = new Exclusion
        {
            Id = "x1",
            Type = ExclusionType.Path,
            Value = @"C:\trusted\app.exe",
            AddedBy = "test",
            AddedAtUtc = DateTime.UtcNow,
        };
        _store.AddExclusion(ex);

        var loaded = Assert.Single(_store.GetExclusions());
        Assert.Equal(ExclusionType.Path, loaded.Type);
        Assert.Equal(@"C:\trusted\app.exe", loaded.Value);

        _store.RemoveExclusion("x1");
        Assert.Empty(_store.GetExclusions());
    }

    // ---------- quarantine ----------

    [Fact]
    public void Quarantine_RoundTripsAndStatusUpdate()
    {
        var item = new QuarantineItem
        {
            Id = "q1",
            OriginalPath = @"C:\evil\evil.exe",
            StoredPath = @"C:\ProgramData\Sentinel\quarantine\q1.bin",
            Sha256 = "a".PadRight(64, '0'),
            Sha1 = "b".PadRight(40, '0'),
            Md5 = "c".PadRight(32, '0'),
            Size = 1234,
            QuarantinedAtUtc = DateTime.UtcNow,
            Reason = "Test quarantine",
            Status = QuarantineStatus.Quarantined,
        };
        _store.InsertQuarantine(item);

        var loaded = Assert.Single(_store.GetQuarantine());
        Assert.Equal(QuarantineStatus.Quarantined, loaded.Status);
        Assert.Equal(@"C:\evil\evil.exe", loaded.OriginalPath);

        _store.UpdateQuarantineStatus("q1", QuarantineStatus.Restored);
        Assert.Equal(QuarantineStatus.Restored, Assert.Single(_store.GetQuarantine()).Status);
    }

    // ---------- events ----------

    [Fact]
    public void AppendAndGetEvents_RoundTrips()
    {
        _store.AppendEvent(new SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "scan",
            Message = "Scan completed",
            Severity = EventSeverity.Info,
        });

        var events = _store.GetEvents();

        var ev = Assert.Single(events);
        Assert.Equal("scan", ev.Category);
        Assert.Equal("Scan completed", ev.Message);
        Assert.Equal(EventSeverity.Info, ev.Severity);
        Assert.True(ev.Id > 0);
    }

    [Fact]
    public void GetEvents_FiltersByCategory()
    {
        _store.AppendEvent(new SentinelEvent { TimestampUtc = DateTime.UtcNow, Category = "scan", Message = "s", Severity = EventSeverity.Info });
        _store.AppendEvent(new SentinelEvent { TimestampUtc = DateTime.UtcNow, Category = "detection", Message = "d", Severity = EventSeverity.Warning });

        var events = _store.GetEvents(category: "detection");

        var ev = Assert.Single(events);
        Assert.Equal("detection", ev.Category);
    }

    // ---------- scan jobs ----------

    [Fact]
    public void ScanJob_InsertAndUpdate()
    {
        var job = new ScanJobRecord
        {
            Id = "j1",
            Mode = "quick",
            StartedUtc = DateTime.UtcNow,
            Status = "Running",
        };
        _store.InsertScanJob(job);
        _store.UpdateScanJob("j1", "Completed", filesScanned: 42, findingsCount: 3);

        var loaded = Assert.Single(_store.GetScanJobs());
        Assert.Equal("Completed", loaded.Status);
        Assert.Equal(42, loaded.FilesScanned);
        Assert.Equal(3, loaded.FindingsCount);
        Assert.NotNull(loaded.FinishedUtc);
    }

    // ---------- settings ----------

    [Fact]
    public void Settings_SetAndGet()
    {
        Assert.Null(_store.GetSetting("missing"));

        _store.SetSetting("theme", "dark");
        Assert.Equal("dark", _store.GetSetting("theme"));

        _store.SetSetting("theme", "light");
        Assert.Equal("light", _store.GetSetting("theme"));
    }

    // ---------- hash cache ----------

    [Fact]
    public void HashCache_RoundTrips()
    {
        var now = DateTime.UtcNow;
        Assert.Null(_store.GetHashCache(@"C:\a\b.exe", 100, now));

        _store.SetHashCache(@"C:\a\b.exe", 100, now, "sha256", "sha1", "md5");

        var cached = _store.GetHashCache(@"C:\a\b.exe", 100, now);
        Assert.NotNull(cached);
        Assert.Equal("sha256", cached.Value.Sha256);
        Assert.Equal("sha1", cached.Value.Sha1);
        Assert.Equal("md5", cached.Value.Md5);
    }

    [Fact]
    public void HashCache_SizeMismatch_Misses()
    {
        var now = DateTime.UtcNow;
        _store.SetHashCache(@"C:\a\b.exe", 100, now, "sha256", null, null);

        Assert.Null(_store.GetHashCache(@"C:\a\b.exe", 999, now));
    }

    // ---------- signer cache ----------

    [Fact]
    public void ObserveSigner_Accumulates()
    {
        _store.ObserveSigner("Microsoft Corporation", "trusted");
        _store.ObserveSigner("Microsoft Corporation", "trusted");

        // No public getter; verify no exception and that a second observation works.
        _store.ObserveSigner("Other Corp", "untrusted");
    }
}