using Sentinel.Core.Models;
using Sentinel.Core.Storage;
using Xunit;

namespace Sentinel.Tests;

public class StorageRetentionTests : IDisposable
{
    private readonly string _db;
    private readonly SentinelStore _store;

    public StorageRetentionTests()
    {
        _db = Path.Combine(Path.GetTempPath(), $"sentinel-test-{Guid.NewGuid():n}.db");
        _store = new SentinelStore(_db, maxEvidenceRows: 500, maxEventRows: 200,
            findingsOpenKeepDays: 180, findingsReviewKeepDays: 30, maxFindingRows: 100,
            maxScanJobRows: 50, maxHashCacheRows: 100);
    }

    private static StoredFinding Finding(string entity, int sevDaysAgo, FindingStatus status) => new()
    {
        Id = CorrelationEngine_StableId(entity),
        EntityKey = entity,
        Title = "test",
        Severity = Severity.High,
        Confidence = 0.8,
        RiskScore = 50,
        ReasonsJson = "[]",
        MitreTacticsJson = "[]",
        RecommendedAction = "review",
        Status = status,
        FirstSeenUtc = DateTime.UtcNow.AddDays(-sevDaysAgo),
        LastSeenUtc = DateTime.UtcNow.AddDays(-sevDaysAgo),
        OccurrenceCount = 1,
    };

    private static string CorrelationEngine_StableId(string entity)
        => Sentinel.Core.Detection.CorrelationEngine.StableEntityId(entity);

    [Fact]
    public void ConvergedUpsert_OneRowPerEntity_CountsAccumulate()
    {
        var f1 = Finding(@"C:\x\y.exe", 1, FindingStatus.New);
        var f2 = f1 with { LastSeenUtc = DateTime.UtcNow, OccurrenceCount = 3 };

        _store.UpsertFindingConverged(f1);
        _store.UpsertFindingConverged(f2);

        var all = _store.GetFindings(limit: 100);
        var row = Assert.Single(all, r => r.EntityKey == @"C:\x\y.exe");
        Assert.Equal(4, row.OccurrenceCount); // 1 + 3
        Assert.Equal(f1.Id, row.Id);
    }

    [Fact]
    public void ConvergedUpsert_PreservesUserStatus()
    {
        var f1 = Finding(@"C:\x\z.exe", 1, FindingStatus.New);
        _store.UpsertFindingConverged(f1);
        var id = Assert.Single(_store.GetFindings(limit: 100), r => r.EntityKey == @"C:\x\z.exe").Id;

        // User marks the finding Allowed (the GUI path).
        _store.UpdateFindingStatus(id, FindingStatus.Allowed);

        // A re-scan upserts with Status=New - must NOT reset the user's decision.
        var f3 = f1 with { OccurrenceCount = 5 };
        _store.UpsertFindingConverged(f3);

        var row = Assert.Single(_store.GetFindings(limit: 100), r => r.EntityKey == @"C:\x\z.exe");
        Assert.Equal(FindingStatus.Allowed, row.Status);
        Assert.Equal(6, row.OccurrenceCount);
    }

    [Fact]
    public async Task Cleanup_TrimsReviewedFindings_AndKeepsFreshOpenOnes()
    {
        _store.UpsertFindingConverged(Finding(@"C:\old-reviewed.exe", 100, FindingStatus.Reviewed));
        _store.UpsertFindingConverged(Finding(@"C:\old-allowed.exe", 100, FindingStatus.Allowed));
        _store.UpsertFindingConverged(Finding(@"C:\fresh-new.exe", 1, FindingStatus.New));
        _store.UpsertFindingConverged(Finding(@"C:\old-new.exe", 200, FindingStatus.New));

        await _store.CleanupAsync(CancellationToken.None);

        var entities = _store.GetFindings(limit: 100).Select(f => f.EntityKey).ToList();
        Assert.DoesNotContain(@"C:\old-reviewed.exe", entities);
        Assert.DoesNotContain(@"C:\old-allowed.exe", entities);
        Assert.DoesNotContain(@"C:\old-new.exe", entities);
        Assert.Contains(@"C:\fresh-new.exe", entities);
    }

    [Fact]
    public async Task Cleanup_CapsHashCacheRows()
    {
        for (int i = 0; i < 250; i++)
        {
            _store.SetHashCache($@"C:\cache\file-{i:D4}.bin", i, DateTime.UtcNow.AddMinutes(-i), $"sha{i:D64}", null, null);
        }
        await _store.CleanupAsync(CancellationToken.None);
        // cap is 100; cleaner may keep slightly under, never above.
        Assert.True(_store.HashCacheCount() <= 100, $"hash_cache rows {_store.HashCacheCount()} > cap 100");
    }

    [Fact]
    public async Task Cleanup_CapsScanJobs()
    {
        for (int i = 0; i < 80; i++)
        {
            _store.InsertScanJob(new ScanJobRecord
            {
                Id = $"job-{i}",
                Mode = "full",
                StartedUtc = DateTime.UtcNow.AddMinutes(-i),
                Status = "Completed",
            });
        }
        await _store.CleanupAsync(CancellationToken.None);
        Assert.True(_store.ScanJobCount() <= 50);
    }

    [Fact]
    public void Blacklist_LookupAddRemove()
    {
        Assert.Null(_store.LookupBlacklist("aa".PadRight(64, '0')));
        _store.UpsertBlacklist("aa".PadRight(64, '0'), "malware", "Test sample", "test", "tester");
        var hit = _store.LookupBlacklist("aa".PadRight(64, '0'));
        Assert.NotNull(hit);
        Assert.Equal("Test sample", hit!.Label);
        Assert.Single(_store.GetBlacklist());
        _store.RemoveBlacklist("aa".PadRight(64, '0'));
        Assert.Null(_store.LookupBlacklist("aa".PadRight(64, '0')));
    }

    public void Dispose()
    {
        _store.Dispose();
        try { File.Delete(_db); File.Delete(_db + "-wal"); File.Delete(_db + "-shm"); }
        catch { }
    }
}
