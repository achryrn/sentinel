using System.Diagnostics;
using Microsoft.Data.Sqlite;
using Sentinel.Core.Models;
using Sentinel.Core.Storage;

//                       SENTINEL FEEDBACK-LOOP SOAK TEST
//
// Reproduces the 2026-08 incident: heavy writes to the DB's own directory while
// the (now faster) pipeline runs. Old build ⇒ evidence grew unbounded + per-insert
// trims + never-checkpointed WAL ⇒ file ballooned to 52 GB.
// Fixed build must withstand this for the duration and keep the DB file small
// (batched pump + OR REPLACE coalescing + periodic trim + WAL checkpoint/vacuum).

string dbPath = args.Length > 0
    ? args[0]
    : @"C:\Users\Zachary\Documents\Project\anti\test\SoakTest\soak.db";

var store = new SentinelStore(dbPath, maxEvidenceRows: 1_000, maxEventRows: 500, trimBatchSize: 200);
var rng = new Random(Seed: 42);
var stop = TimeSpan.FromMinutes(3);
var sw = Stopwatch.StartNew();

var dir = Path.GetDirectoryName(dbPath)!;
var attacker = Task.Run(() =>
{
    // Write directly into the store's own directory so the cleanup loop,
    // checkpoint/VACUUM and watchers all churn against it — repeat of the incident.
    while (sw.Elapsed < stop)
    {
        int n = rng.Next(1, 20);
        for (int i = 0; i < n; i++)
        {
            string f = Path.Combine(dir, $"churn-{rng.Next(1, 50)}.tmp");
            try
            {
                File.WriteAllBytes(f, new byte[rng.Next(0, 64 * 1024)]);
                File.Delete(f);
            }
            catch
            {
            }
        }
        Thread.Sleep(150);
    }
});

async Task IngestLoop()
{
    // Simulated realtime event storm: unique entities + repeated same-entity
    // events. Same-entity repeats must coalesce via the Evidence dedupe key so
    // table sizes stay near the caps, not at the churn rate. Duplicates are legal
    // WITHIN one batch too — a drain batch can hold two events with the same
    // entity+event (e.g. two changes to one file within 2 s).
    while (sw.Elapsed < stop)
    {
        var evList = new List<Evidence>(256);
        var evtList = new List<SentinelEvent>(256);
        int n = rng.Next(100, 300);
        for (int i = 0; i < n; i++)
        {
            bool repeat = rng.Next(100) < 80;
            var e = new Evidence
            {
                Source = "realtime",
                Timestamp = DateTime.UtcNow,
                EntityType = "realtime",
                EntityId = repeat ? $"/entity/{rng.Next(1, 40)}" : $"/entity/{Guid.NewGuid():n}",
                Event = "realtime-file-changed",
                Severity = Severity.Low,
                Confidence = 0.3,
                Explanation = "soak: simulated file change",
            };
            evList.Add(e);
            evtList.Add(new SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "realtime",
                Message = $"soak {e.EntityId}",
                Severity = EventSeverity.Info,
            });
        }
        // Deliberately inject intra-batch duplicates (same entity+event twice).
        for (int i = 0; i < 2; i++)
        {
            evList.Add(new Evidence
            {
                Source = "realtime",
                Timestamp = DateTime.UtcNow,
                EntityType = "realtime",
                EntityId = "/entity/dup",
                Event = "realtime-file-changed",
                Severity = Severity.Low,
                Confidence = 0.3,
                Explanation = "soak: duplicate in same batch",
            });
        }
        await store.InsertBatchAsync(evList, evtList, CancellationToken.None);
        await Task.Delay(350);
    }
}

var ingest = Task.Run(IngestLoop);

// The service runs the trim/checkpoint/vacuum on a timer (StoreCleanupLoopAsync);
// the soak must exercise that same path or row counts never get trimmed.
var cleaner = Task.Run(async () =>
{
    while (sw.Elapsed < stop + TimeSpan.FromSeconds(60))
    {
        try
        {
            await store.CleanupAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[cleaner] {ex.Message}");
        }
        await Task.Delay(TimeSpan.FromSeconds(20));
    }
});

await Task.WhenAll(attacker, ingest, cleaner);

// Let a couple of cleanup cycles land after the storm stops.
await Task.Delay(TimeSpan.FromSeconds(60));

var fi = new FileInfo(dbPath);
long walBytes = new FileInfo(dbPath + "-wal").Length;
long evidenceRows = CountRows("evidence");
long eventRows = CountRows("events");
string[] sizes =
[
    $"evidence:  {evidenceRows}",
    $"events:    {eventRows}",
    $"db bytes:  {fi.Length:N0}",
    $"wal bytes: {walBytes:N0}",
    $"db size:   {fi.Length / 1_048_576.0:N1} MB",
];
string[] expected =
[
    $"evidence ≤ 1600 (cap 1000, recent-post-cleaner growth)",
    $"events   ≤  750 (cap 500, recent-post-cleaner growth)",
    "vacuum applied when waste ≥ 50%",
    $"db ≪ 200 MB (was 52 GB)",
];
string report = string.Join(Environment.NewLine, sizes) + "\n\nExpected:\n" + string.Join(Environment.NewLine, expected);
File.WriteAllText(Path.Combine(Path.GetDirectoryName(dbPath)!, "soak-result.txt"), report);
Console.WriteLine(report);
store.Dispose();
return 0;

long CountRows(string table)
{
    using var c = new SqliteConnection($"Data Source={dbPath};Mode=ReadOnly");
    c.Open();
    using var cmd = c.CreateCommand();
    cmd.CommandText = $"SELECT COUNT(*) FROM {table};";
    return (long)(cmd.ExecuteScalar() ?? 0L);
}