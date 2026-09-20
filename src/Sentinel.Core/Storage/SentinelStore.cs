using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sentinel.Core.Detection;
using Sentinel.Core.Models;

namespace Sentinel.Core.Storage;

/// <summary>
/// SQLite-backed store for findings, evidence, scan jobs, hash cache, signer
/// cache, exclusions, quarantine, settings and the event log tail.
/// Single-writer connection owned by the service; readers use short-lived
/// connections. WAL mode.
/// </summary>
public sealed class SentinelStore : IDisposable
{
    public const string DefaultDbPath = @"C:\ProgramData\Sentinel\sentinel.db";
    public int MaxEvidenceRows { get; }
    public int MaxEventRows { get; }

    /// <summary>Rows to trim when the batched cleaner runs (default 20 % of the cap).</summary>
    public int TrimBatchSize { get; }

    /// <summary>Minimum data bytes on disk before the cleaner may run a VACUUM.</summary>
    public long MinVacuumBytes { get; } = TrimLowWaterMarkBytes;

    private readonly string _dbPath;
    private readonly SqliteConnection _writer;
    private readonly object _writeLock = new();
    private readonly SemaphoreSlim _cleanerGate = new(1, 1);

    public SentinelStore(
        string? dbPath = null,
        int? maxEvidenceRows = null,
        int? maxEventRows = null,
        int? trimBatchSize = null,
        int? findingsReviewKeepDays = null,
        int? findingsOpenKeepDays = null,
        int? maxFindingRows = null,
        int? maxScanJobRows = null,
        int? maxHashCacheRows = null)
    {
        _dbPath = dbPath ?? DefaultDbPath;
        MaxEvidenceRows = maxEvidenceRows ?? 100_000;
        MaxEventRows = maxEventRows ?? 5_000;
        TrimBatchSize = trimBatchSize ?? Math.Max(MaxEvidenceRows / 5, 1);
        FindingsReviewKeepDays = findingsReviewKeepDays ?? 30;
        FindingsOpenKeepDays = findingsOpenKeepDays ?? 180;
        MaxFindingRows = maxFindingRows ?? 200_000;
        MaxScanJobRows = maxScanJobRows ?? 2_000;
        MaxHashCacheRows = maxHashCacheRows ?? 2_000_000;
        Directory.CreateDirectory(Path.GetDirectoryName(_dbPath)!);
        _writer = new SqliteConnection($"Data Source={_dbPath}");
        _writer.Open();
        using (var cmd = _writer.CreateCommand())
        {
            cmd.CommandText = "PRAGMA journal_mode=WAL;";
            cmd.ExecuteNonQuery();
            cmd.CommandText = "PRAGMA busy_timeout=15000;";
            cmd.ExecuteNonQuery();
            cmd.CommandText = "PRAGMA auto_vacuum=FULL;";
            cmd.ExecuteNonQuery();
            cmd.CommandText = "PRAGMA synchronous=NORMAL;";
            cmd.ExecuteNonQuery();
            cmd.CommandText = "PRAGMA wal_autocheckpoint=1000;";
            cmd.ExecuteNonQuery();
        }
        InitializeSchema();
    }

    /// <summary>
    /// Bounded bytes of live data that a small store should never exceed. DBs
    /// whose resident data is below this floor are exempt from VACUUM entirely,
    /// so a tiny install can never be pointlessly shrunk. Default: 20 MB.
    /// </summary>
    public const long TrimLowWaterMarkBytes = 20L * 1024 * 1024;

    /// <summary>
    /// Hard cap on resident data for the enforcement tier: when live data
    /// exceeds this, a trim may evict rows from the table that is farthest past
    /// its row cap (critical rows — findings, quarantine — are never evicted by
    /// the automatic trim). Default: 200 MB.
    /// </summary>
    public const long TrimHardCapBytes = 200L * 1024 * 1024;

    /// <summary>Hard cap on resident DB data; never exceeded by a healthy store.</summary>
    public const long MaxDbBytes = TrimHardCapBytes;

    /// <summary>Days to keep reviewable findings (Reviewed/Allowed/FalsePositive) after last observation.</summary>
    public int FindingsReviewKeepDays { get; }

    /// <summary>Days to keep open findings (New/Quarantined) after last observation.</summary>
    public int FindingsOpenKeepDays { get; }

    /// <summary>Maximum finding rows retained by the automatic cleaner.</summary>
    public int MaxFindingRows { get; }

    /// <summary>Maximum scan-job rows retained by the automatic cleaner.</summary>
    public int MaxScanJobRows { get; }

    /// <summary>Maximum hash-cache rows retained by the automatic cleaner.</summary>
    public int MaxHashCacheRows { get; }

    private void InitializeSchema()
    {
        using var cmd = _writer.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                entity_key TEXT NOT NULL,
                title TEXT NOT NULL,
                severity INTEGER NOT NULL,
                confidence REAL NOT NULL,
                risk_score REAL NOT NULL,
                reasons_json TEXT NOT NULL,
                mitre_tactics_json TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                status INTEGER NOT NULL,
                first_seen_utc TEXT NOT NULL,
                last_seen_utc TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS ix_findings_entity ON findings(entity_key);
            CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings(severity);

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                event TEXT NOT NULL,
                severity INTEGER NOT NULL,
                confidence REAL NOT NULL,
                explanation TEXT NOT NULL,
                details_json TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_evidence_entity ON evidence(entity_id);

            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT,
                status TEXT NOT NULL,
                files_scanned INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                targets_json TEXT
            );

            CREATE TABLE IF NOT EXISTS hash_cache (
                path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                last_write_utc TEXT NOT NULL,
                sha256 TEXT,
                sha1 TEXT,
                md5 TEXT,
                first_seen_utc TEXT NOT NULL,
                verdict TEXT
            );

            CREATE TABLE IF NOT EXISTS signer_cache (
                signer TEXT PRIMARY KEY,
                trust_state TEXT NOT NULL,
                observed_count INTEGER NOT NULL DEFAULT 1,
                last_seen_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exclusions (
                id TEXT PRIMARY KEY,
                type INTEGER NOT NULL,
                value TEXT NOT NULL,
                scope TEXT,
                added_by TEXT NOT NULL,
                added_at_utc TEXT NOT NULL,
                rationale TEXT
            );

            CREATE TABLE IF NOT EXISTS quarantine (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                sha1 TEXT NOT NULL,
                md5 TEXT NOT NULL,
                size INTEGER NOT NULL,
                quarantined_at_utc TEXT NOT NULL,
                reason TEXT NOT NULL,
                signer_name TEXT,
                evidence_ids_json TEXT,
                status INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                severity INTEGER NOT NULL,
                entity TEXT,
                details_json TEXT
            );

            CREATE TABLE IF NOT EXISTS hash_blacklist (
                sha256 TEXT PRIMARY KEY,
                verdict TEXT NOT NULL,
                label TEXT NOT NULL,
                category TEXT,
                added_by TEXT NOT NULL,
                added_at_utc TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    // ---------- findings ----------

    public void UpsertFinding(StoredFinding f)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT INTO findings (id, entity_key, title, severity, confidence, risk_score,
                    reasons_json, mitre_tactics_json, recommended_action, status, first_seen_utc,
                    last_seen_utc, occurrence_count)
                VALUES ($id, $entity, $title, $sev, $conf, $risk, $reasons, $tactics, $action,
                    $status, $first, $last, $occ)
                ON CONFLICT(id) DO UPDATE SET
                    last_seen_utc = excluded.last_seen_utc,
                    occurrence_count = excluded.occurrence_count,
                    status = excluded.status;
                """;
            cmd.Parameters.AddWithValue("$id", f.Id);
            cmd.Parameters.AddWithValue("$entity", f.EntityKey);
            cmd.Parameters.AddWithValue("$title", f.Title);
            cmd.Parameters.AddWithValue("$sev", (int)f.Severity);
            cmd.Parameters.AddWithValue("$conf", f.Confidence);
            cmd.Parameters.AddWithValue("$risk", f.RiskScore);
            cmd.Parameters.AddWithValue("$reasons", f.ReasonsJson);
            cmd.Parameters.AddWithValue("$tactics", f.MitreTacticsJson);
            cmd.Parameters.AddWithValue("$action", f.RecommendedAction);
            cmd.Parameters.AddWithValue("$status", (int)f.Status);
            cmd.Parameters.AddWithValue("$first", f.FirstSeenUtc.ToString("o"));
            cmd.Parameters.AddWithValue("$last", f.LastSeenUtc?.ToString("o") ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$occ", f.OccurrenceCount);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Converging upsert: keeps at most ONE active finding row per entity.
    /// If the entity already has a finding with a user-set status (Allowed,
    /// FalsePositive, Quarantined) that row is updated in place — the user's
    /// decision survives re-scans. Otherwise the deterministic finding id
    /// (stable per entity) makes repeated scans update the same row instead of
    /// duplicating it (the pre-hardening build inserted a fresh GUID row every
    /// correlation pass, which unboundedly grew the store).
    /// </summary>
    public void UpsertFindingConverged(StoredFinding f)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                SELECT id, status FROM findings WHERE entity_key = $entity
                ORDER BY last_seen_utc DESC, first_seen_utc DESC LIMIT 1;
                """;
            cmd.Parameters.AddWithValue("$entity", f.EntityKey);
            string? existingId = null;
            int existingStatus = -1;
            using (var r = cmd.ExecuteReader())
            {
                if (r.Read())
                {
                    existingId = r.GetString(0);
                    existingStatus = r.GetInt32(1);
                }
            }

            // Resolve target id + status, then write.
            // Status rule: the correlation pipeline always upserts with "New".
            // If the row already carries a user decision (non-New), keep it —
            // otherwise adopt the incoming status.
            string id = existingId ?? f.Id;
            int status = (existingStatus >= 0 && (int)f.Status == (int)FindingStatus.New && existingStatus != (int)FindingStatus.New)
                ? existingStatus
                : (int)f.Status;

            cmd.Parameters.Clear();
            cmd.CommandText = """
                INSERT INTO findings (id, entity_key, title, severity, confidence, risk_score,
                    reasons_json, mitre_tactics_json, recommended_action, status, first_seen_utc,
                    last_seen_utc, occurrence_count)
                VALUES ($id, $entity, $title, $sev, $conf, $risk, $reasons, $tactics, $action,
                    $status, $first, $last, $occ)
                ON CONFLICT(id) DO UPDATE SET
                    entity_key = excluded.entity_key,
                    title = excluded.title,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    risk_score = excluded.risk_score,
                    reasons_json = excluded.reasons_json,
                    mitre_tactics_json = excluded.mitre_tactics_json,
                    recommended_action = excluded.recommended_action,
                    last_seen_utc = excluded.last_seen_utc,
                    occurrence_count = findings.occurrence_count + excluded.occurrence_count;
                """;
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$entity", f.EntityKey);
            cmd.Parameters.AddWithValue("$title", f.Title);
            cmd.Parameters.AddWithValue("$sev", (int)f.Severity);
            cmd.Parameters.AddWithValue("$conf", f.Confidence);
            cmd.Parameters.AddWithValue("$risk", f.RiskScore);
            cmd.Parameters.AddWithValue("$reasons", f.ReasonsJson);
            cmd.Parameters.AddWithValue("$tactics", f.MitreTacticsJson);
            cmd.Parameters.AddWithValue("$action", f.RecommendedAction);
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$first", f.FirstSeenUtc.ToString("o"));
            cmd.Parameters.AddWithValue("$last", f.LastSeenUtc?.ToString("o") ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$occ", f.OccurrenceCount);
            cmd.ExecuteNonQuery();
        });
    }

    public List<StoredFinding> GetFindings(int limit = 500, Severity? minSeverity = null)
    {
        var list = new List<StoredFinding>();
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = minSeverity is null
            ? "SELECT * FROM findings ORDER BY risk_score DESC, first_seen_utc DESC LIMIT $limit;"
            : "SELECT * FROM findings WHERE severity >= $min ORDER BY risk_score DESC, first_seen_utc DESC LIMIT $limit;";
        cmd.Parameters.AddWithValue("$limit", limit);
        if (minSeverity is not null)
        {
            cmd.Parameters.AddWithValue("$min", (int)minSeverity.Value);
        }
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(ReadFinding(r));
        }
        return list;
    }

    public void UpdateFindingStatus(string id, FindingStatus status)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = "UPDATE findings SET status = $status WHERE id = $id;";
            cmd.Parameters.AddWithValue("$status", (int)status);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        });
    }

    private static StoredFinding ReadFinding(SqliteDataReader r) => new()
    {
        Id = r.GetString(0),
        EntityKey = r.GetString(1),
        Title = r.GetString(2),
        Severity = (Severity)r.GetInt32(3),
        Confidence = r.GetDouble(4),
        RiskScore = r.GetDouble(5),
        ReasonsJson = r.GetString(6),
        MitreTacticsJson = r.GetString(7),
        RecommendedAction = r.GetString(8),
        Status = (FindingStatus)r.GetInt32(9),
        FirstSeenUtc = DateTime.Parse(r.GetString(10), null, System.Globalization.DateTimeStyles.RoundtripKind),
        LastSeenUtc = r.IsDBNull(11) ? null : DateTime.Parse(r.GetString(11), null, System.Globalization.DateTimeStyles.RoundtripKind),
        OccurrenceCount = r.GetInt32(12),
    };

    // ---------- evidence ----------

    public void InsertEvidence(Evidence e)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT OR REPLACE INTO evidence (id, source, timestamp_utc, entity_type, entity_id,
                    event, severity, confidence, explanation, details_json)
                VALUES ($id, $source, $ts, $etype, $eid, $event, $sev, $conf, $expl, $details);
                """;
            cmd.Parameters.AddWithValue("$id", e.Key);
            cmd.Parameters.AddWithValue("$source", e.Source);
            cmd.Parameters.AddWithValue("$ts", e.Timestamp.ToString("o"));
            cmd.Parameters.AddWithValue("$etype", e.EntityType);
            cmd.Parameters.AddWithValue("$eid", e.EntityId);
            cmd.Parameters.AddWithValue("$event", e.Event);
            cmd.Parameters.AddWithValue("$sev", (int)e.Severity);
            cmd.Parameters.AddWithValue("$conf", e.Confidence);
            cmd.Parameters.AddWithValue("$expl", e.Explanation);
            cmd.Parameters.AddWithValue("$details", e.DetailsJson is null ? (object)DBNull.Value : DetectionEngine.CapDetailsJson(e.DetailsJson));
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Inserts a batch of evidence items and a batch of event rows in one
    /// write transaction. Inserts run INSERT OR REPLACE keyed on the evidence
    /// dedupe key, so retried buckets never accumulate duplicate rows and a
    /// pathological event storm is coalesced by the store itself.
    /// Timestamps are not guaranteed unique across the batch.
    /// </summary>
    /// <summary>
    /// Inserts a batch of evidence items and a batch of event rows in one write
    /// transaction, serialized against the cleaner and all other writers by the
    /// single-writer lock (the pre-hardening version ran its transaction WITHOUT
    /// the lock, so the periodic cleaner could start mid-transaction and fail
    /// with "pending local transaction" — surfaced by the soak test).
    /// </summary>
    public async Task InsertBatchAsync(
        IReadOnlyList<Evidence> evidence,
        IReadOnlyList<SentinelEvent> events,
        CancellationToken ct)
    {
        await Task.Run(() =>
        {
            lock (_writeLock)
            {
                using var cmd = _writer.CreateCommand();
                cmd.CommandText = "PRAGMA busy_timeout=15000;";
                cmd.ExecuteNonQuery();

                using var txn = _writer.BeginTransaction();
                try
                {
                    if (evidence.Count > 0)
                    {
                        cmd.Transaction = txn;
                        cmd.CommandText = """
                            CREATE TEMP TABLE IF NOT EXISTS _batch_evidence (
                                id TEXT PRIMARY KEY,
                                source TEXT NOT NULL,
                                timestamp_utc TEXT NOT NULL,
                                entity_type TEXT NOT NULL,
                                entity_id TEXT NOT NULL,
                                event TEXT NOT NULL,
                                severity INTEGER NOT NULL,
                                confidence REAL NOT NULL,
                                explanation TEXT NOT NULL,
                                details_json TEXT
                            ) WITHOUT ROWID;
                            """;
                        cmd.ExecuteNonQuery();

                        cmd.CommandText = "DELETE FROM _batch_evidence;";
                        cmd.ExecuteNonQuery();
                        foreach (var e in evidence)
                        {
                            cmd.CommandText = """
                                INSERT OR REPLACE INTO _batch_evidence (id, source, timestamp_utc, entity_type, entity_id,
                                    event, severity, confidence, explanation, details_json)
                                VALUES ($id, $source, $ts, $etype, $eid, $event, $sev, $conf, $expl, $details);
                                """;
                            cmd.Parameters.Clear();
                            cmd.Parameters.AddWithValue("$id", e.Key);
                            cmd.Parameters.AddWithValue("$source", e.Source);
                            cmd.Parameters.AddWithValue("$ts", e.Timestamp.ToString("o"));
                            cmd.Parameters.AddWithValue("$etype", e.EntityType);
                            cmd.Parameters.AddWithValue("$eid", e.EntityId);
                            cmd.Parameters.AddWithValue("$event", e.Event);
                            cmd.Parameters.AddWithValue("$sev", (int)e.Severity);
                            cmd.Parameters.AddWithValue("$conf", e.Confidence);
                            cmd.Parameters.AddWithValue("$expl", e.Explanation);
                            cmd.Parameters.AddWithValue("$details", e.DetailsJson is null ? (object)DBNull.Value : DetectionEngine.CapDetailsJson(e.DetailsJson));
                            cmd.ExecuteNonQuery();
                        }

                        cmd.CommandText = """
                            INSERT OR REPLACE INTO evidence (id, source, timestamp_utc, entity_type, entity_id,
                                event, severity, confidence, explanation, details_json)
                            SELECT id, source, timestamp_utc, entity_type, entity_id, event, severity,
                                confidence, explanation, details_json FROM _batch_evidence;
                            """;
                        cmd.ExecuteNonQuery();
                    }

                    if (events.Count > 0)
                    {
                        cmd.Transaction = txn;
                        foreach (var ev in events)
                        {
                            cmd.CommandText = """
                                INSERT INTO events (timestamp_utc, category, message, severity, entity, details_json)
                                VALUES ($ts, $cat, $msg, $sev, $entity, $details);
                                """;
                            cmd.Parameters.Clear();
                            cmd.Parameters.AddWithValue("$ts", ev.TimestampUtc.ToString("o"));
                            cmd.Parameters.AddWithValue("$cat", ev.Category);
                            cmd.Parameters.AddWithValue("$msg", ev.Message);
                            cmd.Parameters.AddWithValue("$sev", (int)ev.Severity);
                            cmd.Parameters.AddWithValue("$entity", ev.Entity ?? (object)DBNull.Value);
                            cmd.Parameters.AddWithValue("$details", ev.DetailsJson is null ? (object)DBNull.Value : DetectionEngine.CapDetailsJson(ev.DetailsJson));
                            cmd.ExecuteNonQuery();
                        }
                    }

                    txn.Commit();
                }
                catch
                {
                    try
                    {
                        txn.Rollback();
                    }
                    catch
                    {
                    }
                    throw;
                }
            }
        }, ct).ConfigureAwait(false);
    }

    public List<Evidence> GetEvidence(string entityId, int limit = 200)
    {
        var list = new List<Evidence>();
        using var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM evidence WHERE entity_id = $eid ORDER BY timestamp_utc DESC LIMIT $limit;";
        cmd.Parameters.AddWithValue("$eid", entityId);
        cmd.Parameters.AddWithValue("$limit", limit);
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new Evidence
            {
                Source = r.GetString(1),
                Timestamp = DateTime.Parse(r.GetString(2), null, System.Globalization.DateTimeStyles.RoundtripKind),
                EntityType = r.GetString(3),
                EntityId = r.GetString(4),
                Event = r.GetString(5),
                Severity = (Severity)r.GetInt32(6),
                Confidence = r.GetDouble(7),
                Explanation = r.GetString(8),
                DetailsJson = r.IsDBNull(9) ? null : r.GetString(9),
            });
        }
        return list;
    }

    // ---------- scan jobs ----------

    public long HashCacheCount()
    {
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM hash_cache;";
        return (long)(cmd.ExecuteScalar() ?? 0L);
    }

    public long ScanJobCount()
    {
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM scan_jobs;";
        return (long)(cmd.ExecuteScalar() ?? 0L);
    }

    public void InsertScanJob(ScanJobRecord job)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT INTO scan_jobs (id, mode, started_utc, finished_utc, status, files_scanned,
                    findings_count, targets_json)
                VALUES ($id, $mode, $started, $finished, $status, $files, $findings, $targets);
                """;
            cmd.Parameters.AddWithValue("$id", job.Id);
            cmd.Parameters.AddWithValue("$mode", job.Mode);
            cmd.Parameters.AddWithValue("$started", job.StartedUtc.ToString("o"));
            cmd.Parameters.AddWithValue("$finished", job.FinishedUtc?.ToString("o") ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$status", job.Status);
            cmd.Parameters.AddWithValue("$files", job.FilesScanned);
            cmd.Parameters.AddWithValue("$findings", job.FindingsCount);
            cmd.Parameters.AddWithValue("$targets", job.TargetsJson ?? (object)DBNull.Value);
            cmd.ExecuteNonQuery();
        });
    }

    public void UpdateScanJob(string id, string status, long filesScanned, long findingsCount)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                UPDATE scan_jobs SET status = $status, files_scanned = $files,
                    findings_count = $findings, finished_utc = $finished WHERE id = $id;
                """;
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$files", filesScanned);
            cmd.Parameters.AddWithValue("$findings", findingsCount);
            cmd.Parameters.AddWithValue("$finished", DateTime.UtcNow.ToString("o"));
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        });
    }

    public List<ScanJobRecord> GetScanJobs(int limit = 50)
    {
        var list = new List<ScanJobRecord>();
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM scan_jobs ORDER BY started_utc DESC LIMIT $limit;";
        cmd.Parameters.AddWithValue("$limit", limit);
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new ScanJobRecord
            {
                Id = r.GetString(0),
                Mode = r.GetString(1),
                StartedUtc = DateTime.Parse(r.GetString(2), null, System.Globalization.DateTimeStyles.RoundtripKind),
                FinishedUtc = r.IsDBNull(3) ? null : DateTime.Parse(r.GetString(3), null, System.Globalization.DateTimeStyles.RoundtripKind),
                Status = r.GetString(4),
                FilesScanned = r.GetInt64(5),
                FindingsCount = r.GetInt64(6),
                TargetsJson = r.IsDBNull(7) ? null : r.GetString(7),
            });
        }
        return list;
    }

    // ---------- hash cache ----------

    public (string? Sha256, string? Sha1, string? Md5)? GetHashCache(string path, long size, DateTime lastWriteUtc)
    {
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sha256, sha1, md5 FROM hash_cache WHERE path = $p AND size = $s AND last_write_utc = $w;";
        cmd.Parameters.AddWithValue("$p", path);
        cmd.Parameters.AddWithValue("$s", size);
        cmd.Parameters.AddWithValue("$w", lastWriteUtc.ToString("o"));
        using var r = cmd.ExecuteReader();
        if (!r.Read())
        {
            return null;
        }
        return (r.IsDBNull(0) ? null : r.GetString(0),
                r.IsDBNull(1) ? null : r.GetString(1),
                r.IsDBNull(2) ? null : r.GetString(2));
    }

    public void SetHashCache(string path, long size, DateTime lastWriteUtc, string? sha256, string? sha1, string? md5)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT INTO hash_cache (path, size, last_write_utc, sha256, sha1, md5, first_seen_utc)
                VALUES ($p, $s, $w, $sha256, $sha1, $md5, $first)
                ON CONFLICT(path) DO UPDATE SET size = excluded.size, last_write_utc = excluded.last_write_utc,
                    sha256 = excluded.sha256, sha1 = excluded.sha1, md5 = excluded.md5;
                """;
            cmd.Parameters.AddWithValue("$p", path);
            cmd.Parameters.AddWithValue("$s", size);
            cmd.Parameters.AddWithValue("$w", lastWriteUtc.ToString("o"));
            cmd.Parameters.AddWithValue("$sha256", sha256 ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$sha1", sha1 ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$md5", md5 ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$first", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        });
    }

    // ---------- signer cache ----------

    public void ObserveSigner(string signer, string trustState)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT INTO signer_cache (signer, trust_state, observed_count, last_seen_utc)
                VALUES ($s, $t, 1, $now)
                ON CONFLICT(signer) DO UPDATE SET
                    observed_count = observed_count + 1,
                    last_seen_utc = excluded.last_seen_utc;
                """;
            cmd.Parameters.AddWithValue("$s", signer);
            cmd.Parameters.AddWithValue("$t", trustState);
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        });
    }

    // ---------- exclusions ----------

    public void AddExclusion(Exclusion ex)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT INTO exclusions (id, type, value, scope, added_by, added_at_utc, rationale)
                VALUES ($id, $type, $value, $scope, $by, $at, $why);
                """;
            cmd.Parameters.AddWithValue("$id", ex.Id);
            cmd.Parameters.AddWithValue("$type", (int)ex.Type);
            cmd.Parameters.AddWithValue("$value", ex.Value);
            cmd.Parameters.AddWithValue("$scope", ex.Scope ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$by", ex.AddedBy);
            cmd.Parameters.AddWithValue("$at", ex.AddedAtUtc.ToString("o"));
            cmd.Parameters.AddWithValue("$why", ex.Rationale ?? (object)DBNull.Value);
            cmd.ExecuteNonQuery();
        });
    }

    public void RemoveExclusion(string id)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = "DELETE FROM exclusions WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        });
    }

    public List<Exclusion> GetExclusions()
    {
        var list = new List<Exclusion>();
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM exclusions ORDER BY added_at_utc DESC;";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new Exclusion
            {
                Id = r.GetString(0),
                Type = (ExclusionType)r.GetInt32(1),
                Value = r.GetString(2),
                Scope = r.IsDBNull(3) ? null : r.GetString(3),
                AddedBy = r.GetString(4),
                AddedAtUtc = DateTime.Parse(r.GetString(5), null, System.Globalization.DateTimeStyles.RoundtripKind),
                Rationale = r.IsDBNull(6) ? null : r.GetString(6),
            });
        }
        return list;
    }

    // ---------- quarantine ----------

    public void InsertQuarantine(QuarantineItem item)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT INTO quarantine (id, original_path, stored_path, sha256, sha1, md5, size,
                    quarantined_at_utc, reason, signer_name, evidence_ids_json, status)
                VALUES ($id, $orig, $stored, $sha256, $sha1, $md5, $size, $at, $reason, $signer, $ev, $status);
                """;
            cmd.Parameters.AddWithValue("$id", item.Id);
            cmd.Parameters.AddWithValue("$orig", item.OriginalPath);
            cmd.Parameters.AddWithValue("$stored", item.StoredPath);
            cmd.Parameters.AddWithValue("$sha256", item.Sha256);
            cmd.Parameters.AddWithValue("$sha1", item.Sha1);
            cmd.Parameters.AddWithValue("$md5", item.Md5);
            cmd.Parameters.AddWithValue("$size", item.Size);
            cmd.Parameters.AddWithValue("$at", item.QuarantinedAtUtc.ToString("o"));
            cmd.Parameters.AddWithValue("$reason", item.Reason);
            cmd.Parameters.AddWithValue("$signer", item.SignerName ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$ev", item.EvidenceIdsJson ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$status", (int)item.Status);
            cmd.ExecuteNonQuery();
        });
    }

    public void UpdateQuarantineStatus(string id, QuarantineStatus status)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = "UPDATE quarantine SET status = $status WHERE id = $id;";
            cmd.Parameters.AddWithValue("$status", (int)status);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        });
    }

    public List<QuarantineItem> GetQuarantine()
    {
        var list = new List<QuarantineItem>();
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM quarantine ORDER BY quarantined_at_utc DESC;";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new QuarantineItem
            {
                Id = r.GetString(0),
                OriginalPath = r.GetString(1),
                StoredPath = r.GetString(2),
                Sha256 = r.GetString(3),
                Sha1 = r.GetString(4),
                Md5 = r.GetString(5),
                Size = r.GetInt64(6),
                QuarantinedAtUtc = DateTime.Parse(r.GetString(7), null, System.Globalization.DateTimeStyles.RoundtripKind),
                Reason = r.GetString(8),
                SignerName = r.IsDBNull(9) ? null : r.GetString(9),
                EvidenceIdsJson = r.IsDBNull(10) ? null : r.GetString(10),
                Status = (QuarantineStatus)r.GetInt32(11),
            });
        }
        return list;
    }

    // ---------- known-bad hash blacklist ----------

    /// <summary>Looks up a SHA-256 in the known-bad blacklist. Null when not listed.</summary>
    public BlacklistEntry? LookupBlacklist(string sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256))
        {
            return null;
        }
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sha256, verdict, label, category, added_by, added_at_utc FROM hash_blacklist WHERE sha256 = $h;";
        cmd.Parameters.AddWithValue("$h", sha256.ToLowerInvariant());
        using var r = cmd.ExecuteReader();
        if (!r.Read())
        {
            return null;
        }
        return new BlacklistEntry
        {
            Sha256 = r.GetString(0),
            Verdict = r.GetString(1),
            Label = r.GetString(2),
            Category = r.IsDBNull(3) ? null : r.GetString(3),
            AddedBy = r.GetString(4),
            AddedAtUtc = DateTime.Parse(r.GetString(5), null, System.Globalization.DateTimeStyles.RoundtripKind),
        };
    }

    public void UpsertBlacklist(string sha256, string verdict, string label, string? category, string addedBy)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT INTO hash_blacklist (sha256, verdict, label, category, added_by, added_at_utc)
                VALUES ($h, $v, $l, $c, $by, $now)
                ON CONFLICT(sha256) DO UPDATE SET
                    verdict = excluded.verdict, label = excluded.label,
                    category = excluded.category, added_by = excluded.added_by,
                    added_at_utc = excluded.added_at_utc;
                """;
            cmd.Parameters.AddWithValue("$h", sha256.ToLowerInvariant());
            cmd.Parameters.AddWithValue("$v", verdict);
            cmd.Parameters.AddWithValue("$l", label);
            cmd.Parameters.AddWithValue("$c", category ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$by", addedBy);
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        });
    }

    public void RemoveBlacklist(string sha256)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = "DELETE FROM hash_blacklist WHERE sha256 = $h;";
            cmd.Parameters.AddWithValue("$h", sha256.ToLowerInvariant());
            cmd.ExecuteNonQuery();
        });
    }

    public List<BlacklistEntry> GetBlacklist(int limit = 500)
    {
        var list = new List<BlacklistEntry>();
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sha256, verdict, label, category, added_by, added_at_utc FROM hash_blacklist ORDER BY added_at_utc DESC LIMIT $limit;";
        cmd.Parameters.AddWithValue("$limit", limit);
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new BlacklistEntry
            {
                Sha256 = r.GetString(0),
                Verdict = r.GetString(1),
                Label = r.GetString(2),
                Category = r.IsDBNull(3) ? null : r.GetString(3),
                AddedBy = r.GetString(4),
                AddedAtUtc = DateTime.Parse(r.GetString(5), null, System.Globalization.DateTimeStyles.RoundtripKind),
            });
        }
        return list;
    }

    // ---------- settings ----------

    public string? GetSetting(string key)
    {
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key = $k;";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void SetSetting(string key, string value)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = "INSERT INTO settings (key, value) VALUES ($k, $v) ON CONFLICT(key) DO UPDATE SET value = excluded.value;";
            cmd.Parameters.AddWithValue("$k", key);
            cmd.Parameters.AddWithValue("$v", value);
            cmd.ExecuteNonQuery();
        });
    }

    // ---------- events ----------

    public void AppendEvent(SentinelEvent ev)
    {
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = """
                INSERT INTO events (timestamp_utc, category, message, severity, entity, details_json)
                VALUES ($ts, $cat, $msg, $sev, $entity, $details);
                """;
            cmd.Parameters.AddWithValue("$ts", ev.TimestampUtc.ToString("o"));
            cmd.Parameters.AddWithValue("$cat", ev.Category);
            cmd.Parameters.AddWithValue("$msg", ev.Message);
            cmd.Parameters.AddWithValue("$sev", (int)ev.Severity);
            cmd.Parameters.AddWithValue("$entity", ev.Entity ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$details", ev.DetailsJson is null ? (object)DBNull.Value : DetectionEngine.CapDetailsJson(ev.DetailsJson));
            cmd.ExecuteNonQuery();
        });
    }

    public List<SentinelEvent> GetEvents(int limit = 200, string? category = null)
    {
        var list = new List<SentinelEvent>();
        using var conn = NewReader();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = category is null
            ? "SELECT * FROM events ORDER BY id DESC LIMIT $limit;"
            : "SELECT * FROM events WHERE category = $cat ORDER BY id DESC LIMIT $limit;";
        cmd.Parameters.AddWithValue("$limit", limit);
        if (category is not null)
        {
            cmd.Parameters.AddWithValue("$cat", category);
        }
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new SentinelEvent
            {
                Id = r.GetInt64(0),
                TimestampUtc = DateTime.Parse(r.GetString(1), null, System.Globalization.DateTimeStyles.RoundtripKind),
                Category = r.GetString(2),
                Message = r.GetString(3),
                Severity = (EventSeverity)r.GetInt32(4),
                Entity = r.IsDBNull(5) ? null : r.GetString(5),
                DetailsJson = r.IsDBNull(6) ? null : r.GetString(6),
            });
        }
        return list;
    }

    // ---------- batching DB cleaner ----------

    /// <summary>
    /// Batched backstop that keeps the store bounded even if a caller bypasses
    /// the batching pump: trims events/evidence past their caps, checkpoints the
    /// WAL, and VACUUMs only when the file has materially wasted pages. Runs on
    /// a timer once per minute at most (no per-insert trims).
    /// </summary>
    public async Task CleanupAsync(CancellationToken ct)
    {
        long rows = await CleanupRowsAsync(ct).ConfigureAwait(false);
        await CheckpointAndVacuumAsync(ct).ConfigureAwait(false);
        if (rows > 0)
        {
            AppendEvent(new SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "system",
                Message = $"Store cleanup trimmed {rows} rows.",
                Severity = EventSeverity.Info,
            });
        }
    }

    /// <summary>
    /// Trims evidence/events that exceed their caps. Runs inside the cleaner's
    /// writer session (like the constructor's initialization); committed rows
    /// stay valid. Never evicts findings or quarantine (critical data).
    /// </summary>
    private Task<long> CleanupRowsAsync(CancellationToken ct)
    {
        return Task.Run(() =>
        {
            lock (_writeLock)
            {
                using var cmd = _writer.CreateCommand();
                cmd.CommandText = "PRAGMA busy_timeout=15000;";
                cmd.ExecuteNonQuery();

                // The batch temp table may not exist yet (cleaner ran before any
                // batch insert). Clearing it at trim time is only belt-and-suspenders.
                try
                {
                    cmd.CommandText = "DELETE FROM _batch_evidence;";
                    cmd.ExecuteNonQuery();
                }
                catch (SqliteException)
                {
                }

                long deleted = 0;
                foreach (var (table, maxRows) in new (string, int)[] { ("events", MaxEventRows), ("evidence", MaxEvidenceRows) })
                {
                    // Trim down to the cap exactly; re-runs every minute handle
                    // whatever the batched pump added in between.
                    cmd.CommandText = $"""
                        DELETE FROM {table} WHERE id IN (
                            SELECT id FROM {table} ORDER BY id DESC LIMIT -1 OFFSET $max
                        );
                        """;
                    cmd.Parameters.Clear();
                    cmd.Parameters.AddWithValue("$max", Math.Max(maxRows, 1));
                    deleted += cmd.ExecuteNonQuery();
                }

                // Findings: retention by user status + age. User decisions are
                // kept longest for open (New/Quarantined) items; reviewable
                // statuses age out quickly; a hard row cap bounds everything.
                cmd.Parameters.Clear();
                cmd.CommandText = """
                    DELETE FROM findings WHERE status IN (1, 2, 4)
                        AND (last_seen_utc IS NOT NULL AND last_seen_utc < $cutReview);
                    """;
                cmd.Parameters.AddWithValue("$cutReview", DateTime.UtcNow.AddDays(-FindingsReviewKeepDays).ToString("o"));
                deleted += cmd.ExecuteNonQuery();

                cmd.Parameters.Clear();
                cmd.CommandText = """
                    DELETE FROM findings WHERE status IN (0, 3)
                        AND COALESCE(last_seen_utc, first_seen_utc) < $cutOpen;
                    """;
                cmd.Parameters.AddWithValue("$cutOpen", DateTime.UtcNow.AddDays(-FindingsOpenKeepDays).ToString("o"));
                deleted += cmd.ExecuteNonQuery();

                cmd.Parameters.Clear();
                cmd.CommandText = """
                    DELETE FROM findings WHERE id IN (
                        SELECT id FROM findings ORDER BY risk_score ASC, first_seen_utc ASC LIMIT -1 OFFSET $max
                    );
                    """;
                cmd.Parameters.AddWithValue("$max", Math.Max(MaxFindingRows, 1));
                deleted += cmd.ExecuteNonQuery();

                // Scan jobs: keep the newest N.
                cmd.Parameters.Clear();
                cmd.CommandText = """
                    DELETE FROM scan_jobs WHERE id IN (
                        SELECT id FROM scan_jobs ORDER BY started_utc DESC LIMIT -1 OFFSET $max
                    );
                    """;
                cmd.Parameters.AddWithValue("$max", Math.Max(MaxScanJobRows, 1));
                deleted += cmd.ExecuteNonQuery();

                // Hash cache: keep the most-recently-seen N entries.
                cmd.Parameters.Clear();
                cmd.CommandText = """
                    DELETE FROM hash_cache WHERE path IN (
                        SELECT path FROM hash_cache ORDER BY first_seen_utc ASC LIMIT -1 OFFSET $max
                    );
                    """;
                cmd.Parameters.AddWithValue("$max", Math.Max(MaxHashCacheRows, 1));
                deleted += cmd.ExecuteNonQuery();

                return deleted;
            }
        }, ct);
    }

    /// <summary>Checkpoints the WAL with retries, then VACUUMs only if page waste is material.</summary>
    private async Task CheckpointAndVacuumAsync(CancellationToken ct)
    {
        long dbSizeBytes = 0;
        long freelistCount = 0;
        long pageCount = 0;
        long pageSize = 0;
        ExecuteWriter(cmd =>
        {
            cmd.CommandText = "PRAGMA busy_timeout=15000;";
            cmd.ExecuteNonQuery();

            cmd.CommandText = "PRAGMA page_count;";
            pageCount = (long)(cmd.ExecuteScalar() ?? 0L);
            cmd.CommandText = "PRAGMA page_size;";
            pageSize = (long)(cmd.ExecuteScalar() ?? 4096L);
            cmd.CommandText = "PRAGMA freelist_count;";
            freelistCount = (long)(cmd.ExecuteScalar() ?? 0L);

            // Deadline retries, WAL mode exclusive, then release.
            cmd.CommandText = "PRAGMA wal_checkpoint(PASSIVE);";
            for (int i = 0; i < 5; i++)
            {
                using var r = cmd.ExecuteReader();
                bool busy = false;
                while (r.Read())
                {
                    busy = r.GetInt32(1) != 0;
                }
                if (!busy)
                {
                    break;
                }
                Thread.Sleep(100);
            }
        });

        dbSizeBytes = pageCount * pageSize;
        if (dbSizeBytes < TrimLowWaterMarkBytes)
        {
            return; // tiny store — nothing to shrink.
        }
        if (freelistCount * pageSize < Math.Max(dbSizeBytes / 2, 1))
        {
            return; // less than 50% waste — VACUUM would not pay off.
        }

        // VACUUM needs the whole DB to itself.
        await _cleanerGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            lock (_writeLock)
            {
                using var cmd = _writer.CreateCommand();
                cmd.CommandText = "PRAGMA busy_timeout=15000;";
                cmd.ExecuteNonQuery();
                cmd.CommandText = "VACUUM;";
                cmd.ExecuteNonQuery();
            }
        }
        finally
        {
            _cleanerGate.Release();
        }
    }

    // ---------- helpers ----------

    private void ExecuteWriter(Action<SqliteCommand> action)
    {
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            action(cmd);
        }
    }

    private SqliteConnection NewReader()
    {
        var conn = new SqliteConnection($"Data Source={_dbPath};Mode=ReadOnly");
        conn.Open();
        return conn;
    }

    public void Dispose()
    {
        try
        {
            using var cmd = _writer.CreateCommand();
            cmd.CommandText = "PRAGMA busy_timeout=15000;";
            cmd.ExecuteNonQuery();
            cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            cmd.ExecuteNonQuery();
        }
        catch
        {
        }
        _cleanerGate.Dispose();
        _writer.Dispose();
    }
}