namespace Sentinel.Core.Models;

/// <summary>Severity of an event in the event log.</summary>
public enum EventSeverity
{
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
}

/// <summary>One entry in the persisted event log tail.</summary>
public sealed record SentinelEvent
{
    /// <summary>Auto-increment id; 0 when not yet persisted.</summary>
    public long Id { get; init; }
    public required DateTime TimestampUtc { get; init; }
    public required string Category { get; init; }      // scan | detection | quarantine | exclusion | system | realtime
    public required string Message { get; init; }
    public EventSeverity Severity { get; init; } = EventSeverity.Info;
    public string? Entity { get; init; }
    public string? DetailsJson { get; init; }
}

/// <summary>One quarantined item.</summary>
public sealed record QuarantineItem
{
    public required string Id { get; init; }
    public required string OriginalPath { get; init; }
    public required string StoredPath { get; init; }
    public required string Sha256 { get; init; }
    public required string Sha1 { get; init; }
    public required string Md5 { get; init; }
    public required long Size { get; init; }
    public required DateTime QuarantinedAtUtc { get; init; }
    public required string Reason { get; init; }
    public string? SignerName { get; init; }
    public string? EvidenceIdsJson { get; init; }
    public required QuarantineStatus Status { get; init; }
}

public enum QuarantineStatus
{
    Quarantined,
    Restored,
    Deleted,
}

/// <summary>A scan job record.</summary>
public sealed record ScanJobRecord
{
    public required string Id { get; init; }
    public required string Mode { get; init; }
    public required DateTime StartedUtc { get; init; }
    public DateTime? FinishedUtc { get; init; }
    public required string Status { get; init; }        // Queued/Running/Completed/Cancelled/Failed
    public long FilesScanned { get; init; }
    public long FindingsCount { get; init; }
    public string? TargetsJson { get; init; }
}

/// <summary>A stored finding (persisted copy of the correlated finding).</summary>
public sealed record StoredFinding
{
    public required string Id { get; init; }
    public required string EntityKey { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required double Confidence { get; init; }
    public required double RiskScore { get; init; }
    public required string ReasonsJson { get; init; }
    public required string MitreTacticsJson { get; init; }
    public required string RecommendedAction { get; init; }
    public required FindingStatus Status { get; init; }
    public required DateTime FirstSeenUtc { get; init; }
    public DateTime? LastSeenUtc { get; init; }
    public int OccurrenceCount { get; init; }
}

/// <summary>One known-bad SHA-256 entry.</summary>
public sealed record BlacklistEntry
{
    public required string Sha256 { get; init; }
    public required string Verdict { get; init; }
    public required string Label { get; init; }
    public string? Category { get; init; }
    public string? AddedBy { get; init; }
    public DateTime? AddedAtUtc { get; init; }
}