namespace Sentinel.Core.Models;

/// <summary>Severity of an evidence item or finding.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>Lifecycle status of a finding.</summary>
public enum FindingStatus
{
    New,
    Reviewed,
    Allowed,
    Quarantined,
    FalsePositive,
}

/// <summary>One observation from a scanner subsystem.</summary>
public sealed record Evidence
{
    public required string Source { get; init; }          // "file", "process", "memory", "network", "persistence", "system", "realtime"
    public required DateTime Timestamp { get; init; }
    public required string EntityType { get; init; }      // "file", "pid", "connection", "persistence", "system"
    public required string EntityId { get; init; }        // file path | pid | connection key | persistence key
    public required string Event { get; init; }           // rule name, e.g. "rwx-private-executable-region"
    public required Severity Severity { get; init; }
    public required double Confidence { get; init; }      // 0..1
    public required string Explanation { get; init; }
    public string? DetailsJson { get; init; }
    public IReadOnlyList<string> RelatedEvidenceIds { get; init; } = [];

    /// <summary>Computed identity used for correlation and deduplication.</summary>
    public string Key => $"{EntityType}|{EntityId}|{Event}";
}

/// <summary>A correlated conclusion about one entity.</summary>
public sealed record Finding
{
    public required string Id { get; init; }
    public required IReadOnlyList<string> EvidenceIds { get; init; }
    public required string EntityKey { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public required double Confidence { get; init; }
    public required IReadOnlyList<string> Reasons { get; init; }
    public required IReadOnlyList<string> MitreTactics { get; init; }
    public required string RecommendedAction { get; init; }
    public FindingStatus Status { get; init; } = FindingStatus.New;
    public required DateTime FirstSeenUtc { get; init; }
    public DateTime? LastSeenUtc { get; init; }
    public int OccurrenceCount { get; init; } = 1;

    /// <summary>Total risk score (0..100), derived from severity × confidence × weight with capping.</summary>
    public double RiskScore { get; init; }
}

/// <summary>Aggregated risk score for one entity.</summary>
public sealed record RiskAssessment
{
    public required string EntityKey { get; init; }
    public required double Score { get; init; }           // 0..100
    public required Severity Severity { get; init; }
    public required IReadOnlyList<string> Reasons { get; init; }
    public required IReadOnlyList<Evidence> Evidence { get; init; }
}

/// <summary>Result of one detection pass over a batch of evidence.</summary>
public sealed record DetectionResult
{
    public required IReadOnlyList<Evidence> Evidence { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required IReadOnlyList<RiskAssessment> RiskAssessments { get; init; }
}