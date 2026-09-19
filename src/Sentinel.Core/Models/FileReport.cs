using Sentinel.Core.Hashing;
using Sentinel.Core.Pe;
using Sentinel.Core.Signing;

namespace Sentinel.Core.Models;

/// <summary>Result of analyzing a single file.</summary>
public sealed class FileReport
{
    public required string Path { get; init; }
    public required string FileName { get; init; }
    public required long Size { get; init; }
    public required DateTime CreationTimeUtc { get; init; }
    public required DateTime LastWriteTimeUtc { get; init; }
    public required DateTime LastAccessTimeUtc { get; init; }

    /// <summary>True when the file is a directory.</summary>
    public bool IsDirectory { get; init; }

    /// <summary>True when the file is a PE image (executable/dll/sys).</summary>
    public bool IsPe { get; init; }

    /// <summary>SHA-256 hash (lowercase hex), when computed.</summary>
    public string? Sha256 { get; init; }

    /// <summary>SHA-1 hash, when computed.</summary>
    public string? Sha1 { get; init; }

    /// <summary>MD5 hash, when computed.</summary>
    public string? Md5 { get; init; }

    /// <summary>Authenticode status, when checked.</summary>
    public SignatureStatus SignatureStatus { get; init; } = SignatureStatus.Unknown;

    /// <summary>Signer display name, when available.</summary>
    public string? SignerName { get; init; }

    /// <summary>PE parse result, when the file is a PE image.</summary>
    public PeInfo? Pe { get; init; }

    /// <summary>Alternate data streams (name + size).</summary>
    public IReadOnlyList<AdDataStream> AlternateDataStreams { get; init; } = [];

    /// <summary>True when the file carries a Mark-of-the-Web (Zone.Identifier ADS).</summary>
    public bool HasMotw { get; init; }

    /// <summary>Zone id from MOTW (3 = Internet, 4 = Restricted, etc.), when present.</summary>
    public int? MotwZoneId { get; init; }

    /// <summary>Referrer URL from MOTW, when present.</summary>
    public string? MotwReferrerUrl { get; init; }

    /// <summary>Shannon entropy of the whole file (bits/byte), when computed.</summary>
    public double? Entropy { get; init; }

    /// <summary>True when the file is hidden or system-flagged.</summary>
    public bool IsHiddenOrSystem { get; init; }

    /// <summary>True when the file is a reparse point (symlink/junction).</summary>
    public bool IsReparsePoint { get; init; }

    /// <summary>True when the file is excluded by an active exclusion rule.</summary>
    public bool IsExcluded { get; init; }

    /// <summary>Human-readable summary of notable characteristics.</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>Label of the known-bad hash match, when the SHA-256 is on the blacklist.</summary>
    public string? KnownMalwareLabel { get; init; }
}

/// <summary>An alternate data stream (ADS) on a file.</summary>
public sealed record AdDataStream
{
    public required string Name { get; init; }
    public required long Size { get; init; }
}

/// <summary>An auditable exclusion rule.</summary>
public sealed class Exclusion
{
    public required string Id { get; init; }
    public required ExclusionType Type { get; init; }
    public required string Value { get; init; }
    public string? Scope { get; init; }
    public required string AddedBy { get; init; }
    public required DateTime AddedAtUtc { get; init; }
    public string? Rationale { get; init; }
}

public enum ExclusionType
{
    Path,
    Hash,
    Signer,
    Process,
}

/// <summary>Progress of a scan job.</summary>
public sealed class ScanProgress
{
    public required ScanState State { get; init; }
    public long FilesTotal { get; init; }
    public long FilesProcessed { get; init; }
    public long BytesProcessed { get; init; }
    public string? CurrentItem { get; init; }
    public double? Percent { get; init; }
    public double FilesPerSecond { get; init; }
    public TimeSpan? Eta { get; init; }
}

public enum ScanState
{
    Queued,
    Running,
    Paused,
    Cancelled,
    Completed,
    Failed,
}