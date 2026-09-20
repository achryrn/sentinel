using Sentinel.Core.Signing;

namespace Sentinel.Core.Models;

/// <summary>
/// Result of cross-checking two independent process views (Toolhelp32 vs WMI).
/// A process visible in exactly one view is anomalous - a signature of userland
/// process-hiding (rootkit artifacts) or of an instrumentation gap.
/// </summary>
public sealed record ProcessViewDiscrepancy
{
    public bool ToolhelpSucceeded { get; init; }
    public bool WmiSucceeded { get; init; }
    public IReadOnlyList<uint> OnlyToolhelpPids { get; init; } = [];
    public IReadOnlyList<uint> OnlyWmiPids { get; init; } = [];
}

/// <summary>Information about a running process.</summary>
public sealed record ProcessInfo
{
    public required uint Pid { get; init; }
    public required string Name { get; init; }
    public string? ExecutablePath { get; init; }
    public uint? ParentPid { get; init; }
    public string? ParentName { get; init; }
    public string? CommandLine { get; init; }
    public string? UserName { get; init; }
    public uint? SessionId { get; init; }
    public DateTime? StartTimeUtc { get; init; }
    public long? WorkingSetBytes { get; init; }
    public long? PrivateBytes { get; init; }
    public int? BasePriority { get; init; }
    public uint? ThreadCount { get; init; }
    public bool IsElevated { get; init; }
    public bool Is64Bit { get; init; }
    public bool IsWow64 { get; init; }
    public bool IsProtectedProcess { get; init; }
    public bool IsSystemProcess { get; init; }

    /// <summary>Signature status of the main executable, when checked.</summary>
    public SignatureStatus SignatureStatus { get; init; } = SignatureStatus.Unknown;
    public string? SignerName { get; init; }

    /// <summary>SHA-256 of the main executable, when computed.</summary>
    public string? Sha256 { get; init; }

    /// <summary>Loaded modules (name + path), when enumerable.</summary>
    public IReadOnlyList<ProcessModuleInfo> Modules { get; init; } = [];

    /// <summary>Human-readable notes (e.g., "elevated", "unsigned", "unusual parent").</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];
}

/// <summary>A module (DLL) loaded into a process.</summary>
public sealed record ProcessModuleInfo
{
    public required string Name { get; init; }
    public required string Path { get; init; }
    public required ulong BaseAddress { get; init; }
    public required uint Size { get; init; }
}