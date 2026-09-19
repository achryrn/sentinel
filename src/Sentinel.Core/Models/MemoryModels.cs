namespace Sentinel.Core.Models;

/// <summary>A single committed memory region of a process.</summary>
public sealed record MemoryRegion
{
    public required ulong BaseAddress { get; init; }
    public required ulong RegionSize { get; init; }
    public required string State { get; init; }          // Commit / Reserve / Free
    public required string Type { get; init; }          // Private / Image / Mapped
    public required string Protect { get; init; }       // e.g. "RW", "RX", "RWX", "Guard"
    public required uint ProtectRaw { get; init; }
    public bool IsExecutable { get; init; }
    public bool IsWritable { get; init; }
    public bool IsGuard { get; init; }
    public bool IsPrivate { get; init; }
    public bool IsImage { get; init; }
    public bool IsMapped { get; init; }
    public double? Entropy { get; init; }               // sampled, null when not sampled
    public string? MappedImagePath { get; init; }       // for MEM_IMAGE regions, best-effort
}

/// <summary>A thread's start address, used to detect suspicious execution origins.</summary>
public sealed record ThreadStartInfo
{
    public required uint ThreadId { get; init; }
    public required ulong StartAddress { get; init; }
    public string? ModuleName { get; init; }            // module containing the start address, if any
    public bool IsInModule { get; init; }
    public bool IsInExecutableRegion { get; init; }
}

/// <summary>Result of a memory analysis pass over one process.</summary>
public sealed record MemoryAnalysisResult
{
    public required uint Pid { get; init; }
    public required string ProcessName { get; init; }
    public IReadOnlyList<MemoryRegion> Regions { get; init; } = [];
    public IReadOnlyList<ThreadStartInfo> ThreadStarts { get; init; } = [];

    /// <summary>Regions that are both private and executable (RWX or RX private) — injection signal.</summary>
    public IReadOnlyList<MemoryRegion> SuspiciousRegions { get; init; } = [];

    /// <summary>Threads whose start address is outside any loaded module — injection signal.</summary>
    public IReadOnlyList<ThreadStartInfo> SuspiciousThreads { get; init; } = [];

    public long TotalPrivateBytes { get; init; }
    public long TotalExecutableBytes { get; init; }
    public long TotalPrivateExecutableBytes { get; init; }
    public int RegionCount { get; init; }
    public bool AccessDenied { get; init; }
    public string? Error { get; init; }
}

/// <summary>Result of a memory dump attempt.</summary>
public sealed record MemoryDumpResult
{
    public required uint Pid { get; init; }
    public required bool Success { get; init; }
    public string? OutputPath { get; init; }
    public long BytesWritten { get; init; }
    public string? Error { get; init; }
    public bool IsProtectedProcess { get; init; }
}