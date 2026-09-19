namespace Sentinel.Core.Models;

/// <summary>Category of persistence mechanism.</summary>
public enum PersistenceCategory
{
    RunKey,
    StartupFolder,
    Winlogon,
    ImageFileExecutionOptions,
    AppInitDll,
    BootExecute,
    Service,
    ScheduledTask,
    WmiSubscription,
    ShellExtension,
    BrowserExtension,
    Rdp,
    LogonScript,
    Other,
}

/// <summary>One persistence mechanism found on the system.</summary>
public sealed record PersistenceEntry
{
    public required PersistenceCategory Category { get; init; }
    public required string Name { get; init; }
    public required string Location { get; init; }
    public string? Command { get; init; }
    public string? Arguments { get; init; }
    public string? TargetPath { get; init; }        // resolved executable path when derivable
    public bool TargetExists { get; init; }
    public bool IsEnabled { get; init; } = true;
    public string? User { get; init; }              // which user scope (HKLM/HKCU/SYSTEM/user)
    public string? Hash { get; init; }              // SHA-256 of target when computed
    public string? Signer { get; init; }            // signer name when verified
    public IReadOnlyList<string> Notes { get; init; } = [];
}

/// <summary>Full persistence scan result.</summary>
public sealed record PersistenceScanResult
{
    public required DateTime ScannedAtUtc { get; init; }
    public IReadOnlyList<PersistenceEntry> Entries { get; init; } = [];
    public int TotalCount => Entries.Count;
    public string? Error { get; init; }
}