namespace Sentinel.Core.Models;

/// <summary>Result of the read-only system security audit.</summary>
public sealed record SystemAuditResult
{
    public required DateTime AuditedAtUtc { get; init; }

    // OS information
    public string? OsVersion { get; init; }
    public string? OsBuild { get; init; }
    public string? OsEdition { get; init; }
    public bool IsServer { get; init; }
    public DateTime? InstallDateUtc { get; init; }
    public DateTime? LastBootUtc { get; init; }

    // Update posture
    public DateTime? LastUpdateInstalledUtc { get; init; }
    public int? DaysSinceLastUpdate { get; init; }
    public int? InstalledUpdatesLast90Days { get; init; }
    public bool UpdateServiceEnabled { get; init; }

    // Defender state
    public bool? DefenderEnabled { get; init; }
    public string? DefenderStatus { get; init; }
    public string? DefenderSignatureVersion { get; init; }
    public DateTime? DefenderSignatureAge { get; init; }

    // Firewall
    public bool? FirewallEnabled { get; init; }
    public bool? FirewallPublicEnabled { get; init; }
    public bool? FirewallPrivateEnabled { get; init; }
    public bool? FirewallDomainEnabled { get; init; }
    public int FirewallRuleCount { get; init; }

    // UAC
    public int? UacLevel { get; init; }
    public bool? UacEnabled { get; init; }

    // Accounts
    public int LocalAdminCount { get; init; }
    public IReadOnlyList<string> LocalAdmins { get; init; } = [];
    public bool GuestEnabled { get; init; }

    // Exposure
    public bool RdpEnabled { get; init; }
    public bool SmbEnabled { get; init; }
    public bool RdpExposedToPublic { get; init; }
    public bool SmbExposedToPublic { get; init; }
    public IReadOnlyList<int> PublicListeningPorts { get; init; } = [];

    // Misc
    public bool SecureBootEnabled { get; init; }
    public bool TpmPresent { get; init; }
    public bool BitLockerEnabled { get; init; }
    public bool IsAdministrator { get; init; }

    /// <summary>Human-readable notes about weak or notable findings.</summary>
    public IReadOnlyList<string> Findings { get; init; } = [];
    public string? Error { get; init; }
}