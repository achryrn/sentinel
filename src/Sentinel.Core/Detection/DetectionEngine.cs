using System.Text.Json;
using Sentinel.Core.Hashing;
using Sentinel.Core.Json;
using Sentinel.Core.Models;
using Sentinel.Core.Pe;
using Sentinel.Core.Signing;

namespace Sentinel.Core.Detection;

/// <summary>
/// The detection engine: converts raw scanner outputs (FileReport, ProcessInfo,
/// MemoryAnalysisResult, NetworkSnapshot, PersistenceScanResult, SystemAuditResult)
/// into normalized <see cref="Evidence"/> items by applying a catalog of weighted,
/// explainable rules. Rules never produce verdicts on their own — they emit
/// evidence that the correlation engine and risk assessor combine.
/// </summary>
public sealed class DetectionEngine
{
    /// <summary>MITRE ATT&CK tactic tags used in findings.</summary>
    public static class Tactics
    {
        public const string Execution = "Execution";
        public const string Persistence = "Persistence";
        public const string PrivilegeEscalation = "Privilege Escalation";
        public const string DefenseEvasion = "Defense Evasion";
        public const string CredentialAccess = "Credential Access";
        public const string Discovery = "Discovery";
        public const string LateralMovement = "Lateral Movement";
        public const string Collection = "Collection";
        public const string CommandAndControl = "Command and Control";
        public const string Exfiltration = "Exfiltration";
        public const string Impact = "Impact";
        public const string InitialAccess = "Initial Access";
    }

    private static readonly JsonSerializerOptions s_json = new()
    {
        WriteIndented = false,
        Converters = { new IpAddressConverter() },
    };

    // ---------- file evidence ----------

    public static Evidence? FileUnsignedExecutable(FileReport f)
    {
        if (!f.IsPe || f.SignatureStatus != SignatureStatus.Unsigned)
        {
            return null;
        }
        if (string.IsNullOrEmpty(f.Path) || IsKnownSystemPath(f.Path))
        {
            return null;
        }
        return Ev("file", f.Path, "unsigned-executable", Severity.Low, 0.5,
            $"Executable '{f.FileName}' is unsigned.", f);
    }

    public static Evidence? FileSignatureInvalid(FileReport f)
    {
        if (!f.IsPe || f.SignatureStatus != SignatureStatus.SignatureInvalid)
        {
            return null;
        }
        return Ev("file", f.Path, "invalid-signature", Severity.High, 0.8,
            $"Executable '{f.FileName}' has an invalid or broken digital signature.", f);
    }

    public static Evidence? FileUntrustedSigner(FileReport f)
    {
        if (!f.IsPe || f.SignatureStatus != SignatureStatus.SignedUntrusted)
        {
            return null;
        }
        return Ev("file", f.Path, "untrusted-signer", Severity.Medium, 0.6,
            $"Executable '{f.FileName}' is signed by an untrusted/unrecognized signer.", f);
    }

    public static Evidence? FileHighEntropy(FileReport f)
    {
        if (f.Entropy is null || f.Entropy < Entropy.HighEntropyThreshold || !f.IsPe)
        {
            return null;
        }
        if (f.Size < 16 * 1024)
        {
            return null; // small files are naturally high-entropy
        }
        return Ev("file", f.Path, "high-entropy-pe", Severity.Medium, 0.55,
            $"PE file '{f.FileName}' has whole-file entropy {f.Entropy:F2} bits/byte — possible packing/encryption.", f);
    }

    public static Evidence? FileRwxSection(FileReport f)
    {
        var pe = f.Pe;
        if (pe?.Status != PeParseStatus.Ok)
        {
            return null;
        }
        var rwx = pe.Sections.FirstOrDefault(s => s.IsExecutable && s.IsWritable);
        if (rwx is null)
        {
            return null;
        }
        return Ev("file", f.Path, "rwx-section", Severity.Medium, 0.6,
            $"PE section '{rwx.Name}' is both writable and executable (RWX) — classic shellcode habitat.", f,
            tactics: [Tactics.DefenseEvasion]);
    }

    public static Evidence? FileSectionRuntimeGrowth(FileReport f)
    {
        var pe = f.Pe;
        if (pe?.Status != PeParseStatus.Ok)
        {
            return null;
        }
        var grown = pe.Sections.FirstOrDefault(s => s.HasRuntimeGrowth);
        if (grown is null)
        {
            return null;
        }
        return Ev("file", f.Path, "section-runtime-growth", Severity.Low, 0.45,
            $"PE section '{grown.Name}' virtual size exceeds raw size — runtime growth (possible unpacking).", f);
    }

    public static Evidence? FileOverlay(FileReport f)
    {
        var pe = f.Pe;
        if (pe?.Status != PeParseStatus.Ok || pe.OverlaySize < 256)
        {
            return null;
        }
        return Ev("file", f.Path, "pe-overlay", Severity.Low, 0.4,
            $"PE file has {pe.OverlaySize} bytes of overlay data past the last section (possible embedded payload).", f);
    }

    public static Evidence? FileTlsCallbacks(FileReport f)
    {
        var pe = f.Pe;
        if (pe?.Status != PeParseStatus.Ok || pe.TlsCallbacks.Count == 0)
        {
            return null;
        }
        return Ev("file", f.Path, "tls-callbacks", Severity.Low, 0.5,
            $"PE file declares {pe.TlsCallbacks.Count} TLS callback(s) — code runs before the entry point.", f,
            tactics: [Tactics.DefenseEvasion]);
    }

    public static Evidence? FileNoAslr(FileReport f)
    {
        var pe = f.Pe;
        if (pe?.Status != PeParseStatus.Ok || pe.HasAslr)
        {
            return null;
        }
        return Ev("file", f.Path, "no-aslr", Severity.Low, 0.35,
            $"PE file '{f.FileName}' lacks ASLR (DYNAMIC_BASE) — DEP/ASLR bypass potential.", f);
    }

    public static Evidence? FileNoNx(FileReport f)
    {
        var pe = f.Pe;
        if (pe?.Status != PeParseStatus.Ok || pe.HasNxCompat)
        {
            return null;
        }
        return Ev("file", f.Path, "no-nx", Severity.Low, 0.35,
            $"PE file '{f.FileName}' lacks NX_COMPAT — DEP bypass potential.", f);
    }

    public static Evidence? FileTimestampAnomaly(FileReport f)
    {
        var pe = f.Pe;
        if (pe?.Status != PeParseStatus.Ok || string.IsNullOrEmpty(pe.TimestampAnomaly))
        {
            return null;
        }
        return Ev("file", f.Path, "timestamp-anomaly", Severity.Low, 0.5,
            $"PE file '{f.FileName}' has an anomalous link timestamp (zero/future/epoch) — often seen in re-packed malware.", f);
    }

    public static Evidence? FileFromInternet(FileReport f)
    {
        if (!f.HasMotw)
        {
            return null;
        }
        return Ev("file", f.Path, "motw-internet", Severity.Low, 0.6,
            $"File '{f.FileName}' was downloaded from the internet (Zone {f.MotwZoneId}).", f,
            tactics: [Tactics.InitialAccess]);
    }

    public static Evidence? FileHiddenSystem(FileReport f)
    {
        if (!f.IsHiddenOrSystem)
        {
            return null;
        }
        return Ev("file", f.Path, "hidden-system-file", Severity.Low, 0.45,
            $"File '{f.FileName}' is hidden or system-flagged in an unusual location.", f,
            tactics: [Tactics.DefenseEvasion]);
    }

    public static Evidence? FileSuspiciousLocation(FileReport f)
    {
        var path = f.Path;
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }
        string[] suspicious = [
            @"\appdata\roaming\microsoft\windows\start menu",
            @"\appdata\roaming\microsoft\windows\start menu\programs\startup",
            @"\programdata\microsoft\windows\start menu\programs\startup",
            @"\users\public",
            @"\windows\temp",
            @"\appdata\local\temp",
        ];
        string lower = path.ToLowerInvariant();
        if (suspicious.Any(s => lower.Contains(s, StringComparison.Ordinal)))
        {
            return Ev("file", f.Path, "suspicious-location", Severity.Low, 0.45,
                $"Executable '{f.FileName}' is in a location commonly abused for persistence.", f,
                tactics: [Tactics.Persistence]);
        }
        return null;
    }

    // ---------- process evidence ----------

    public static Evidence? ProcessUnsigned(ProcessInfo p)
    {
        if (p.SignatureStatus != SignatureStatus.Unsigned)
        {
            return null;
        }
        return Ev("process", p.Pid.ToString(), "process-unsigned", Severity.Low, 0.5,
            $"Process '{p.Name}' (PID {p.Pid}) is unsigned.", p);
    }

    public static Evidence? ProcessElevated(ProcessInfo p)
    {
        if (!p.IsElevated)
        {
            return null;
        }
        return Ev("process", p.Pid.ToString(), "process-elevated", Severity.Info, 0.9,
            $"Process '{p.Name}' (PID {p.Pid}) is running elevated.", p,
            tactics: [Tactics.PrivilegeEscalation]);
    }

    public static Evidence? ProcessSystemLocation(ProcessInfo p)
    {
        var path = p.ExecutablePath;
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }
        string lower = path.ToLowerInvariant();
        bool system = lower.StartsWith(@"c:\windows", StringComparison.Ordinal)
            || lower.StartsWith(@"c:\program files", StringComparison.Ordinal)
            || lower.StartsWith(@"c:\program files (x86)", StringComparison.Ordinal);
        if (system)
        {
            return null;
        }
        string[] suspicious = [@"\appdata\", @"\users\public\", @"\windows\temp", @"\temp\", @"\programdata\"];
        if (suspicious.Any(s => lower.Contains(s, StringComparison.Ordinal)))
        {
            return Ev("process", p.Pid.ToString(), "process-suspicious-path", Severity.Medium, 0.6,
                $"Process '{p.Name}' runs from a suspicious path: {path}", p,
                tactics: [Tactics.DefenseEvasion]);
        }
        return null;
    }

    public static Evidence? ProcessSuspiciousParent(ProcessInfo p)
    {
        string? parent = p.ParentName;
        if (string.IsNullOrEmpty(parent))
        {
            return null;
        }
        string[] suspiciousParents = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"];
        string parentLower = parent.ToLowerInvariant();
        string? name = p.Name?.ToLowerInvariant();
        // child of script host with a non-system child is normal for installers; flag only
        // when child is itself a script host or suspicious binary in a suspicious path.
        if (suspiciousParents.Contains(parentLower) && !string.IsNullOrEmpty(name) && name.Contains("explorer", StringComparison.Ordinal))
        {
            return null;
        }
        if (suspiciousParents.Contains(parentLower) && p.ExecutablePath is string ep && !ep.StartsWith(@"c:\windows", StringComparison.OrdinalIgnoreCase))
        {
            return Ev("process", p.Pid.ToString(), "script-child-suspicious", Severity.Medium, 0.55,
                $"Process '{p.Name}' was spawned by script host '{parent}' from a non-system path.", p,
                tactics: [Tactics.Execution]);
        }
        return null;
    }

    // ---------- memory evidence ----------

    public static Evidence? MemoryRwxPrivate(Models.MemoryAnalysisResult m, MemoryRegion r)
    {
        if (!r.IsPrivate || !r.IsExecutable || r.Protect != "RWX")
        {
            return null;
        }
        return Ev("memory", m.Pid.ToString(), "rwx-private-region", Severity.High, 0.7,
            $"Process '{m.ProcessName}' (PID {m.Pid}) has a private RWX region at 0x{r.BaseAddress:X} ({r.RegionSize} bytes) — potential injected shellcode.", m,
            tactics: [Tactics.DefenseEvasion, Tactics.Execution]);
    }

    public static Evidence? MemoryHighEntropyExec(Models.MemoryAnalysisResult m, MemoryRegion r)
    {
        if (!r.IsPrivate || !r.IsExecutable || r.Entropy is null || r.Entropy < Entropy.HighEntropyThreshold)
        {
            return null;
        }
        return Ev("memory", m.Pid.ToString(), "high-entropy-private-exec", Severity.Medium, 0.6,
            $"Private executable region at 0x{r.BaseAddress:X} has entropy {r.Entropy:F2} — packed/injected code.", m,
            tactics: [Tactics.DefenseEvasion]);
    }

    public static Evidence? MemoryThreadOutsideModule(Models.MemoryAnalysisResult m, ThreadStartInfo t)
    {
        if (t.IsInModule)
        {
            return null;
        }
        return Ev("memory", m.Pid.ToString(), "thread-outside-module", Severity.Medium, 0.65,
            $"Thread {t.ThreadId} in '{m.ProcessName}' starts at 0x{t.StartAddress:X} — outside any loaded module (T1055 pattern).", m,
            tactics: [Tactics.Execution, Tactics.DefenseEvasion]);
    }

    // ---------- network evidence ----------

    public static Evidence? NetworkSuspiciousPort(NetworkSnapshot snap, NetworkConnection c)
    {
        if (!c.IsEstablished)
        {
            return null;
        }
        int[] suspiciousPorts = [4444, 5555, 6666, 6667, 7777, 9999, 1337, 31337, 4445, 8080, 8888];
        if (!suspiciousPorts.Contains(c.RemotePort ?? 0))
        {
            return null;
        }
        return Ev("network", ConnKey(c), "suspicious-remote-port", Severity.Medium, 0.5,
            $"Connection from '{c.ProcessName}' (PID {c.OwningPid}) to {c.RemoteAddress}:{c.RemotePort} — commonly abused port.", c,
            tactics: [Tactics.CommandAndControl]);
    }

    public static Evidence? NetworkExfiltrationShape(NetworkSnapshot snap, NetworkConnection c)
    {
        if (!c.IsEstablished || c.ProcessName is null)
        {
            return null;
        }
        // Known data-exfil tool processes
        string lower = c.ProcessName.ToLowerInvariant();
        if (lower.Contains("nc") || lower.Contains("ncat") || lower.Contains("socat") || lower.Contains("powershell") || lower.Contains("curl") || lower.Contains("wget"))
        {
            if (c.RemotePort is int rp && rp is not 80 and not 443 and not 53)
            {
                return Ev("network", ConnKey(c), "exfil-tool-connection", Severity.Low, 0.45,
                    $"'{c.ProcessName}' maintains a connection to {c.RemoteAddress}:{rp} on a non-standard port.", c,
                    tactics: [Tactics.Exfiltration]);
            }
        }
        return null;
    }

    // ---------- persistence evidence ----------

    public static Evidence? PersistenceSuspiciousLocation(PersistenceEntry p)
    {
        if (p.Category == PersistenceCategory.RunKey
            || p.Category == PersistenceCategory.StartupFolder
            || p.Category == PersistenceCategory.ScheduledTask
            || p.Category == PersistenceCategory.Winlogon
            || p.Category == PersistenceCategory.WmiSubscription)
        {
            if (p.TargetPath is null || !p.TargetExists)
            {
                return Ev("persistence", PersistenceKey(p), "persistence-missing-target", Severity.Medium, 0.55,
                    $"Persistence entry '{p.Name}' points to a missing target: {p.Command}", p,
                    tactics: [Tactics.Persistence]);
            }
        }
        return null;
    }

    public static Evidence? PersistenceInStartup(PersistenceEntry p)
    {
        if (p.Category != PersistenceCategory.StartupFolder)
        {
            return null;
        }
        if (p.TargetPath is not null && !IsKnownSystemPath(p.TargetPath) && p.TargetExists)
        {
            return Ev("persistence", PersistenceKey(p), "startup-folder-item", Severity.Low, 0.5,
                $"Item '{p.Name}' in the startup folder (non-system path).", p,
                tactics: [Tactics.Persistence]);
        }
        return null;
    }

    // ---------- system evidence ----------

    public static Evidence? SystemDefenderDisabled(SystemAuditResult a)
    {
        if (a.DefenderEnabled != false)
        {
            return null;
        }
        return Ev("system", "system", "defender-disabled", Severity.High, 0.8,
            "Windows Defender real-time protection is disabled.", a,
            tactics: [Tactics.DefenseEvasion]);
    }

    public static Evidence? SystemFirewallDisabled(SystemAuditResult a)
    {
        if (a.FirewallEnabled != false)
        {
            return null;
        }
        return Ev("system", "system", "firewall-disabled", Severity.High, 0.7,
            "Windows Firewall is disabled.", a,
            tactics: [Tactics.DefenseEvasion]);
    }

    public static Evidence? SystemUacDisabled(SystemAuditResult a)
    {
        if (a.UacEnabled != false)
        {
            return null;
        }
        return Ev("system", "system", "uac-disabled", Severity.Medium, 0.6,
            "UAC is disabled — processes run with full privileges.", a,
            tactics: [Tactics.PrivilegeEscalation]);
    }

    public static Evidence? SystemStaleUpdates(SystemAuditResult a)
    {
        if (a.DaysSinceLastUpdate is null || a.DaysSinceLastUpdate < 30)
        {
            return null;
        }
        return Ev("system", "system", "stale-updates", Severity.Medium, 0.55,
            $"System has not installed updates in {a.DaysSinceLastUpdate} days.", a);
    }

    public static Evidence? SystemGuestEnabled(SystemAuditResult a)
    {
        if (!a.GuestEnabled)
        {
            return null;
        }
        return Ev("system", "system", "guest-enabled", Severity.Medium, 0.5,
            "The Guest account is enabled.", a);
    }

    // ---------- normalization ----------

    /// <summary>
    /// Normalizes scanner outputs into evidence. Every rule that matches produces
    /// one evidence item with an explanation; nothing is auto-blocked.
    /// </summary>
    public static IReadOnlyList<Evidence> Normalize(FileReport? file = null, ProcessInfo? process = null,
        Models.MemoryAnalysisResult? memory = null, NetworkSnapshot? network = null,
        PersistenceScanResult? persistence = null, SystemAuditResult? system = null)
    {
        var list = new List<Evidence>(32);

        if (file is not null)
        {
            Add(list, FileUnsignedExecutable(file));
            Add(list, FileSignatureInvalid(file));
            Add(list, FileUntrustedSigner(file));
            Add(list, FileHighEntropy(file));
            Add(list, FileRwxSection(file));
            Add(list, FileSectionRuntimeGrowth(file));
            Add(list, FileOverlay(file));
            Add(list, FileTlsCallbacks(file));
            Add(list, FileNoAslr(file));
            Add(list, FileNoNx(file));
            Add(list, FileTimestampAnomaly(file));
            Add(list, FileFromInternet(file));
            Add(list, FileHiddenSystem(file));
            Add(list, FileSuspiciousLocation(file));
        }

        if (process is not null)
        {
            Add(list, ProcessUnsigned(process));
            Add(list, ProcessElevated(process));
            Add(list, ProcessSystemLocation(process));
            Add(list, ProcessSuspiciousParent(process));
        }

        if (memory is not null)
        {
            foreach (var r in memory.SuspiciousRegions)
            {
                Add(list, MemoryRwxPrivate(memory, r));
                Add(list, MemoryHighEntropyExec(memory, r));
            }
            foreach (var t in memory.SuspiciousThreads)
            {
                Add(list, MemoryThreadOutsideModule(memory, t));
            }
        }

        if (network is not null)
        {
            foreach (var c in network.Connections)
            {
                Add(list, NetworkSuspiciousPort(network, c));
                Add(list, NetworkExfiltrationShape(network, c));
            }
        }

        if (persistence is not null)
        {
            foreach (var p in persistence.Entries)
            {
                Add(list, PersistenceSuspiciousLocation(p));
                Add(list, PersistenceInStartup(p));
            }
        }

        if (system is not null)
        {
            Add(list, SystemDefenderDisabled(system));
            Add(list, SystemFirewallDisabled(system));
            Add(list, SystemUacDisabled(system));
            Add(list, SystemStaleUpdates(system));
            Add(list, SystemGuestEnabled(system));
        }

        return list;
    }

    private static void Add(List<Evidence> list, Evidence? e)
    {
        if (e is not null)
        {
            list.Add(e);
        }
    }

    private static Evidence Ev(string source, string entityId, string evt, Severity severity, double confidence,
        string explanation, object details, string[]? tactics = null)
    {
        return new Evidence
        {
            Source = source,
            Timestamp = DateTime.UtcNow,
            EntityType = source,
            EntityId = entityId,
            Event = evt,
            Severity = severity,
            Confidence = confidence,
            Explanation = explanation,
            DetailsJson = JsonSerializer.Serialize(details, s_json),
        };
    }

    private static bool IsKnownSystemPath(string path)
    {
        string lower = path.ToLowerInvariant();
        return lower.StartsWith(@"c:\windows", StringComparison.Ordinal)
            || lower.StartsWith(@"c:\program files", StringComparison.Ordinal)
            || lower.StartsWith(@"c:\program files (x86)", StringComparison.Ordinal);
    }

    private static string ConnKey(NetworkConnection c) =>
        $"{c.Protocol}|{c.LocalAddress}:{c.LocalPort}->{c.RemoteAddress}:{c.RemotePort}";

    private static string PersistenceKey(PersistenceEntry p) =>
        $"{p.Category}|{p.Name}|{p.Location}";
}