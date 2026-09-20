using Sentinel.Core.Detection;
using Sentinel.Core.Models;
using Sentinel.Core.Pe;
using Sentinel.Core.Signing;

namespace Sentinel.Tests;

/// <summary>
/// Detection rule tests using synthetic records only - no real malware, no
/// live system scanning. Verifies rules fire on the intended signals and,
/// critically, do NOT fire on benign inputs (false-positive resistance).
/// </summary>
public class DetectionEngineTests
{
    [Fact]
    public void CapDetailsJson_BoundsOversizedPayload_KeepsValidJson()
    {
        // Regression: the pre-hardening store could grow tens of GB because
        // evidence details embedded full scanner reports (PE import/export
        // tables). Details must be capped and stay valid JSON for the GUI.
        var big = new { blob = new string('x', 100_000), path = @"C:\a\b.exe" };
        string raw = System.Text.Json.JsonSerializer.Serialize(big);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(raw) > DetectionEngine.MaxDetailsJsonBytes);

        string capped = DetectionEngine.CapDetailsJson(raw);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(capped) <= DetectionEngine.MaxDetailsJsonBytes);
        using var doc = System.Text.Json.JsonDocument.Parse(capped); // must not throw
        Assert.True(doc.RootElement.GetProperty("truncated").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("head").GetString()!.StartsWith('{'.ToString(), StringComparison.Ordinal));

        // Small payloads pass through untouched.
        Assert.Equal("[1]", DetectionEngine.CapDetailsJson("[1]"));
        Assert.Equal("", DetectionEngine.CapDetailsJson(""));
    }

    private static FileReport File(
        string path = @"C:\Users\Test\AppData\Local\Temp\evil.exe",
        string fileName = "evil.exe",
        long size = 100_000,
        bool isPe = true,
        SignatureStatus sig = SignatureStatus.Unsigned,
        double? entropy = null,
        PeInfo? pe = null,
        bool hasMotw = false,
        bool hidden = false)
    {
        var now = DateTime.UtcNow;
        return new FileReport
        {
            Path = path,
            FileName = fileName,
            Size = size,
            CreationTimeUtc = now,
            LastWriteTimeUtc = now,
            LastAccessTimeUtc = now,
            IsPe = isPe,
            SignatureStatus = sig,
            Pe = pe,
            Entropy = entropy,
            HasMotw = hasMotw,
            IsHiddenOrSystem = hidden,
        };
    }

    private static PeInfo OkPe(ushort dllChars = 0x0160, uint timeStamp = 0x60000000, IReadOnlyList<PeSection>? sections = null)
    {
        return new PeInfo
        {
            Status = PeParseStatus.Ok,
            Is64Bit = true,
            Machine = PeParser.MachineAmd64,
            MachineName = "x64 (AMD64)",
            NumberOfSections = 1,
            TimeDateStamp = timeStamp,
            Characteristics = 0x0022,
            DllCharacteristics = dllChars,
            Subsystem = 3,
            AddressOfEntryPoint = 0x1000,
            ImageBase = 0x140000000,
            SizeOfImage = 0x2000,
            SizeOfHeaders = 0x400,
            CheckSum = 0,
            OptionalHeaderSize = 240,
            Sections = sections ?? [new PeSection { Name = ".text", VirtualSize = 0x100, VirtualAddress = 0x1000, RawSize = 0x200, RawPointer = 0x400, Characteristics = 0x60000020 }],
        };
    }

    // ---------- file rules ----------

    [Fact]
    public void UnsignedExecutable_Fires()
    {
        var e = DetectionEngine.FileUnsignedExecutable(File());
        Assert.NotNull(e);
        Assert.Equal("unsigned-executable", e.Event);
        Assert.Equal(Severity.Low, e.Severity);
        Assert.Equal("file", e.Source);
    }

    [Fact]
    public void SignedTrustedExecutable_NoEvidence()
    {
        var e = DetectionEngine.FileUnsignedExecutable(File(sig: SignatureStatus.SignedTrusted));
        Assert.Null(e);
    }

    [Fact]
    public void UnsignedNonPe_NoEvidence()
    {
        var e = DetectionEngine.FileUnsignedExecutable(File(isPe: false));
        Assert.Null(e);
    }

    [Fact]
    public void UnsignedInSystemPath_NoEvidence()
    {
        var e = DetectionEngine.FileUnsignedExecutable(File(path: @"C:\Windows\System32\notepad.exe", fileName: "notepad.exe"));
        Assert.Null(e);
    }

    [Fact]
    public void InvalidSignature_FiresHigh()
    {
        var e = DetectionEngine.FileSignatureInvalid(File(sig: SignatureStatus.SignatureInvalid));
        Assert.NotNull(e);
        Assert.Equal("invalid-signature", e.Event);
        Assert.Equal(Severity.High, e.Severity);
    }

    [Fact]
    public void UntrustedSigner_FiresMedium()
    {
        var e = DetectionEngine.FileUntrustedSigner(File(sig: SignatureStatus.SignedUntrusted));
        Assert.NotNull(e);
        Assert.Equal("untrusted-signer", e.Event);
        Assert.Equal(Severity.Medium, e.Severity);
    }

    [Fact]
    public void HighEntropyLargePe_Fires()
    {
        var e = DetectionEngine.FileHighEntropy(File(size: 1_000_000, entropy: 7.9));
        Assert.NotNull(e);
        Assert.Equal("high-entropy-pe", e.Event);
    }

    [Fact]
    public void HighEntropySmallFile_NoEvidence()
    {
        // Small files are naturally high-entropy - must not fire.
        var e = DetectionEngine.FileHighEntropy(File(size: 8_000, entropy: 7.9));
        Assert.Null(e);
    }

    [Fact]
    public void LowEntropy_NoEvidence()
    {
        var e = DetectionEngine.FileHighEntropy(File(size: 1_000_000, entropy: 5.0));
        Assert.Null(e);
    }

    [Fact]
    public void RwxSection_Fires()
    {
        var pe = OkPe(sections: [new PeSection { Name = ".text", VirtualSize = 0x100, VirtualAddress = 0x1000, RawSize = 0x200, RawPointer = 0x400, Characteristics = 0xE0000020 }]); // CODE|EXECUTE|WRITE
        var e = DetectionEngine.FileRwxSection(File(pe: pe));
        Assert.NotNull(e);
        Assert.Equal("rwx-section", e.Event);
    }

    [Fact]
    public void NormalSection_NoRwxEvidence()
    {
        var e = DetectionEngine.FileRwxSection(File(pe: OkPe()));
        Assert.Null(e);
    }

    [Fact]
    public void TimestampAnomaly_Fires()
    {
        var pe = OkPe(timeStamp: 0);
        var e = DetectionEngine.FileTimestampAnomaly(File(pe: pe));
        Assert.NotNull(e);
        Assert.Equal("timestamp-anomaly", e.Event);
    }

    [Fact]
    public void NormalTimestamp_NoAnomaly()
    {
        var pe = OkPe(timeStamp: 0x60000000);
        var e = DetectionEngine.FileTimestampAnomaly(File(pe: pe));
        Assert.Null(e);
    }

    [Fact]
    public void Motw_Fires()
    {
        var e = DetectionEngine.FileFromInternet(File(hasMotw: true));
        Assert.NotNull(e);
        Assert.Equal("motw-internet", e.Event);
    }

    [Fact]
    public void NoMotw_NoEvidence()
    {
        Assert.Null(DetectionEngine.FileFromInternet(File()));
    }

    [Fact]
    public void HiddenSystem_Fires()
    {
        var e = DetectionEngine.FileHiddenSystem(File(hidden: true));
        Assert.NotNull(e);
        Assert.Equal("hidden-system-file", e.Event);
    }

    [Fact]
    public void StartupFolder_FiresPersistence()
    {
        var e = DetectionEngine.FileSuspiciousLocation(File(path: @"C:\Users\Bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe"));
        Assert.NotNull(e);
        Assert.Equal("suspicious-location", e.Event);
    }

    [Fact]
    public void NormalLocation_NoEvidence()
    {
        Assert.Null(DetectionEngine.FileSuspiciousLocation(File(path: @"C:\Program Files\App\app.exe")));
    }

    // ---------- process rules ----------

    private static ProcessInfo Proc(
        string name = "evil.exe",
        string? path = @"C:\Users\Bob\AppData\Local\Temp\evil.exe",
        SignatureStatus sig = SignatureStatus.Unsigned,
        bool elevated = false,
        string? parent = null)
    {
        return new ProcessInfo
        {
            Pid = 1234,
            Name = name,
            ExecutablePath = path,
            ParentName = parent,
            SignatureStatus = sig,
            IsElevated = elevated,
        };
    }

    [Fact]
    public void UnsignedProcess_Fires()
    {
        var e = DetectionEngine.ProcessUnsigned(Proc());
        Assert.NotNull(e);
        Assert.Equal("process-unsigned", e.Event);
        Assert.Equal("1234", e.EntityId);
    }

    [Fact]
    public void SignedProcess_NoEvidence()
    {
        Assert.Null(DetectionEngine.ProcessUnsigned(Proc(sig: SignatureStatus.SignedTrusted)));
    }

    [Fact]
    public void ElevatedProcess_FiresInfo()
    {
        var e = DetectionEngine.ProcessElevated(Proc(elevated: true));
        Assert.NotNull(e);
        Assert.Equal(Severity.Info, e.Severity);
    }

    [Fact]
    public void NonElevated_NoFire()
    {
        Assert.Null(DetectionEngine.ProcessElevated(Proc()));
    }

    [Fact]
    public void ProcessInSystemPath_NoFire()
    {
        Assert.Null(DetectionEngine.ProcessSystemLocation(Proc(path: @"C:\Windows\System32\svchost.exe")));
    }

    [Fact]
    public void ProcessInTemp_Fires()
    {
        var e = DetectionEngine.ProcessSystemLocation(Proc());
        Assert.NotNull(e);
        Assert.Equal("process-suspicious-path", e.Event);
        Assert.Equal(Severity.Medium, e.Severity);
    }

    [Fact]
    public void ScriptChildFromNonSystemPath_Fires()
    {
        var e = DetectionEngine.ProcessSuspiciousParent(Proc(parent: "cmd.exe"));
        Assert.NotNull(e);
        Assert.Equal("script-child-suspicious", e.Event);
    }

    [Fact]
    public void ScriptChildFromSystemPath_NoFire()
    {
        var p = Proc(parent: "cmd.exe", path: @"C:\Windows\System32\conhost.exe");
        Assert.Null(DetectionEngine.ProcessSuspiciousParent(p));
    }

    [Fact]
    public void ExplorerChildOfScriptHost_NoFire()
    {
        var p = Proc(name: "explorer.exe", parent: "cmd.exe", path: @"C:\Windows\explorer.exe");
        Assert.Null(DetectionEngine.ProcessSuspiciousParent(p));
    }

    // ---------- memory rules ----------

    private static MemoryRegion Region(
        ulong baseAddr = 0x1000000,
        ulong size = 0x1000,
        string protect = "RWX",
        bool isPrivate = true,
        bool isExec = true,
        double? entropy = null)
    {
        return new MemoryRegion
        {
            BaseAddress = baseAddr,
            RegionSize = size,
            State = "Commit",
            Type = isPrivate ? "Private" : "Image",
            Protect = protect,
            ProtectRaw = 0,
            IsExecutable = isExec,
            IsWritable = protect.Contains('W'),
            IsPrivate = isPrivate,
            Entropy = entropy,
        };
    }

    private static MemoryAnalysisResult Mem(params MemoryRegion[] regions)
    {
        return new MemoryAnalysisResult
        {
            Pid = 4242,
            ProcessName = "test.exe",
            SuspiciousRegions = regions,
        };
    }

    [Fact]
    public void RwxPrivateRegion_FiresHigh()
    {
        var e = DetectionEngine.MemoryRwxPrivate(Mem(Region()), Region());
        Assert.NotNull(e);
        Assert.Equal("rwx-private-region", e.Event);
        Assert.Equal(Severity.High, e.Severity);
    }

    [Fact]
    public void RxImageRegion_NoRwxFire()
    {
        var r = Region(protect: "RX", isPrivate: false);
        Assert.Null(DetectionEngine.MemoryRwxPrivate(Mem(r), r));
    }

    [Fact]
    public void HighEntropyPrivateExec_Fires()
    {
        var r = Region(entropy: 7.8);
        var e = DetectionEngine.MemoryHighEntropyExec(Mem(r), r);
        Assert.NotNull(e);
        Assert.Equal("high-entropy-private-exec", e.Event);
    }

    [Fact]
    public void LowEntropyRegion_NoFire()
    {
        var r = Region(entropy: 4.0);
        Assert.Null(DetectionEngine.MemoryHighEntropyExec(Mem(r), r));
    }

    [Fact]
    public void ThreadOutsideModule_Fires()
    {
        var t = new ThreadStartInfo { ThreadId = 7, StartAddress = 0x7FF0000, IsInModule = false };
        var m = new MemoryAnalysisResult { Pid = 4242, ProcessName = "test.exe", SuspiciousThreads = [t] };
        var e = DetectionEngine.MemoryThreadOutsideModule(m, t);
        Assert.NotNull(e);
        Assert.Equal("thread-outside-module", e.Event);
    }

    [Fact]
    public void ThreadInModule_NoFire()
    {
        var t = new ThreadStartInfo { ThreadId = 7, StartAddress = 0x7FF0000, IsInModule = true };
        var m = new MemoryAnalysisResult { Pid = 4242, ProcessName = "test.exe", SuspiciousThreads = [t] };
        Assert.Null(DetectionEngine.MemoryThreadOutsideModule(m, t));
    }

    // ---------- network rules ----------

    private static NetworkConnection Conn(int remotePort, string process = "evil.exe", bool established = true)
    {
        return new NetworkConnection
        {
            Protocol = "TCP",
            LocalAddress = System.Net.IPAddress.Loopback,
            LocalPort = 50000,
            RemoteAddress = System.Net.IPAddress.Parse("203.0.113.10"),
            RemotePort = remotePort,
            State = established ? "Established" : null,
            OwningPid = 1234,
            ProcessName = process,
            IsEstablished = established,
        };
    }

    private static NetworkSnapshot Snap(params NetworkConnection[] conns)
    {
        return new NetworkSnapshot { CapturedAtUtc = DateTime.UtcNow, Connections = conns };
    }

    [Fact]
    public void SuspiciousPort_Fires()
    {
        var c = Conn(4444);
        var e = DetectionEngine.NetworkSuspiciousPort(Snap(c), c);
        Assert.NotNull(e);
        Assert.Equal("suspicious-remote-port", e.Event);
    }

    [Fact]
    public void NormalPort_NoFire()
    {
        var c = Conn(443);
        Assert.Null(DetectionEngine.NetworkSuspiciousPort(Snap(c), c));
    }

    [Fact]
    public void ListeningConnection_NoFire()
    {
        var c = Conn(4444, established: false);
        Assert.Null(DetectionEngine.NetworkSuspiciousPort(Snap(c), c));
    }

    [Fact]
    public void ExfilToolOnNonStandardPort_Fires()
    {
        var c = Conn(9001, process: "ncat.exe");
        var e = DetectionEngine.NetworkExfiltrationShape(Snap(c), c);
        Assert.NotNull(e);
        Assert.Equal("exfil-tool-connection", e.Event);
    }

    [Fact]
    public void ExfilToolOnHttps_NoFire()
    {
        var c = Conn(443, "curl.exe");
        Assert.Null(DetectionEngine.NetworkExfiltrationShape(Snap(c), c));
    }

    // ---------- persistence rules ----------

    private static PersistenceEntry Entry(PersistenceCategory cat, string? target = null, bool exists = false)
    {
        return new PersistenceEntry
        {
            Category = cat,
            Name = "evil",
            Location = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            Command = target ?? @"C:\evil\evil.exe",
            TargetPath = target,
            TargetExists = exists,
        };
    }

    [Fact]
    public void RunKeyMissingTarget_Fires()
    {
        var e = DetectionEngine.PersistenceSuspiciousLocation(Entry(PersistenceCategory.RunKey));
        Assert.NotNull(e);
        Assert.Equal("persistence-missing-target", e.Event);
    }

    [Fact]
    public void RunKeyExistingTarget_NoFire()
    {
        Assert.Null(DetectionEngine.PersistenceSuspiciousLocation(Entry(PersistenceCategory.RunKey, target: @"C:\Windows\System32\svchost.exe", exists: true)));
    }

    [Fact]
    public void ServiceCategory_NoFire()
    {
        Assert.Null(DetectionEngine.PersistenceSuspiciousLocation(Entry(PersistenceCategory.Service)));
    }

    [Fact]
    public void StartupFolderExistingNonSystem_Fires()
    {
        var e = DetectionEngine.PersistenceInStartup(Entry(PersistenceCategory.StartupFolder, target: @"C:\Users\Bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe", exists: true));
        Assert.NotNull(e);
        Assert.Equal("startup-folder-item", e.Event);
    }

    // ---------- system rules ----------

    private static SystemAuditResult Audit(bool? defender = true, bool? firewall = true, bool? uac = true, int? days = 5, bool guest = false)
    {
        return new SystemAuditResult
        {
            AuditedAtUtc = DateTime.UtcNow,
            DefenderEnabled = defender,
            FirewallEnabled = firewall,
            UacEnabled = uac,
            DaysSinceLastUpdate = days,
            GuestEnabled = guest,
        };
    }

    [Fact]
    public void DefenderDisabled_FiresHigh()
    {
        var e = DetectionEngine.SystemDefenderDisabled(Audit(defender: false));
        Assert.NotNull(e);
        Assert.Equal("defender-disabled", e.Event);
        Assert.Equal(Severity.High, e.Severity);
    }

    [Fact]
    public void DefenderEnabled_NoFire()
    {
        Assert.Null(DetectionEngine.SystemDefenderDisabled(Audit(defender: true)));
    }

    [Fact]
    public void DefenderUnknown_NoFire()
    {
        // bool? null means "could not determine" - must not fire.
        Assert.Null(DetectionEngine.SystemDefenderDisabled(Audit(defender: null)));
    }

    [Fact]
    public void FirewallDisabled_Fires()
    {
        var e = DetectionEngine.SystemFirewallDisabled(Audit(firewall: false));
        Assert.NotNull(e);
        Assert.Equal("firewall-disabled", e.Event);
    }

    [Fact]
    public void UacDisabled_Fires()
    {
        var e = DetectionEngine.SystemUacDisabled(Audit(uac: false));
        Assert.NotNull(e);
        Assert.Equal("uac-disabled", e.Event);
    }

    [Fact]
    public void StaleUpdates_Fires()
    {
        var e = DetectionEngine.SystemStaleUpdates(Audit(days: 45));
        Assert.NotNull(e);
        Assert.Equal("stale-updates", e.Event);
    }

    [Fact]
    public void FreshUpdates_NoFire()
    {
        Assert.Null(DetectionEngine.SystemStaleUpdates(Audit(days: 5)));
    }

    [Fact]
    public void GuestEnabled_Fires()
    {
        var e = DetectionEngine.SystemGuestEnabled(Audit(guest: true));
        Assert.NotNull(e);
        Assert.Equal("guest-enabled", e.Event);
    }

    // ---------- Normalize ----------

    [Fact]
    public void Normalize_BenignInputs_ProducesNoEvidence()
    {
        var file = File(path: @"C:\Program Files\App\app.exe", sig: SignatureStatus.SignedTrusted, pe: OkPe());
        var proc = Proc(path: @"C:\Windows\System32\svchost.exe", sig: SignatureStatus.SignedTrusted);
        var mem = new MemoryAnalysisResult { Pid = 1, ProcessName = "svchost.exe" };
        var net = Snap(Conn(443, "svchost.exe"));
        var sys = Audit(defender: true, firewall: true, uac: true, days: 2, guest: false);

        var evidence = DetectionEngine.Normalize(file: file, process: proc, memory: mem, network: net, system: sys);

        Assert.Empty(evidence);
    }

    [Fact]
    public void Normalize_SuspiciousInputs_ProducesEvidence()
    {
        var file = File(); // unsigned, temp location
        var proc = Proc(); // unsigned, appdata
        var r = Region();
        var mem = Mem(r);
        var snap = Snap(Conn(4444));
        var sys = Audit(defender: false, firewall: false, uac: false, days: 60, guest: true);

        var evidence = DetectionEngine.Normalize(file: file, process: proc, memory: mem, network: snap, system: sys);

        Assert.NotEmpty(evidence);
        Assert.Contains(evidence, e => e.Event == "unsigned-executable");
        Assert.Contains(evidence, e => e.Event == "rwx-private-region");
        Assert.Contains(evidence, e => e.Event == "suspicious-remote-port");
        Assert.Contains(evidence, e => e.Event == "defender-disabled");
        Assert.Contains(evidence, e => e.Event == "guest-enabled");
    }
}