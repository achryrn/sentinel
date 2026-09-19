# Sentinel — Architecture

**Product name:** Sentinel (working title) — Windows endpoint inspection platform.
**Language/stack:** C# / .NET 10 (Windows), WPF GUI, Win32 interop via `LibraryImport`, SQLite (Microsoft.Data.Sqlite) for persistence.
**Licensing note:** this is an original implementation; all interop declarations, parsers, and rule logic are written from scratch for this project. No third-party security libraries.

---

## 1. Component diagram

```
                    ┌─────────────────────┐
                    │      GUI (WPF)      │   runs as STANDARD USER
                    └──────────┬──────────┘
                               │  named pipe IPC (JSON lines)
                    ┌──────────▼──────────┐
                    │  Sentinel.Service   │   LocalSystem (privileged backend)
                    │  (Windows service)  │
                    └──────────┬──────────┘
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
   FileScanner           ProcessScanner         NetworkScanner
        │                      │                      │
        └──────────────┬───────┴──────────────┬───────┘
                       ▼                      ▼
                MemoryAnalyzer         PersistenceScanner
                       │                      │
                       └──────────┬───────────┘
                                  ▼
                         DetectionEngine
                                  │
                         CorrelationEngine
                                  │
                         RiskAssessor
                                  │
                         Findings / EventStore / SQLite
                                  │
                          GUI / CLI / Reports
```

Every component is a library class in `Sentinel.Core`; the service, CLI, and GUI are thin hosts over the same code.

---

## 2. Projects

| Project | Kind | Purpose |
|---|---|---|
| `Sentinel.Core` | classlib (net10.0-windows) | Everything: interop, parsers, scanners, engines, storage, IPC protocol, monitoring |
| `Sentinel.Service` | exe | Windows service host (LocalSystem), owns privileged operations, owns pipe server |
| `Sentinel.Cli` | exe | Headless mode for scripting/CI (`sentinel scan`, `sentinel status`, ...) |
| `Sentinel.Gui` | WPF exe | Unprivileged client; speaks IPC only |
| `Sentinel.Tests` | xunit | Unit + integration tests (no network, no destructive ops) |

---

## 3. Data model (core entities)

- **`Evidence`** — one observation: `Source` (subsystem), `Timestamp`, `EntityType` + `EntityId` (file path | pid | connection key | persistence key | system), `Event` (name), `Severity` (Info..Critical), `Confidence` (0..1), `Explanation`, `Details` (JSON), `RelatedEvidenceIds`.
- **`Finding`** — correlated conclusion: `EvidenceIds`, `EntityKey`, `Title`, `Severity`, `Confidence`, `Reasons[]` (human-readable, each mapped to evidence), `MitreTactics[]`, `RecommendedAction`, `Status` (New/Reviewed/Allowed/Quarantined).
- **`ScanJob`** — a scan run: `Id`, `Mode` (Quick/Full/Custom/File/Folder/Drive/StartupLocations/SuspiciousLocations), `Targets`, `Exclusions`, `Progress` (files total/processed, bytes, current item, speed, eta, state), `Started/Finished`, `ResultSummary`.
- **`PersistenceEntry`** — normalized persistence item (see scanner).
- **`NetworkConnection`**, **`ProcessInfo`**, **`MemoryRegion`**, **`FileReport`** — scanner outputs.
- **`Exclusion`** — type (Path/Hash/Signer/Process), value, scope, added-by, timestamp, rationale. All exclusions are stored in SQLite and visible in UI (Settings → Exclusions). **Auditability is a hard requirement.**

---

## 4. Storage (SQLite)

DB at `%ProgramData%\Sentinel\sentinel.db` (service-managed; GUI never opens it directly).

| Table | Purpose |
|---|---|
| `findings` | correlated findings + status |
| `evidence` | evidence items (bounded — trimmed to ~100k rows) |
| `scan_jobs` | scan history |
| `hash_cache` | path→(size, lastWrite, sha256, sha1, md5, firstSeen, verdict) |
| `signer_cache` | signer name → trust state, observed count |
| `exclusions` | auditable exclusions |
| `quarantine` | quarantine records (id, original path, hashes, times, reason, status) |
| `settings` | service config (kv) |
| `events` | persisted event log tail |

Concurrency: single writer connection owned by the service; readers use short-lived connections. WAL mode.

---

## 5. Interop layer (`Native`)

`LibraryImport`-based (source-generated, trimmed-safe) declarations, grouped by library:
- `kernel32`: `CreateToolhelp32Snapshot`, `Process32FirstW/NextW`, `Module32FirstW/NextW`, `OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`, `MiniDumpWriteDump` (dbghelp), `QueryFullProcessImageNameW`, `GetProcessTimes`, `GetProcessMemoryInfo` (psapi), `NtQueryInformationThread` (ntdll, ThreadQuerySetWin32StartAddress), `ReadDirectoryChangesW`, `RegNotifyChangeKeyValue`, `GetSystemInfo`.
- `wintrust/crypt32`: `WinVerifyTrust`, `CryptQueryObject`, `CryptDecodeObjectEx`, `CryptFormatObject`, `CertNameToStrW`.
- `iphlpapi`: `GetExtendedTcpTable`, `GetExtendedUdpTable`, `GetIfTable2`, `GetAdaptersAddresses`.
- `dbghelp`: `MiniDumpWriteDump`.
- `amsi`: `AmsiInitialize`, `AmsiScanBuffer`, `AmsiScanString`, `AmsiOpenSession`, `AmsiUninitialize` (late-bound via LoadLibrary to degrade gracefully).
- `advapi32/security`: `GetTokenInformation`, `LookupAccountSidW`, `ConvertSidToStringSidW`, `OpenProcessToken`, `GetTokenInformation` (integrity), `OpenSCManager`/`QueryServiceConfig2W` (elevated service), `GetUserNameW`.
- COM interop (embedded interfaces, no external libs): `INetFwPolicy2` (firewall read), `IShellLinkW` (LNK targets), `ITaskScheduler` via `schtasks` fallback.

All P/Invoke marshaling is explicit; buffers are sized by probing calls (`ERROR_INSUFFICIENT_BUFFER` pattern).

---

## 6. Subsystem matrix

| Subsystem | Primary sources | Privilege | Perf | Detection capabilities | Limitations | FP risks |
|---|---|---|---|---|---|---|
| File scanner | NTFS enumeration, `FileInfo`, streaming hash | User | I/O bound; throttled | Files, sizes, times, ADS, MOTW, hash cache | No encrypted file content (EFS) unless user context | none (facts) |
| PE parser | custom binary parser | User | ~0.1–1 ms/file | Sections, imports/exports, TLS callbacks, resources, overlay, anomalies, entry point | Cannot parse exotic/obfuscated headers; reports `Failed` | none (facts) |
| Signature | WinVerifyTrust, CryptQueryObject | User | ~1–20 ms/file | Signed/trusted/untrusted/invalid/unsigned, signer, timestamp | No revocation-by-default; no chain detail | Revocation-offline FPs avoided by default-off |
| Process scanner | Toolhelp, WMI Win32_Process, psapi | Admin (full); user (self-level) | 10–50 ms | PID/PPID/cmdline/user/session/modules/signer/times | Elevated process detail needs elevation | WMI nulls for system procs (handled) |
| Memory analyzer | VirtualQueryEx, ReadProcessMemory, toolhelp modules | Admin for others | 1–50 ms/proc | Region protections, unbacked exec, RWX, thread start addresses, modified images | No PPL; no kernel truth | JIT/CLR/legit allocs → correlated, never alone |
| Memory dump | MiniDumpWriteDump | Admin + SeDebug | I/O bound | Full/limited dumps, local analysis | PPL/anti-debug failures reported honestly | n/a |
| Network scanner | GetExtended{Tcp,Udp}Table, GetIfTable2, DnsQuery (reverse) | User | ~1–10 ms | Per-PID connections, states, interfaces, listening ports | No payload, no DNS-query telemetry (without Sysmon), no block | NAT-private IPs, CDNs — baselined |
| Persistence scanner | Registry reads, TaskCache, WMI root\subscription, schtasks XML, startup folders, browsers | Admin (full) | 50–300 ms | Run keys, services, tasks, WMI, startup folders, Winlogon, IFEO, AppInit, shell hooks, browser extensions | CLSID names need resolution (bounded) | Legit vendor entries → signer/path context |
| System audit | registry, INetFwPolicy2, WMI, event log | Admin (full) | 100–500 ms | Build, patches (UCRT version), firewall, Defender state, UAC, accounts, RDP/SMB exposure, listening ports | Some states need elevation to observe | n/a (facts) |
| Event log reader | `System.Diagnostics.Eventing.Reader` | Admin for Security/Sysmon | per-channel | 4624/4625/4688/7045..., Sysmon 1/3/6/8/10/11-15/22/25 | Depends on audit policy/Sysmon presence | Reported when unavailable |
| Realtime monitor | ReadDirectoryChangesW, WMI events, RegNotifyChangeKeyValue, bounded polls | Admin (full) | Low (event-driven) | File create in watch dirs, process create, persistence key writes, network deltas | No kernel guarantees; latency seconds | Bounded queues, dedupe |
| Detection engine | Evidence stream | n/a | rule O(1)/evidence | 40+ rules, weighted, explainable | rules ≠ verdicts | mitigated by weighting |
| Correlation | in-memory + SQLite | n/a | indexed | Entity linkage, time windows, chain scoring | No ML | none |
| Quarantine | service-only file ops | Service account | I/O bound | isolate, restore (hash-verified), delete, audit | No encrypted quarantine (documented) | none |
| AMSI | amsi.dll (optional) | User | 1–50 ms/call | Third-party verdict on files/scripts/buffers | Size caps; presence-dependent; not authoritative | Defender-flag-of-self avoided by design |

---

## 7. Detection pipeline

```
Scanner output (FileReport, ProcessInfo, ...)
        │ 1. normalize → Evidence[]
        ▼
DetectionEngine.Evaluate(evidence)          — per-evidence rules
        │ 2. emit individual Evidence (severity, confidence, explanation)
        ▼
CorrelationEngine.Correlate(evidence)       — entity keys + time windows (default 60 s)
        │ 3. composite Evidence chains
        ▼
RiskAssessor.Assess(evidenceSet)            — weighted aggregation per entity
        │ 4. Finding { reasons[], confidence, severity, actions }
        ▼
EventStore + SQLite + live stream → GUI/CLI
```

Scoring model: each reason contributes (severity × confidence × weight) with explicit capping; the Finding displays the full reason list — **never a bare number**.

---

## 8. Threat model & trust boundaries

- The pipe server runs in the service; clients are authenticated by process image (client must be `Sentinel.Gui.exe`/`Sentinel.Cli.exe` or same-session admin), and sensitive ops (quarantine, exclusions, dumps) require elevation check on the service side.
- The GUI never touches files in quarantine directly.
- Credentials (reputation provider API keys) are stored in service config only (`%ProgramData%\Sentinel\service.json`, ACL'd), never sent to the GUI.
- The scanner never writes to scanned files, never executes scanned content, never injects, never terminates processes, never disables security controls.
- Quarantine operations are always user-confirmed (unless realtime-protection policy explicitly configured otherwise).

---

## 9. Threading & performance model

- Service: scan workers run on bounded `TaskScheduler` with per-scan throttles (byte budget/s, CPU budget); one scan at a time per job; realtime monitors are independent lightweight loops.
- Event pipeline: producers → bounded `Channel<T>` (backpressure) → consumers (detection engine, store).
- GUI: `ObservableCollection` updates marshaled to dispatcher with batching; `DataGrid` virtualization; live tables capped (network view keeps last N=5000 rows).
- Memory: streaming IO everywhere; no whole-file loads except small config/PE headers (≤4 MB cap for AMSI buffers).
- Honest progress: exact counts for enumerated targets; indeterminate bars otherwise; ETA from moving average of throughput.

---

## 10. Security & safety invariants (enforced in code)

1. No execution of scanned content (no Process.Start on findings; scripts scanned via AMSI only).
2. No memory writes into other processes; `ReadProcessMemory`/`VirtualQueryEx` only; dumps via MiniDumpWriteDump (no injection).
3. No service/driver installation, no firewall changes, no Defender changes, no UAC changes.
4. Protected-process (PPL) failures are reported as `Unable to inspect`, never bypassed.
5. Quarantine default: user-confirmed; restore verifies hashes both ways.
6. All exclusions visible and removable; no silent exclusions.
7. If AMSI itself is unavailable → feature reported unavailable, scan continues.

---

## 11. Configuration

`%ProgramData%\Sentinel\service.json` (service-owned):
- scan defaults (quick/full target sets, exclusions, throttle)
- realtime toggles + watch roots
- AMSI toggle + size cap
- reputation provider (disabled by default; keys here, never in GUI)
- event retention

GUI settings are presented read-only where they concern service security.

---

## 12. Future work (documented, not implemented)

- Kernel driver (object/thread callbacks, minifilter, WFP callout) — deliberately out of scope; architecture note only.
- ETW kernel providers (admin; version-sensitive) — pending value/cost.
- Full offline/rootkit module; boot-time scanning.
- Encrypted-volume-aware scan; shadow-copy scanning.
- Reputation provider integrations (VirusTotal etc.) behind the existing provider interface.
- ML-assisted scoring (currently deterministic + explainable).
