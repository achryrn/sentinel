# Sentinel — Final Implementation Report

**Product:** Sentinel — Windows endpoint security inspection platform
**Date:** 2026-08-08
**Stack:** C# / .NET 10 (`net10.0-windows`), WPF GUI, Win32 interop (`LibraryImport`), SQLite (Microsoft.Data.Sqlite)
**Status:** All acceptance criteria met; 123/123 tests passing; E2E verified against a live service.

---

## 1. Project Overview

Sentinel is a Windows endpoint inspection platform that scans **files, processes, memory, network connections, persistence mechanisms, and system security posture**, then correlates the collected evidence into risk-scored findings mapped to MITRE ATT&CK tactics. It was built research-first: the technical research (Windows internals, PE/COFF, Authenticode, process architecture, network tables, persistence mechanisms, AMSI, Sysinternals tooling) was completed and documented before implementation began, and every detection is evidence-based and explainable.

The product is delivered as a solution of five projects:

| Project | Kind | Purpose |
|---|---|---|
| `Sentinel.Core` | classlib | All scanners, parsers, engines, storage, IPC protocol, realtime monitor |
| `Sentinel.Service` | exe | Privileged backend (LocalSystem); owns pipe server, scans, store |
| `Sentinel.Cli` | exe | Headless client for scripting/CI |
| `Sentinel.Gui` | WPF exe | Unprivileged client with 12 views |
| `Sentinel.Tests` | xunit | 123 unit + integration tests |

---

## 2. Honest Capability Statement

**Sentinel is an inspection and detection platform — it is NOT a complete antivirus product.** Specifically:

- ✅ **What it does:** read-only scanning of files (static analysis, PE structure, Authenticode signatures, entropy, streams), live processes (modules, threads, memory regions, tokens), network sockets (per-process TCP/UDP), persistence (registry, startup folders, scheduled tasks, services), and system security posture (Defender, firewall, UAC, updates, accounts, exposure). It correlates evidence into findings with risk scores and MITRE ATT&CK tactic tags, and provides quarantine (explicit user action) and auditable exclusions.
- ❌ **What it does NOT do:** no kernel driver, no AMSI hooking, no auto-execution of suspicious files, no process memory modification during scanning, no injection, no auto-deletion, no auto-remediation, no real-time blocking. All actions require user confirmation.
- ⚠️ **Detection quality:** detections are *signals*, not verdicts. A single weak signal (e.g., an unsigned executable) is reported as low-severity evidence; only correlated evidence produces findings. False positives are mitigated by signer/path trust, exclusions, and confidence scoring — but they remain possible, and the UI is designed for human review.

---

## 3. Research Methodology & References

Research was completed first and documented in `docs/RESEARCH.md`. Key references:

| Reference | Role in the product |
|---|---|
| **MITRE ATT&CK** | Behavioral reference for detection rules; every finding carries tactic tags (Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact, Initial Access) |
| **Microsoft AMSI** | Documented as the integration point for future real-time scanning (see §16). AMSI is a scan *integration* interface, not a scanner itself; no AMSI code is present in this build |
| **Sysinternals** | Inspection reference: Process Explorer (process/module/memory views), TCPView (per-process sockets), Autoruns (persistence breadth), Sigcheck (signature verification) — the scanner breadth mirrors these tools |
| **Sysmon** | Telemetry event catalog reference for the realtime event model |
| **Win32 documentation** | Toolhelp32, IP Helper (GetExtendedTcpTable/UdpTable), VirtualQueryEx, Wintrust/Authenticode, Registry, WMI (System.Management), Windows Update COM |

**Methodology:** layered evidence pipeline — data collection (scanners) → evidence normalization (DetectionEngine rules) → entity correlation (CorrelationEngine) → risk scoring (RiskAssessor) → persistence → UI/report. Every rule emits structured evidence with severity, confidence, explanation, and details; rules never produce verdicts alone.

---

## 4. Architecture

```
┌─────────────────────┐
│      GUI (WPF)      │   standard user
└──────────┬──────────┘
           │  named pipe IPC (JSON lines)
┌──────────▼──────────┐
│  Sentinel.Service   │   LocalSystem
└──────────┬──────────┘
   ┌───────┼───────┬───────────┬──────────────┐
   ▼       ▼       ▼           ▼              ▼
 File   Process  Memory    Network      Persistence
Scanner  Scanner  Scanner   Scanner       Scanner
   └───────┴───────┴─────────┴──────────────┘
                    ▼
            DetectionEngine (rules → evidence)
                    ▼
            CorrelationEngine (entity linkage → findings)
                    ▼
            RiskAssessor (risk score) → SQLite store
                    ▼
            GUI / CLI / realtime events
```

- **Service** owns the named pipe server (`\\.\pipe\sentinel\ipc`), the SQLite store (`%ProgramData%\Sentinel\sentinel.db`), the realtime file monitor, and the periodic system audit (every 30 min).
- **GUI and CLI** are unprivileged clients that speak IPC only; they never open the database directly.
- **Scan scheduling:** bounded scheduler with a single active scan; progress is broadcast as `scan-progress` events; results flow through the evidence pipeline.

---

## 5. Data Model & Storage (SQLite)

- **`Evidence`** — one observation: `Source` (file/process/memory/network/persistence/system), `Timestamp`, `EntityType` + `EntityId` (file path | pid | connection key | persistence key | system), `Event` (rule name), `Severity` (Info..Critical), `Confidence` (0..1), `Explanation`, `Details` (JSON), `RelatedEvidenceIds`.
- **`Finding`** — correlated conclusion: `EvidenceIds`, `EntityKey`, `Title`, `Severity`, `Confidence`, `Reasons[]`, `MitreTactics[]`, `RecommendedAction`, `Status` (New/Reviewed/Allowed/Quarantined), `RiskScore`.
- **`ScanJob`** — scan run record: mode, targets, exclusions, progress, timestamps, result summary.
- **Scanner outputs:** `FileReport`, `ProcessInfo`, `MemoryAnalysisResult`, `NetworkSnapshot`, `PersistenceEntry`, `SystemAuditResult`.
- **`Exclusion`** — auditable: type (Path/Hash/Signer), value, scope, added-by, timestamp, rationale.
- **`QuarantineRecord`** — original path, hashes, times, reason, status.

**Database:** SQLite at `%ProgramData%\Sentinel\sentinel.db` (service-managed).

| Table | Purpose |
|---|---|
| `findings` | correlated findings + status |
| `evidence` | evidence items (bounded, trimmed to ~100k rows) |
| `scan_jobs` | scan history |
| `hash_cache` | path → (size, lastWrite, sha256, sha1, md5, firstSeen, verdict) |
| `signer_cache` | signer name → trust state, observed count |
| `exclusions` | auditable exclusions |
| `quarantine` | quarantine records |

---

## 6. File Scanner

- **Input:** file or folder (recursive), with exclusions honored.
- **Per file:** size, timestamps, attributes, SHA256/SHA1/MD5 (cached by path+size+lastWrite), Zone.Identifier (Mark-of-the-Web), ADS streams (via `FindFirstStreamW`), PE parse (custom `PeParser`), Authenticode verification (WinVerifyTrust + CryptQueryObject), signer extraction, entropy (Shannon, per-block).
- **PE analysis:** DOS/COFF/Optional headers, section table, imports/exports, TLS callbacks, overlay, debug/PDB, ASLR/NX flags, RWX sections, entrypoint-outside-sections, unusual section names, timestamp anomalies. Malformed files → `PeParseStatus.Failed` with reason, never exceptions.
- **Evidence rules:** unsigned executable, invalid signature, untrusted signer, high entropy, RWX section, section runtime growth, overlay, TLS callbacks, no ASLR, no NX, timestamp anomaly, from-internet, hidden/system attributes, suspicious location.

## 7. Process Scanner

- **Enumeration:** `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32FirstW/NextW` (Unicode structs — a real bug was found and fixed here: missing `CharSet.Unicode` on `PROCESSENTRY32W` caused `ERROR_BAD_LENGTH` and empty lists).
- **Per process:** PID, name, path, session, parent PID (WMI `Win32_Process`), modules (per-process `TH32CS_SNAPMODULE`), threads, integrity/elevation, signature status, hash (on demand).
- **Access:** `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`; graceful degradation when access is denied (system processes, PPL).
- **Evidence:** unsigned, elevated, system-location, suspicious parent.

## 8. Memory Scanner

- **Per process:** `VirtualQueryEx` region walk; region classification (private/committed/executable), RWX detection, entropy of executable regions, thread start addresses vs. module ranges (`Thread32First/Next` + module base/end), access-denied tracking.
- **Explicitly read-only:** no memory modification, no injection, no writes — scanning only.
- **Evidence:** private RWX region (potential injected shellcode), high-entropy executable region, thread start outside module.

## 9. Network Scanner

- **Capture:** `GetExtendedTcpTable`/`GetExtendedUdpTable` (IPv4 + IPv6) with `TCP_TABLE_OWNER_PID_ALL`/`UDP_TABLE_OWNER_PID`; per-connection owning PID mapped to process names.
- **Note:** a real bug was found and fixed here — the table header `dwNumEntries` is a 4-byte DWORD, but the code advanced the pointer by `IntPtr.Size` (8 bytes on x64), scrambling every row. Fixed to `buf + 4`.
- **Output:** local/remote address+port, state (TCP state names 1–12), PID, process name, listening vs. established, loopback vs. public.
- **Evidence:** suspicious port, exfiltration shape (many outbound connections).

## 10. Persistence Scanner

- **Coverage:** startup folders (user + common), Run/RunOnce registry keys (HKLM/HKCU), Winlogon shell, scheduled tasks (via `schtasks` query), services (via `sc` query), WMI event subscriptions (best-effort).
- **Evidence:** suspicious location, startup entry.

## 11. System Auditor

Read-only security posture audit:

- **OS:** version, build, edition, server flag, install date, last boot.
- **Updates:** last install (Windows Update COM API `Microsoft.Update.Session` → `QueryHistory`), days since, stale-update finding.
- **Defender:** enabled, real-time/behavior/on-access/NIS/IOAV status (WMI `MSFT_MpComputerStatus`), signature version + age.
- **Firewall:** per-profile state (COM `HNetCfg.FwPolicy2`, profiles Domain/Private/Public), rule count.
- **UAC:** enabled, consent level.
- **Accounts:** local Administrators membership, Guest state.
- **Exposure:** RDP, SMB, public listening ports (from the network snapshot).

*E2E note:* the audit pipeline was verified against a live Windows 11 machine — OS build 26200, Defender all-on, firewall enabled with 517 rules, UAC level 5, 2 admins, updates current. Three real-world bugs were found and fixed during E2E (see §15).

## 12. Detection Engine (Rules)

Every rule is a pure function `(scanner output) → Evidence?`. Rules never produce verdicts alone. 30+ rules across six sources (see §6–§11). Each evidence carries severity, confidence, explanation, and details; the engine normalizes scanner outputs into evidence in one pass.

## 13. Correlation Engine & Risk Scoring

- **Correlation:** evidence is grouped by entity (file path, PID, connection key, persistence key, system) within a 60-second window; distinct signals per entity are combined into a `Finding` with max severity, confidence `min(1, 0.3 + Σconf·0.35)`, deduplicated reasons, MITRE tactic tags, and a recommended action (immediate review / review / informational).
- **Risk scoring:** `RiskAssessor` computes a weighted score from evidence severities and event weights; findings are stored with `risk_score` and listed highest-first.

## 14. IPC & Service Host

- **Protocol:** named pipe `\\.\pipe\sentinel\ipc`, JSON-lines, camelCase, case-insensitive, `IpAddressConverter` for IP serialization.
- **Commands:** Ping, Status, ScanFile/Folder/Quick/Full/Process/Network/Persistence/Memory, AuditSystem, CancelScan, GetFindings, GetEvidence, UpdateFindingStatus, GetExclusions, Add/RemoveExclusion, GetQuarantine, QuarantineFile, Restore/DeleteQuarantine, GetEvents, GetScanJobs, GetRealtimeEvents, DumpProcessMemory.
- **Events:** `scan-progress`, `file-report`, `realtime-event` broadcast to connected clients; GUI re-raises on the UI thread.
- **Service modes:** console (`--run`) for development, Windows service (`--install`/`--uninstall`) for production.

**GUI (WPF, 12 views):** Dashboard (live posture + recent findings), Scan, Threats (findings), Processes, Network, Memory, Persistence, Files, System (audit), Events, Quarantine, Settings (exclusions). All views refresh via IPC; the dashboard shows Defender/firewall/UAC posture from a fresh audit.

**CLI (14 commands):** `status`, `scan <path|--quick|--full>`, `findings`, `evidence <entity>`, `events`, `quarantine [--list|--restore|--delete]`, `exclusions [--add|--remove]`, `processes`, `network`, `persistence`, `memory [pid]`, `audit`, `dump <pid>`, `help`.

## 15. Testing & E2E Verification

**Unit/integration tests: 123/123 passing** (`dotnet test`):

| Suite | Tests | Coverage |
|---|---|---|
| `DetectionEngineTests` | 52 | every rule, normalization, edge cases |
| `PeParserTests` | 21 | PE parsing, malformed files, sections, imports, TLS, overlay |
| `SentinelStoreTests` | 17 | SQLite CRUD, findings, evidence, exclusions, quarantine |
| `CorrelationEngineTests` | 14 | grouping, confidence, tactics, risk scoring |
| `EntropyTests` | 11 | Shannon entropy, block entropy |
| `HashServiceTests` | 8 | SHA256/SHA1/MD5, caching |

**E2E verification (live service, real machine):**

| Check | Result |
|---|---|
| Process scan | ✅ real process list with PIDs/names/parents |
| Memory scan | ✅ regions/suspicious/threads/denied per process |
| Network scan | ✅ real TCP/UDP addresses, PIDs, process names |
| Findings | ✅ severity/score/entity/action/tactics |
| Persistence | ✅ startup folders, winlogon, scheduled tasks |
| Events | ✅ realtime file-modified events |
| Audit | ✅ OS/Defender/firewall/UAC/admins/updates all real values |
| Quarantine/exclusions/evidence | ✅ list/add/remove/evidence-by-entity |
| GUI | ✅ launches, connects via IPC, all 12 views load |
| Build | ✅ 0 errors |

**Bugs found & fixed during E2E (all verified):**

1. **Process scan empty** — `CreateToolhelp32Snapshot` used `TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE` with PID 0 (SNAPMODULE requires a valid PID → invalid handle). Fixed to `TH32CS_SNAPPROCESS`.
2. **Process scan still empty (root cause)** — `PROCESSENTRY32W`/`MODULEENTRY32W`/`WIN32_FIND_STREAM_DATA` missing `CharSet.Unicode` → `ByValTStr SizeConst=260` marshaled as 260 ANSI bytes (304-byte struct) instead of 520 UTF-16 bytes (556-byte struct) → `Process32FirstW` rejected with `ERROR_BAD_LENGTH`. Fixed by adding `CharSet = CharSet.Unicode`.
3. **Network tables malformed** — all four capture methods advanced `buf + IntPtr.Size` (8 bytes) but the table header `dwNumEntries` is 4 bytes → every row read 4 bytes off. Fixed to `buf + 4`.
4. **GetFindings double-wrapped** — `IpcMessages.Response(request.Id, GetFindings(request))` where `GetFindings` already returns a Response → payload was an object, not the findings array. Fixed.
5. **Audit empty values** — the collect methods did `r = r with {...}` on a by-value parameter, silently discarding changes. Fixed by returning `SystemAuditResult` from each and assigning in `Audit()`.
6. **Audit: firewall COM** — `FirewallEnabled[0]` indexer threw `E_INVALIDARG`; fixed to method-call syntax with correct profile values (1=Domain, 2=Private, 4=Public).
7. **Audit: Defender WMI** — `ProductState` property missing on this build (threw `ManagementException` killing the collector); `AntivirusSignatureLastUpdated` is a CIM datetime string, not `DateTime`. Fixed with `SafeGet` guards, `ProductStatus`, and `ManagementDateTimeConverter`.
8. **Audit: updates missing** — `LastUpdateInstalledUtc` was never collected; WU WMI namespace absent on this machine. Added `CollectUpdates` using the Windows Update COM API.

## 16. Limitations & Future Work

**Known limitations (honest):**
- No kernel driver — kernel-mode integrity, early-boot activity, PPL-protected process memory, and rootkit-hidden artifacts are out of scope.
- No AMSI integration code — AMSI is documented as the future integration point for real-time scanning of script/office content.
- No auto-remediation — quarantine/terminate/delete are explicit user actions only.
- WMI/COM availability varies by Windows SKU; collectors degrade gracefully (documented in `SystemAuditor`).
- Full scans are I/O bound (SHA-256 dominates); no incremental scan resume.
- Findings are signals, not verdicts — false positives are possible and the UI is designed for human review.

**Future work:**
- AMSI integration for script/office scanning (documented in `docs/RESEARCH.md`).
- ETW-based telemetry (Sysmon-style event catalog).
- Kernel-mode integrity checks (requires a driver — explicitly out of scope for this build).
- Cloud hash lookup (VirusTotal-style) with privacy controls.
- Scheduled scans and alerting (email/webhook).
- Multi-machine fleet view.

---

*This report is honest about what Sentinel is and is not. It is a research-grade, evidence-based Windows endpoint inspection platform — not a complete antivirus product.*