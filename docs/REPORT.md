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

| Table | Purpose | Bound |
|---|---|---|
| `findings` | correlated findings + status | cap 200k + 30/180-day status retention; **1 row per entity** (deterministic id) |
| `evidence` | evidence items | cap 100k rows |
| `events` | service/realtime event log | cap 5k rows |
| `scan_jobs` | scan history | cap 2k rows |
| `hash_cache` | path → (size, lastWrite, sha256, sha1, md5, firstSeen, verdict) | cap 2M rows; get-before-compute |
| `hash_blacklist` | known-bad SHA-256 (seeded with EICAR) | small |
| `signer_cache` | signer name → trust state, observed count | — |
| `exclusions` | auditable exclusions | — |
| `quarantine` | quarantine records | — |

**The 52 GB incident, root cause and fix (this hardening round):**

1. *Every evidence item created a new GUID finding.* A single file could produce dozens of rows per scan, and each scan multiplied the table. Fixed with deterministic finding IDs (`fnd-` + SHA-256 of the entity key), a finding gate (≥ 2 signals / medium+ severity / conf ≥ 0.75), and `UpsertFindingConverged` (one row per entity even if the file is found again).
2. *The realtime monitor watched its own database/WAL directory.* Every WAL write changed the directory → an event → more evidence → more writes → a feedback loop. Fixed by curating watch roots (startup locations only), evidence-kind filtering, batched writes, and caps with retention.
3. *Unbounded caches and logs.* `hash_cache`, `events`, `scan_jobs`, and `findings` now all have explicit caps plus an age-based retention pass; VACUUM runs only at ≥ 50% waste; dumps are trimmed.

**Verified:** the `test/SoakTest` harness storms the store for ~2 minutes then settles — the database stays at **~2.6 MB** (bounded), and the EICAR E2E run keeps `sentinel.db` at **~0.35 MB** after repeated rescans plus live realtime monitoring.

**Follow-up regression found & fixed during resource measurement:** the first run of an 880-file (547 MB) folder scan grew the store to **54 MB** — `details_json` was embedding the *full* scan report per evidence row (complete PE import/export tables, avg ~12 KB, up to 111 KB per row). Fixed at two layers: `DetectionEngine.CapDetailsJson` (4 KB cap, valid-JSON summary keeps the head) and a store-side cap on every insert. The same scan now produces a **~6.4 MB DB** (+ ~8 MB transient WAL, checkpointed every 60 s). Covered by regression test `CapDetailsJson_BoundsOversizedPayload_KeepsValidJson`.

**Measured resource profile (Windows 11 x64, service process):**

| Sector | Idle | Active scan (547 MB / 880 files) |
|---|---|---|
| RAM | ~55 MB working set / ~17 MB private | peak ~250 MB working set, falls back to ~135 MB after |
| CPU | ~3% of one core | one core, **BelowNormal priority** (new — scans yield to interactive work) |
| GPU | 0 (service is CPU/disk text-mode compute) | 0 |
| Storage | no writes; 60 s cleanup, 30 min audit | ~6.4 MB DB + transient WAL; caps + details cap prevent growth |
| Disk I/O during scan | none | sequential single-threaded reads; no throttle by design (priority handles responsiveness) |

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

Every rule is a pure function `(scanner output) → Evidence?`. Rules never produce verdicts alone. 40+ structural rules across six sources (see §6–§11) plus four content/behavioral engines (new in this hardening round):

- **YARA-lite rule engine** (`RuleEngine`) — parses a YARA subset (meta/strings/condition; ascii, wide, nocase, hex-with-`?`; `and`/`or`/`not`, `N of`, `any of`). Default pack of 10 rules embedded; user rules auto-load from `%ProgramData%\Sentinel\rules\*.rule`. Robustness: unparseable constructs (regex strings, unknown sections) skip that rule only — the pack survives. Byte matching limits at 8 MiB per file.
- **AMSI scanner** (`AmsiScanner`) — P/Invoke against amsi.dll (`AmsiInitialize`/`AmsiScanBuffer`); verdict ≥ 0x4000 (blocked by admin) counts as *Detected* evidence. Read-only provider query, not a hook. Availability is probed once and reported (unavailable → silently skipped).
- **Script analyzer** (`ScriptAnalyzer`) — heuristics over script/office-ish text formats: encoded commands (`-enc`/`FromBase64String`), download cradles (`IEX(New-Object Net.WebClient).DownloadString`), execute chains, char-code assembly (`chr(`-heavy), base64/split-join obfuscation, persistence hooks (Run keys, schtasks), credential access (mimikatz, `net user`, `Get-Credential`). Latin-1/UTF-16/UTF-8 decoding; 4 MiB cap; extension gate widened to include small `.txt`/`.com`/`.scr` (EICAR tests and disguised payloads).
- **Process-chain analyzer** (`ProcessChainAnalyzer`) — realtime parent→child chain rules with a bounded 1024-PID ring: encoded launch, download cradle → network child, hidden launcher, credential tool (Critical), script-host child, Office→PowerShell child, schtasks persistence. Fires on the *chain*, not a single process.
- **Process-view discrepancy** — Toolhelp (native) vs WMI PID comparison: native-only PIDs → High `process-hidden-from-wmi` (rootkit artifact candidate); WMI-only → Low race note. Runs on a bounded poll inside the realtime loop.
- **SHA-256 blacklist** — `hash_blacklist` table, seeded with the EICAR hash; every scanned file is checked before hashing (hash cache miss path), producing `known-malware-hash` (Critical 0.98) evidence and a report note. Mutable at runtime (`blacklist --add/--remove`).

EICAR E2E proof (this machine): scanning `test/eicar-test.txt` produced a **Critical finding (risk 100.0, conf 1.00)** with three independent evidence sources — `rule-eicar_test_file`, `amsi-detected`, `known-malware-hash`. Re-scans converge to a single finding row.

## 13. Correlation Engine & Risk Scoring

- **Correlation:** evidence is grouped by entity (file path, PID, connection key, persistence key, system) within a 60-second window; distinct signals per entity are combined into a `Finding` with max severity, confidence `min(1, 0.3 + Σconf·0.35)`, deduplicated reasons, MITRE tactic tags, and a recommended action (immediate review / review / informational).
- **Gating (storage fix):** a finding is created only when the entity has ≥ 2 distinct signals, or max severity ≥ Medium, or max confidence ≥ 0.75. A single weak signal (unsigned exe, MOTW, no-ASLR) stays *evidence* — it is not a verdict and no longer floods the findings table.
- **Deterministic finding IDs:** `fnd-` + SHA-256(`sentinel-finding:` + entity key). One row per entity even across scans, sessions, and service restarts; `UpsertFindingConverged` preserves user status (New/Allowed/Quarantined) and accumulates occurrence counts. This is the core de-duplication: the same file found 100 times creates 1 row, not 100.
- **Risk scoring:** `RiskAssessor` computes a weighted score from evidence severities and event weights; findings are stored with `risk_score` and listed highest-first.

## 14. IPC & Service Host

- **Protocol:** named pipe `\\.\pipe\sentinel\ipc`, JSON-lines, camelCase, case-insensitive, `IpAddressConverter` for IP serialization.
- **Commands:** Ping, Status, ScanFile/Folder/Quick/Full/Process/Network/Persistence/Memory, AuditSystem, CancelScan, GetFindings, GetEvidence, UpdateFindingStatus, GetExclusions, Add/RemoveExclusion, GetQuarantine, QuarantineFile, Restore/DeleteQuarantine, GetEvents, GetScanJobs, GetRealtimeEvents, DumpProcessMemory. **GetBlacklist, AddBlacklist, RemoveBlacklist, ReloadRules**.
- **Events:** `scan-progress`, `file-report`, `realtime-event` broadcast to connected clients; GUI re-raises on the UI thread.
- **Service modes:** console (`--run`) for development, Windows service (`--install`/`--uninstall`) for production.

**GUI (WPF, 12 views):** Dashboard (live posture + recent findings), Scan, Threats (findings), Processes, Network, Memory, Persistence, Files, System (audit), Events, Quarantine, Settings (exclusions). All views refresh via IPC; the dashboard shows Defender/firewall/UAC posture from a fresh audit.

**CLI (16 commands):** `status`, `scan <path|--quick|--full>`, `findings`, `evidence <entity>`, `events`, `quarantine [--list|--restore|--delete]`, `exclusions [--add|--remove]`, `processes`, `network`, `persistence`, `memory [pid]`, `audit`, `dump <pid>`, `rules [--reload]`, `blacklist [--add|--remove]`, `help`. `status` reports enabled privileges, rule count, AMSI availability, and blacklist size.

## 15. Testing & E2E Verification

**Unit/integration tests: 154/154 passing** (`dotnet test`):

| Suite | Tests | Coverage |
|---|---|---|
| `DetectionEngineTests` | 52 | every rule, normalization, edge cases |
| `PeParserTests` | 21 | PE parsing, malformed files, sections, imports, TLS, overlay |
| `RuleEngineTests` | 10 | YARA-lite parse/eval (EICAR, wide/nocase/hex, conditions, malformed-skip) |
| `ScriptAnalyzerTests` | 4 | encoded/db/obfuscation/persistence flagging, benign silence |
| `ProcessChainAnalyzerTests` | 6 | chain rules, ring bound, benign silence |
| `CorrelationEngineTests` | 17 | grouping, gating, deterministic IDs, confidence, tactics, risk scoring |
| `SentinelStoreTests` | 17 | SQLite CRUD, findings, evidence, exclusions, quarantine |
| `StorageRetentionTests` | 4 | caps, retention, converged upsert preserves user status |
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
| Storage soak | ✅ 2-minute event storm + 60 s settle → DB stays **2.6 MB** (bounded; the historical failure was 52 GB) |
| EICAR (new engines) | ✅ `scan test/eicar-test.txt` → **Critical finding (conf 1.00)** from 3 engines: `rule-eicar_test_file`, `amsi-detected`, `known-malware-hash` |
| Finding convergence | ✅ 3 re-scans of the same file produce **1 finding row** (deterministic id + converged upsert) |
| Batch-writer/cleaner race | ✅ soak exposed a pending-transaction race (`InsertBatchAsync` vs cleaner); serialized under the single-writer lock and re-verified |

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
- AMSI is **provider-queried** (content pushed through amsi.dll with one call per buffer) but **not hooked** — realtime script/office interception remains future work; as a query it is one evidence source, not a stream.
- Privileged introspection needs an elevated service; in console mode an admin shell is required to enable SeDebug/SeBackup/SeRestore/SeTakeOwnership/SeSecurity. Partial grants are logged and degrade gracefully.
- No auto-remediation — quarantine/terminate/delete are explicit user actions only.
- WMI/COM availability varies by Windows SKU; collectors degrade gracefully (documented in `SystemAuditor`).
- Full scans are I/O bound (SHA-256 dominates); no incremental scan resume.
- Findings are signals, not verdicts — false positives are possible and the UI is designed for human review.

**Future work:**
- AMSI hooking / realtime script+office interception (the AMSI query path exists; the hook is deliberately not part of this read-only build).
- Kernel-mode integrity checks (requires a driver — explicitly out of scope for this build).
- ETW-based telemetry (Sysmon-style event catalog).
- Cloud hash lookup (VirusTotal-style) with privacy controls.
- Scheduled scans and alerting (email/webhook).
- Multi-machine fleet view.

---

*This report is honest about what Sentinel is and is not. It is a research-grade, evidence-based Windows endpoint inspection platform — not a complete antivirus product.*