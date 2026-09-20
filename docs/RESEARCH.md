# Sentinel: Technical Research

**Scope:** Windows endpoint inspection platform (file / process / memory / persistence / network / system state).
**Principle:** every detection must be *evidence-based* and *correlatable*. A single weak signal is a signal, not a verdict.
**Reference frameworks:** MITRE ATT&CK (behavioral detection), Microsoft Sysinternals (inspection breadth), Microsoft AMSI (scanning integration), Sysmon (telemetry event catalog).

---

## 1. Windows malware detection architecture

| Question | Answer |
|---|---|
| What can it observe? | Files (static content, PE structure, signatures, streams), live processes (modules, threads, memory, tokens), persistence (registry, services, tasks, WMI, startup), network (per-process sockets), event logs, ETW telemetry, security configuration. |
| What cannot it observe? | Kernel-mode integrity (no driver), early-boot activity, protected processes (PPL) memory, encrypted TLS payloads, firmware/EFI state, offline/rootkit-hidden artifacts. |
| Privilege | Read-mostly works as standard user (Toolhelp for processes, IP Helper for sockets, registry read); deep visibility (services full info, all users' registry hives, raw WMI queries) is easier/more reliable elevated; nothing here requires a driver. |
| Reliability | High for *facts* (hashes, signatures, config values); medium for *interpretation* (context-dependent scoring). |
| False positives | Interpretation layer is where FPs originate. Mitigated by evidence-based scoring, signer/path trust, exclusions (explicit + auditable). |
| Performance cost | Full scans are I/O bound (SHA-256 dominates); process/network snapshots are cheap if throttled. |
| Continuous? | Yes for monitoring loops; full scans are on-demand. |
| User mode? | Yes: the entire platform is user mode. |
| Service? | Recommended (privileged scanning service): enables elevated scanning without elevated GUI. |
| Driver? | No. A kernel component is out of scope (documented as future work); honest limitations section included. |
| Microsoft supported? | Yes: only documented Win32/System.Management APIs are used. |

**Implementation strategy:** layered design: data collection (scanners) → evidence → detection engine (per-evidence rules) → correlation engine (entity-linkage) → risk scoring → UI/report. GUI is unprivileged; a service hosts the privileged backend.

---

## 2. Windows process architecture

- Every executable runs in a **process** with a virtual address space, handles, threads, a token (user + privileges + integrity level), and a session. **Processes are the fundamental correlation entity** for endpoint visibility.
- Win32 process access rights: `PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION`, `PROCESS_DUP_HANDLE`... ([Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights)).
- `CreateToolhelp32Snapshot` / `Process32FirstW` / `Process32NextW` enumerate processes and modules without elevated rights ([Process32FirstW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32firstw)).
- `ProcessIdToSessionId` maps a PID to its terminal session.
- WMI `Win32_Process` (`ProcessId`, `ParentProcessId`, `ExecutablePath`, `CommandLine`, `CreationDate`, `SessionId`, `ExecutablePath`) supplies command line + parent linkage that Toolhelp does not ([Win32_Process](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/cimwin32/win32-process)). Note: for elevated/system processes it returns `null` unless the caller is elevated: a documented limitation handled by fallback to name-based lookup.
- Parent PID reuse means parentage is *corroborated* by name, never treated as a ground truth chain.

**Implementation strategy:** Toolhelp snapshot for enumeration; WMI (System.Management) for command line + PPID; `ProcessIdToSessionId` + `Environment.ProcessId`; `OpenProcess` with limited query rights for details; graceful degradation when access is denied. Process → network → modules → memory are all keyed by PID.

---

## 3. PE/COFF executable structure

- DOS header (`IMAGE_DOS_HEADER.e_lfanew`) → PE signature (`PE\0\0`) → COFF header (`IMAGE_FILE_HEADER`: machine, number of sections, timestamp, characteristics) → Optional header (`IMAGE_OPTIONAL_HEADER`: magic, entry point, image base, subsystem, DataDirectory array) → Section table (`IMAGE_SECTION_HEADER`: name, virtual size, raw size, pointer, characteristics).
- Data directories of interest: Import (`IMAGE_DIRECTORY_ENTRY_IMPORT`), Export (`EXPORT`), Resource (`RESOURCE`), Security (Authenticode certificate table), TLS (`TLS`), Debug (`DEBUG`), Exception, LoadConfig, IAT.
- Section characteristics: `IMAGE_SCN_MEM_EXECUTE` (0x20000000), `IMAGE_SCN_MEM_WRITE` (0x80000000), `IMAGE_SCN_CNT_CODE`, `IMAGE_SCN_CNT_UNINITIALIZED_DATA`. **RWX (write+execute) sections are rare in legitimate, optimized, signed binaries**: but present in some packers/protectors and a few legit products; hence *signal, not verdict*.
- Imports/Exports are parsed from the import/export directories; TLS callbacks from the TLS directory.
- Overlay = bytes after the end of the last section's raw data (commonly used by packers/attach-ers); Debug data points to PDB info.
- Timestamps: COFF timestamp is a build-time field, frequently faked by malware; a 0 value or a value far in the future/past is a *weak* signal.

**Implementation strategy:** custom binary parser (`PeParser`), safe bounds-checked reads, zero allocation churn; reports raw values plus derived flags (RWX sections, entry point outside sections, unusual section names, overlay size, TLS callbacks, anomaly flags). Malformed files are captured as `PeParseStatus.Failed` with reason: never exceptions.

---

## 4. Authenticode

- Authenticode is Microsoft's code-signing format: PKCS#7 signed data with a `SPC_INDIRECT_DATA_OBJ` (hash of the PE) attached in the **Security data directory** (WIN_CERTIFICATE, `WIN_CERT_TYPE_PKCS_SIGNED_DATA`).
- Verification (Wintrust): `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`; `WTD_REVOCATION_CHECK_NONE` avoids slow/offline CRL checks by default, and we use `WTD_REVOKE_NONE`/`WTD_CHOICE_FILE`.
- `CryptQueryObject` + `CryptDecodeObjectEx` + `CryptFormatObject` (CERT_QUERY_OBJECT_FILE, `CMSG_SIGNER_INFO_PARAM`, `CERT_NAME_SIMPLE_DISPLAY_TYPE`) extracts signer + timestamp from the embedded PKCS#7 ([CryptQueryObject](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptqueryobject)).
- `WinVerifyTrust` returns `TRUST_E_NOSIGNATURE` (no signature), `TRUST_E_SUBJECT_NOT_TRUSTED`, `TRUST_E_EXPLICIT_DISTRUST`, `TRUST_E_BAD_DIGEST`, `TRUST_E_PROVIDER_UNKNOWN`, `CERT_E_*` chain errors; signature *presence* is checked via the Security directory and `CryptQueryObject` `CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED`.
- **Chain-building is not performed in-app**: we call WinVerifyTrust (OS validates chain/trust against the machine's root store) and *report* status + signer; we never attempt our own chain construction or root pinning (requires treating root updates, cross-signing, and private-enterprise CAs correctly: that is the OS's job).

**Implementation strategy:** `WinVerifyTrust` for validity; `CryptQueryObject`/`CryptDecodeObjectEx` for signer name, issuer, timestamp; classification: `SignedTrusted | SignedUntrusted | SignatureInvalid | Unsigned | Unknown` (errors). Never equate unsigned with malicious.

---

## 5. Windows certificate chains

| Question | Answer |
|---|---|
| What can it observe? | Whether the OS trusts the chain for the given purpose, the embedded signer, embedded timestamp, revocation when requested. |
| What cannot it observe? | Root store content across user/enterprise stores in full fidelity without extra calls; true attestation that the *publisher* is who they claim (identity ≠ trust). |
| Privilege | None beyond file read; revocation checking may need network. |
| Reliability | High for OS verdict; signer extraction is exact. |
| False positives | Revocation failures (offline CRL/OCSP) when revocation checking is enabled: avoided by default (`WTD_REVOKE_NONE`), surfaced as a field. |
| Performance | WinVerifyTrust is fast (cached roots); network revocation is the slow path. |
| Continuous | Yes. |
| User mode / service / driver | User mode; no driver. |
| Microsoft supported | Yes (wintrust.dll, crypt32.dll). |

**Implementation strategy:** OS-verification only (`WinVerifyTrust`), optional revocation flag (default off), signer extraction via `CryptQueryObject`. Report signer, issuer, timestamp, status. Revocation *status* reported when available without forcing network checks.

---

## 6. File reputation

- File reputation = verdict/confidence attached to a file identity (hash, signer, path lineage) from trusted sources.
- Modern reputation is strongly signer-centric (signed + known-publisher ⇒ trusted), hash-centric for unknowns, and path/context-centric for interpretation.
- Sentinel's reputation stack (all local-first):
  1. **Hash cache** (SQLite): first-seen date, local classification, verdicts.
  2. **Signer cache**: signer name → trust state (user decision) and observed frequency.
  3. **Frequency/community signal (local)**: how often a hash/signer has been observed on this machine; rare is *a signal*, never a verdict.
  4. **Optional external provider**: *disabled by default*; when enabled, only SHA-256 (and optionally SHA-1) are sent: never the file, never credentials to the GUI. Provider API keys live in the *service* configuration only.
- No automatic uploads. No hidden calls. Explicit configuration required.

---

## 7. Hash-based detection

- MD5/SHA-1 are legacy compatibility hashes (collision/practical-preimage weakness: [NIST SP 800-131A](https://csrc.nist.gov/pubs/sp/800/131a/r2/final) deprecates SHA-1 for digital signatures beyond 2013; MD5 fully broken). **SHA-256 is the primary identity hash.** SHA-1 kept for legacy tooling interop (Sysmon default uses SHA1; VirusTotal accepts MD5/SHA-1). MD5 only for compatibility lookups.
- Streaming hashing (incremental reads, e.g. 1 MiB blocks) allows bounded memory, progress reporting, and cancellation.
- Hash caching: same path+size+last-write-time ⇒ cached hash; rehash only on change (avoids rescans of large immutable files: big perf win for full scans).
- Hash of *the file* ≠ hash of *the PE content*: Authenticode hashes the PE content; changing anything invalidates the signature (detectable: signed but `TRUST_E_BAD_DIGEST` = modified after signing).

**Implementation strategy:** `IncrementalHash` with SHA256 (primary), SHA1 + MD5 optional; SQLite hash cache keyed (path, size, lastWriteUtc); cache eviction policy by recency; cancellation-aware.

---

## 8. Static malware analysis

- Static analysis inspects content without execution: PE structure, imports/exports, resources, strings/entropy, signatures, overlay, debug info, ADS, script content heuristics.
- Strengths: safe, fast, deterministic, no sandbox needed. Limits: cannot observe runtime behavior, can be evaded by packing/obfuscation; cannot decide "malicious" alone.
- Entropy (Shannon, per 256-byte block) measures randomness: packed/encrypted sections have entropy → ~8.0; but legitimate media/archives/crypto (TLS libs, installers) also have high entropy: **signal only**.
- Import analysis: rare/API-only combinations (e.g. `VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread` in a process that also has persistence hooks) are weighted *in combination with other evidence*, never alone.
- Script content: AMSI scanning for scripts; context analysis for interpreter chains (see §21).

**Implementation strategy:** all static signals become `Evidence` records with explicit reasons; `DetectionEngine` weighs combinations.

---

## 9. Dynamic malware indicators

- Dynamic indicators require runtime telemetry: process creation (Sysmon EID 1), image loads (EID 7), remote thread creation (EID 8), process access (EID 10), file creates (EID 11), registry persistence writes (EID 12-14), network (EID 3), DNS (EID 22), process tampering (EID 25), driver loads (EID 6).
- Sentinel's own runtime sensors: process snapshots (toolhelp/WMI), memory region scans (VirtualQueryEx), network tables (GetExtended*Table), ReadDirectoryChangesW (file events), WMI event queries (process create; `__InstanceCreationEvent` for `Win32_Process`).
- These are **snapshot/event sensors**, not a kernel agent: race windows exist; fast-living processes can be missed (mitigated by WMI event subscription).

---

## 10-11. Process inspection & DLL/module inspection

- Modules per process via `Module32FirstW/NextW`; limited to same-or-higher-integrity processes.
- Full path via `GetModuleFileNameEx` fallback; base addresses via module snapshots.
- Unusual module patterns: unsigned module in system process, module from user-writable dirs in elevated process, module with no file on disk, `%TEMP%` modules, mismatch between module name and file identity.

**Implementation strategy:** Toolhelp module snapshot; per-module signature+path classification; "module loaded but file absent" and "unsigned module in signed system process" become weak-to-moderate evidence.

---

## 12. Windows services

- Services live in `HKLM\SYSTEM\CurrentControlSet\Services\<name>`: `ImagePath`, `Start` (0 boot, 1 system, 2 auto, 3 manual, 4 disabled), `Type` (0x10 own process, 0x20 shared process, 0x110 kernel driver), `ObjectName` (account), `Description`, `FailureActions`.
- `SCM` APIs (`OpenSCManager`, `QueryServiceConfig2W`) and `sc.exe` are the privileged view; registry read is the unprivileged view. Sentinel reads the registry (works unelevated; service account info read). Elevated: `QueryServiceConfig2` for full fidelity.
- Watch: non-Microsoft services whose image path is user-writable, unsigned, in temp, or recently added; service binary replaced; kernel driver services (Type 0x110) unsigned.

**Implementation strategy:** registry enumeration of `Services` (read-only); classification by path/signer/start type/age; flagged in persistence findings; no modification.

---

## 13. Scheduled tasks

- Tasks: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` (metadata + `Task` blob, Actions key), plus task XML via `schtasks /query /xml` / COM `Schedule.Service` (elevated for full fidelity).
- Watch: tasks that run executables from user-writable dirs, tasks created recently, tasks referencing unsigned binaries, task actions that are scripts (`powershell`, `mshta`, `wscript`...), "on logon"/"on idle"/repetition triggers.

**Implementation strategy:** registry `TaskCache` walk + `schtasks /query /xml ONE` per task for actions (elevated service; gracefully degrades to registry-only when unelevated).

---

## 14. Startup locations (Autoruns-style)

Enumeration set (subset of the [Sysinternals Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) surface):
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `RunServices`, `RunServicesOnce`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (and `Wow6432Node`)
- Startup folders: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup` (+ `All Users` legacy)
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (Userinit, Shell)
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` (Debugger value: classic hijack point)
- `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` (BootExecute)
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppInit_DLLs` (+ `RequireSignedAppInit_DLLs`)
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms` (RDP startup)
- Logon scripts: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts`, `HKCU\...\Scripts`
- `HKCU\Environment\UserInitMprLogonScript`
- Shell extensions: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`, `\ShellIconOverlayIdentifiers`, `HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers`, `\Directory\shellex\ContextMenuHandlers`, `\CLSID` (only *identified* CLSIDs are listed: no GUID noise)
- Browser extensions: Chrome `Extensions` prefs JSON, Edge same, Firefox `extensions.json` (added as *extension listing* evidence; no auto-verdicts)

**Implementation strategy:** registry + filesystem walk; each entry normalized into `PersistenceEntry` (location, value, image, args, user hive, signer, hash, times, risk, reason); context menu CLSIDs resolved via `HKCR\CLSID` + `InprocServer32` when resolvable (bounded).

---

## 15. Registry persistence

- Run/RunOnce (both hives, Wow6432Node), services, Winlogon, IFEO, AppInit_DLLs, ShellExecuteHooks, Active Setup (`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`: autorun capability), WMI (below).
- Registry writes are observable in near-real-time via Sysmon EID 12-14 or `ReadDirectoryChangesW` on `HKLM`? **No**: registry has no ReadDirectoryChangesW; the supported options are ETW (`Microsoft-Windows-Kernel-Registry`), WMI registry events (limited), or `RegNotifyChangeKeyValue` (single key, needs per-key handles). Sentinel's realtime registry monitoring uses `RegNotifyChangeKeyValue` on a curated list of persistence keys (documented limitation: per-key handles, not a global hook).

**Implementation strategy:** one-shot full persistence scan via registry reads; realtime via `RegNotifyChangeKeyValue` on curated keys.

---

## 16. WMI persistence

- WMI persistence = `__EventFilter` + `__EventConsumer` (ActiveScriptEventConsumer / CommandLineEventConsumer / LogFileEventConsumer) + `__FilterToConsumerBinding` in root\subscription.
- Enumeration is read-only via WMI queries against `root\subscription` (elevated for full fidelity on some systems).
- Watch: any binding, especially `CommandLineEventConsumer` or `ActiveScriptEventConsumer` executing from user-writable paths.

**Implementation strategy:** WMI query `root\subscription` for the three classes; create `PersistenceEntry` per binding.

---

## 17. Browser persistence

- Chrome/Edge: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions`, `Secure Preferences`/`Preferences` JSON (extensions.enabled), `External Extensions` (`HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`).
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*\extensions.json`.
- Legacy: `BHO` (IE): `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects` + `HKCR\CLSID\<guid>\InprocServer32`.

**Implementation strategy:** read-only; extensions listed with path, name, id, signer status where resolvable; no auto-verdicts.

---

## 18. Drivers

- Drivers: `HKLM\SYSTEM\CurrentControlSet\Services\*` with `Type=0x110` (kernel) or 0x120 (file system); image path → `\SystemRoot\System32\drivers\...`.
- `sc.exe query` (or SCM) gives state (running/stopped) and start type.
- Watch: unsigned kernel drivers, signed-by-unknown third parties, recently added, image missing, path in user-writable dirs (rare for legit).
- Sentinel does **not** unload/disable drivers.

---

## 19. Kernel/user-mode boundaries

| Layer | Can see | Cannot see |
|---|---|---|
| User mode | Win32 object namespace, process/module/memory visibility subject to security, network tables, files, registry | SSDT hooks, DKOM-hidden processes (toolhelp walks the linked list), kernel objects |
| ETW | Kernel provider events incl. process/thread/registry/file/image/network if enabled (needs admin for many kernel providers; some require driver "AutoLogger" config) | Post-hoc integrity of kernel data structures |
| Event log | Sysmon (if installed), Security log (if auditing enabled), System log | Anything not audited |
| Kernel driver | Object/thread/process callbacks, minifilter for file ops, WFP callout |: (needs the driver, signing, maintenance) |

Rootkit caveat: a user-mode scanner can *legitimately* flag missing modules, hidden handles, process tampering (Sysmon EID 25), but **cannot claim rootkit detection**. Honest wording required.

---

## 20. ETW

- ETW providers are the standard telemetry backbone (Sysmon, Defender, .NET events all ride on it).
- Without a provider manifest/consumers, a general-purpose user-mode app can consume the *Microsoft-Windows-Kernel-Process* provider only with elevation for some events; kernel providers frequently require admin (or dedicated AutoLogger config / driver for early boot).
- Sentinel uses ETW *only* where supported and stable: not in v1 core (documented as future work with provider choices). Realtime instead uses WMI process events + ReadDirectoryChangesW + network polling: all documented, all supported, no hidden ETW dependencies. Rationale: ETW kernel providers need admin and are version-sensitive; the value/cost did not justify them in the first iteration.

---

## 21. Windows Event Logs

- Read via `EventLogReader`/`System.Diagnostics.Eventing.Reader`: supported, unprivileged for Application/System; Security/Sysmon need admin.
- Relevant channels:
  - Security: 4624 (logon), 4625 (failed logon), 4672 (admin logon), 4688 (process creation: **only when audit policy is enabled**), 7045 (service install), 4697 (service install, newer), 4688/4689 chain.
  - System: 7045 service install; 1001 (WER crash); 6005/6006 (boot/shutdown).
  - `Microsoft-Windows-WER-SystemErrorReporting` and `Application` 1000/1001: crash indicators.
  - Sysmon Operational (if installed): EIDs 1, 3, 6, 7, 8, 10, 11-15, 22, 25.
- Sentinel: event *sources* (Security 4624/4625/4672/4688/7045/4697, System 7045, Application 1000/1001, WER 1001, Sysmon channel when present) read as evidence; documented requirement that Security-channel events depend on audit policy, Sysmon events on Sysmon installation. **Failure to read a channel is reported as "unable to inspect", never silently treated as "no events".**

---

## 22. Sysmon

Sysmon reference (verified against Microsoft Learn, June 2026 revision):

| EID | Event | Sentinel use |
|---|---|---|
| 1 | Process creation (cmdline, parent, hashes, GUIDs) | Parent-child correlation, script chains |
| 3 | Network connection (source process, IPs, ports, hostnames) | Process↔network linkage |
| 6 | Driver loaded (hashes, signatures) | Driver findings |
| 7 | Image loaded (per-process) | Module anomalies (costly; not default) |
| 8 | CreateRemoteThread (source/target, StartAddress) | Injection correlation |
| 10 | ProcessAccess (open process w/ granted access) | Remote-access correlation |
| 11 | FileCreate (autostart/temp/downloads) | Drop indicators |
| 12-14 | Registry events (persistence writes) | Persistence timing |
| 15 | FileCreateStreamHash (ADS/MOTW) | ADS indicators |
| 19-21 | WMI filter/consumer/binding | WMI persistence |
| 22 | DNS query | DNS telemetry |
| 25 | ProcessTampering (hollowing) | Hollowing indicator |
| 29 | FileExecutableDetected | Executable creation |

Sysmon requires admin install and is **optional** in Sentinel: if the channel exists we read it; if not, we say so. Sentinel never claims Sysmon coverage it doesn't have.

---

## 23. AMSI

- AMSI (Antimalware Scan Interface) lets an app ask all installed AMSI providers (Windows Defender + third-party) to scan content: files, memory/streams, and reputation-adjacent content ([AMSI portal](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal), verified).
- API surface: `AmsiInitialize` → `AmsiScanBuffer` / `AmsiScanString` → optional `AmsiOpenSession` (correlate scans of one content stream) → `AmsiUninitialize`. Result via `AMSI_RESULT` + `AmsiResultIsMalware` ([AmsiScanBuffer](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer), verified). Windows 10+, Server 2016+.
- Known constraints: large files should be scanned as *streams* (Defender's documented AMSI size limit guidance: scan in chunks with a session, or limit to a few MB per call); AMSI is a *scanning interface*, not a verdict authority: "not flagged by AMSI" ≠ "clean"; Defender may flag our own process if we behave like malware (avoided by not doing anything dangerous); no file path parameter: content is streamed.
- Sentinel integration: optional, on by default with a size cap (e.g. 4 MB for single-buffer scans; streamed chunked scans for larger files via session); used for scripts (`.ps1`, `.vbs`, `.js`, `.hta`, `.bat`, `.cmd`) and for on-demand "scan content in memory" of *our own* protected regions. AMSI result is *evidence* with its own severity; never the sole verdict.

---

## 24. Windows Filtering Platform / networking APIs

- WFP is for *blocking/filtering* traffic: requires a callout driver for full inspection; Sentinel does not block traffic and does not need WFP.
- Supported observability APIs (user mode, no driver):
  - `GetExtendedTcpTable` / `GetExtendedUdpTable` with `TCP_TABLE_OWNER_PID_ALL` / `UDP_TABLE_OWNER_PID` (verified: returns `MIB_TCPTABLE_OWNER_PID` with owning PID).
  - `GetIfTable2` for interface names; `GetBestRoute2` optional.
  - DNS: `GetHostByAddr`/`DnsQuery` for reverse lookup; **no DNS query telemetry without admin/ETW/Sysmon**: DNS association for live connections is reverse-lookup based, plus optional Sysmon EID 22 read.
- TLS metadata: the only honest statement: payloads are encrypted; Sentinel does not MITM TLS, does not install root certificates, does not pretend to read HTTPS content.

---

## 25. DNS telemetry

- Live: reverse lookups (hostname for IP) per connection: cheap, best-effort.
- Event-driven: Sysmon EID 22 (requires Sysmon + admin).
- ETW `Microsoft-Windows-DNS-Client`: admin required; future work.
- Local DNS cache read (`ipconfig /displaydns` parse): available unelevated; provides recent queries with record data. Used as a *supplement* for "recent DNS activity" view.

---

## 26-28. TCP/UDP inspection, Windows Firewall, process-to-network correlation

- TCP/UDP tables (owner PID) are the primary live source; state machine from `MIB_TCP_STATE_*`.
- Firewall: read profile state via `INetFwPolicy2` COM (`FirewallEnabled`, `DefaultInboundAction`, profile type): read-only.
- Correlation: connections are keyed by owning PID; join with process info (path, signer, risk) at render time; new-process-then-connection sequences come from WMI process events + periodic network snapshots with timestamps (bounded history).
- Listening sockets with PID 0/System (e.g. services) handled explicitly (no process path: reported as system-owned).

---

## 29. Memory mappings & executable/private regions

- `VirtualQueryEx` (verified): per-region `MEMORY_BASIC_INFORMATION`: `State` (MEM_COMMIT/RESERVE/FREE), `Protect` (PAGE_EXECUTE_*), `Type` (MEM_PRIVATE/MAPPED/IMAGE). PAGE_EXECUTE_READWRITE (RWX) and PAGE_EXECUTE_WRITECOPY are explicitly distinguishable; `MEM_IMAGE` + RWX = modified/COW image region.
- Classification model (evidence-based):
  - `MEM_IMAGE` + executable protection → normal code (kernel32, ntdll...).
  - `MEM_PRIVATE` + executable protection + committed → **unbacked executable private memory**: the core suspicious class (shellcode/loaders), but *weighted* by size, count, process reputation, and thread start addresses (JIT runtimes, .NET, and some legit apps allocate this: e.g. `clrjit`, `V8`, Go, Rust JIT-less allocs of executable memory).
  - RWX anywhere → moderate signal (documented; JIT/CLR + some drivers legitimately do this).
  - Thread start address not inside any loaded module (cross-checked against module snapshot base ranges) → weak-moderate (hijacked/unmapped thread starts, also common with JIT).
- `QueryWorkingSetEx` for per-page shared/private granularity when needed (perf-gated; not default).

---

## 30. Process injection detection (MITRE T1055)

MITRE T1055 detection strategy (verified, current): *"Detects process injection by correlating memory manipulation API calls (e.g., VirtualAllocEx, WriteProcessMemory), suspicious thread creation (e.g., CreateRemoteThread), and unusual DLL loads within another process's context."* (DET0508/AN1399).

Sentinel's correlation (user-mode observability):

| Signal | Source |
|---|---|
| Process A opened process B with VM access | Sysmon EID 10 (when present) |
| Remote memory allocation/write into B | Sysmon EID 10 + memory snapshot deltas (unbacked exec region appears) |
| B gains unbacked executable region | VirtualQueryEx snapshot |
| Thread created in B from unmapped address | Thread start addresses vs module ranges (toolhelp + NtQueryInformationThread) |
| Unexpected DLL load in B | Module snapshot diff (unsigned module in signed process) |

No single signal fires alone; ≥2 correlated signals raise a finding with explicit evidence list. Legit tools (debuggers, profilers, AV, injection-based dev tools) produce partial matches: hence the correlation requirement and the false-positive section.

---

## 31. Process hollowing detection

- Hollowing indicators: `NtUnmapViewOfSection` on own image (needs kernel telemetry: not in scope user-mode), Sysmon EID 25 (ProcessTampering) when present, plus observable artifacts: executable region of a mapped image whose section characteristics disagree with the on-disk PE (compare `MEM_IMAGE` region attributes to the PE section permissions), image path module whose headers in memory mismatch the disk file, threads whose start addresses are inside the *old* image region after unmapping.
- Sentinel implements: memory-vs-disk PE comparison (when the file is readable) for loaded modules of high-interest processes (elevated), thread start outside modules, Sysmon EID 25 read. Documented as "indicators, not confirmation".

---

## 32. Thread execution anomalies

- Per-thread: start address (via `NtQueryInformationThread`/`ThreadQuerySetWin32StartAddress`: requires `THREAD_QUERY_INFORMATION`; limited), context is snapshot-only.
- Cross-check start address against module base ranges; classify: inside module / inside known JIT region / unbacked / inaccessible.
- Threads with start addresses in unbacked executable memory **in a process that didn't create it recently** are the strongest user-mode thread anomaly signal.

---

## 33. Remote process access & handle analysis

- Remote access events: Sysmon EID 10 (admin + Sysmon). Sentinel does not enumerate other processes' handles in v1 (requires `NtQuerySystemInformation` with `SystemExtendedHandleInformation`, admin; version-fragile): documented as future work; the *evidence* of remote access comes from EID 10 + memory anomalies correlation.

---

## 34. Code-signing verification (see §4-5)

---

## 35. Alternate Data Streams

- NTFS ADS: `File.Exists(path + ":stream")`/`Directory.EnumerateFileSystemEntries` with `:stream` suffix; `GetFileAttributesEx`/`FindFirstStreamW` enumerates streams properly (supported, unprivileged).
- `Zone.Identifier` (MOTW) is an ADS every downloaded file gets: read it to report "downloaded from internet" context.
- Suspicious ADS: executable content in ADS (`:stream.exe`, `:payload`), large ADS on system binaries. Not verdicts alone.

---

## 36. NTFS metadata & shadow copies

- NTFS metadata (timestamps, creation/change) readable via standard APIs (`FileInfo`, `GetFileInformationByHandle`).
- Shadow copies: `vssadmin list shadows` (admin) or WMI `Win32_ShadowCopy`: read-only listing; not used for scanning in v1 (perf); documented.

---

## 37. Quarantine architecture

- Requirements: unique ID, original path preservation, metadata preservation, safe restore, hash verification, audit trail, permission restriction.
- Design: quarantine root under `ProgramData\Sentinel\Quarantine` (service account only ACLs; service must run as a real account with explicit permissions: LocalSystem is required for the elevated scan service and is the ACL owner; the GUI never touches quarantine directly, only via the service IPC).
- Layout: `<id>\` with `original.json` (path, hashes, times, signer, reason, evidence IDs) + `file` (renamed, read-only, SYSTEM ACLs). Restore = verify hash of quarantined file against stored hash, copy back to original path (if still absent), verify again, update audit trail. Delete = verify-then-delete with audit row.
- Default flow: **Detect → Explain → User confirmation → Quarantine**. Never auto-delete. Real-time protection mode (if enabled) quarantines after configurable policy, never deletes.

---

## 38. Safe file handling

- Scanner reads files with `FileShare.ReadWrite | FileShare.Delete` (open handles by AV/other tools must not break scans), `ReadOnly` file access, no writes ever to scanned files, cancellation every chunk, no writes into scanned trees, bounded memory (streaming).

---

## 39. Detection rule engines & false-positive reduction

- Architecture: `Evidence` (source, timestamp, entity, event, severity, confidence, explanation) → per-evidence `DetectionRule` (checks evidence record) → `CorrelationEngine` (links evidence by entity + time windows) → `RiskAssessor` (aggregates with explicit reasons) → `Finding` (severity, confidence, reason list, affected object, related events, recommended action).
- FPs reduced by: signer trust (Microsoft/known), path policies (system dirs), frequency baselines (only "new" destinations/processes flagged), JIT/CLR allowances for executable memory, explicit user exclusions (auditable), no single-signal verdicts.
- Every finding must list its reasons; the UI shows them.

---

## 40. Scan scheduling & incremental scanning

- Scheduling: `Task Scheduler`-style internal scheduler (timespan-based, e.g. daily full scan) executed by the service.
- Incremental: hash cache keyed (path, size, last-write); full scans skip unchanged files when the cache says hash already known *and* user enabled "skip unchanged" (default on for Full scans); quarantine inventory rescanned each time.
- Never fake progress: files enumerated upfront where cheap (folder scans) → exact counts when feasible; drive/`C:\` full scans estimate via enumeration; UI supports indeterminate state.

---

## 41. Real-time monitoring

| Mechanism | Supported? | Notes |
|---|---|---|
| File events | Yes: ReadDirectoryChangesW (per-directory, event-driven, no polling) | Curated roots: Startup folders, Downloads, Temp, ProgramData\Sentinel, service dirs |
| Process creation | Yes: WMI `__InstanceCreationEvent` on Win32_Process | 2-10 s latency class, elevated for full fidelity; snapshot reconciliation every 30-60 s as backstop |
| Persistence (registry) | Yes: RegNotifyChangeKeyValue on curated keys | Per-key handles; documented |
| Persistence (tasks/services) | Limited: Periodic reconciliation (bounded, e.g. 5 min) | No supported push API; documented |
| Network | Yes: Bounded polling (2 s) + event linkage | No driver; documented |
| Behavior | Yes: Evidence stream + correlation engine | Same pipeline as scans |

No full-disk polling loops anywhere.

---

## 42. Privilege escalation boundaries

| Requirement | Needed |
|---|---|
| File scanning, hashing, PE, signatures, ADS, folder scans | Standard user |
| Full process detail (all users, elevated processes) | Administrator |
| Full services/task detail, WMI subscriptions full fidelity | Administrator (service) |
| Memory scanning of elevated/system processes, dumps of them | Administrator + (some) SeDebugPrivilege |
| Sysmon event read, Security log | Administrator (service) |
| PPL/protected process memory | Not attempted: documented boundary |
| Kernel structures, early boot, SSDT/DKOM | Driver: out of scope |

---

## 43. Performance constraints

- SHA-256 streaming ≈ 0.5-1.5 GB/s typical; full disk scan is I/O-bound: throttle with per-second byte budget + CPU% budget, allow cancel/pause/resume.
- Process snapshot ~10-50 ms per 1000 processes (toolhelp); memory scan of one process ~1-10 ms per 100 regions; network tables ~1-5 ms: all trivially safe at 2-30 s intervals.
- Event store: bounded ring (in-memory, e.g. 5 000) + SQLite persisted; `ReadDirectoryChangesW` buffers backpressure; WMI events bounded.
- GUI: view models are throttled (dispatcher batching), lists virtualized; no UI work on scan threads.

---

## 44. Key reference material

- [AMSI portal + AmsiScanBuffer](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) (Microsoft, verified 2026-08)
- [Sysmon (event catalog, EIDs 1-29)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (Microsoft, verified 2026-08)
- [MITRE ATT&CK T1055 Process Injection: Detection Strategy (DET0508/AN1399)](https://attack.mitre.org/techniques/T1055/) (verified 2026-08)
- [VirtualQueryEx / MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex) (Microsoft, verified)
- [GetExtendedTcpTable / MIB_TCPTABLE_OWNER_PID](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) (Microsoft, verified)
- [Win32_Process](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/cimwin32/win32-process) (Microsoft)
- [Process32FirstW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32firstw), [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights) (Microsoft)
- [NIST SP 800-131A (hash algorithm transitions)](https://csrc.nist.gov/pubs/sp/800/131a/r2/final): SHA-256 primary, SHA-1/MD5 legacy only
- [Sysinternals Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns): autostart location reference
- [Sysinternals Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer): process inspection reference
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust), [CryptQueryObject](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptqueryobject) (Microsoft)
- [Win32_ShadowCopy](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/win32-shadowcopy) (Microsoft, read-only)

---

## 45. Honest capability statement

Sentinel is a **user-mode endpoint inspection platform**. It provides deep, evidence-based visibility and correlation. It is **not** a complete antivirus: it cannot detect kernel/firmware/EFI compromise, cannot inspect protected-process (PPL) memory, cannot guarantee detection of every rootkit or zero-day, cannot see encrypted traffic content, and cannot claim coverage of telemetry channels it was not given access to (Security log without audit policy, Sysmon without Sysmon, WMI for elevated processes without elevation). The UI and reports state these limits in the user's language.
