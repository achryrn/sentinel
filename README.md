# Sentinel — Windows Endpoint Security Scanner

**Sentinel** is a Windows endpoint inspection platform written in C# / .NET 10. It scans files, processes, memory, network connections, persistence mechanisms, and system security posture, then correlates the evidence into risk-scored findings mapped to MITRE ATT&CK tactics.

> **Honest capability statement:** Sentinel is an **inspection and detection platform**, not a complete antivirus product. It does not include a kernel driver, does not hook AMSI, does not auto-execute or auto-delete files, and does not modify process memory. All detections are evidence-based and require user review. See [docs/REPORT.md](docs/REPORT.md) for the full implementation report and limitations.

---

## Architecture at a glance

```
┌─────────────────────┐
│      GUI (WPF)      │   runs as STANDARD USER
└──────────┬──────────┘
           │  named pipe IPC (JSON lines)
┌──────────▼──────────┐
│  Sentinel.Service   │   privileged backend (LocalSystem)
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

Every component is a library class in `Sentinel.Core`; the service, CLI, and GUI are thin hosts over the same code.

## Projects

| Project | Kind | Purpose |
|---|---|---|
| `Sentinel.Core` | classlib (`net10.0-windows`) | Interop, parsers, scanners, detection/correlation engines, storage, IPC, realtime monitor |
| `Sentinel.Service` | exe | Windows service host (LocalSystem); owns the pipe server and privileged operations |
| `Sentinel.Cli` | exe | Headless client for scripting/CI |
| `Sentinel.Gui` | WPF exe | Unprivileged client; speaks IPC only |
| `Sentinel.Tests` | xunit | 123 unit + integration tests |

## Build & run

```powershell
# Build
dotnet build Sentinel.sln

# Run the service (console mode for development)
dotnet run --project src/Sentinel.Service/Sentinel.Service.csproj -- --run

# Install as a Windows service (admin)
dotnet run --project src/Sentinel.Service/Sentinel.Service.csproj -- --install
dotnet run --project src/Sentinel.Service/Sentinel.Service.csproj -- --uninstall

# CLI
dotnet run --project src/Sentinel.Cli/Sentinel.Cli.csproj -- status
dotnet run --project src/Sentinel.Cli/Sentinel.Cli.csproj -- scan C:\path\to\file.exe
dotnet run --project src/Sentinel.Cli/Sentinel.Cli.csproj -- scan --quick
dotnet run --project src/Sentinel.Cli/Sentinel.Cli.csproj -- findings
dotnet run --project src/Sentinel.Cli/Sentinel.Cli.csproj -- audit

# GUI
dotnet run --project src/Sentinel.Gui/Sentinel.Gui.csproj

# Tests
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj
```

## CLI commands

```
status                 Show service status
scan <path>            Scan a file or folder
scan --quick           Quick scan (user profile + common data)
scan --full            Full scan (C:\)
findings               List findings
evidence <entity>      Show evidence for an entity
events                 Show recent events
quarantine <path>      Quarantine a file
quarantine --list      List quarantined items
quarantine --restore <id>   Restore a quarantined item
quarantine --delete <id>    Delete a quarantined item
exclusions             List exclusions
exclusions --add <type> <value>   Add exclusion (path|hash|signer)
exclusions --remove <id>          Remove exclusion
processes              List processes
network                Show network connections
persistence            Show persistence entries
memory [pid]           Analyze memory (all processes or one pid)
audit                  Run system security audit
dump <pid>             Dump process memory (admin)
```

## GUI views (12)

Dashboard, Scan, Threats (findings), Processes, Network, Memory, Persistence, Files, System (audit), Events, Quarantine, Settings (exclusions).

## Detection rules (evidence-based)

Every rule emits **evidence** (source, entity, event, severity, confidence, explanation, details). Rules never produce verdicts alone — the correlation engine combines them per entity.

- **File:** unsigned executable, invalid signature, untrusted signer, high entropy, RWX section, section runtime growth, overlay, TLS callbacks, no ASLR, no NX, timestamp anomaly, from-internet (Zone.Identifier), hidden/system attributes, suspicious location
- **Process:** unsigned, elevated, system-location, suspicious parent
- **Memory:** private RWX region, high-entropy executable region, thread start outside module
- **Network:** suspicious port, exfiltration shape (many outbound connections)
- **Persistence:** suspicious location, startup entry
- **System:** Defender disabled, firewall disabled, UAC disabled, stale updates, guest enabled

## Storage

SQLite at `%ProgramData%\Sentinel\sentinel.db` (service-managed; GUI/CLI never open it directly).

| Table | Purpose |
|---|---|
| `findings` | correlated findings + status |
| `evidence` | evidence items (bounded, trimmed to ~100k rows) |
| `scan_jobs` | scan history |
| `hash_cache` | path → (size, lastWrite, sha256, sha1, md5, firstSeen, verdict) |
| `signer_cache` | signer name → trust state |
| `exclusions` | auditable exclusions |
| `quarantine` | quarantine records |

## Security model

- **Read-only scanning** — no process memory modification, no injection, no auto-execution, no auto-deletion.
- **Quarantine** moves files to `%ProgramData%\Sentinel\Quarantine` with metadata; restore/delete are explicit user actions.
- **Exclusions** are auditable (type, value, scope, added-by, timestamp, rationale) and stored in SQLite.
- **IPC** is a named pipe with JSON-lines protocol; the GUI/CLI are unprivileged clients.

## Known limitations (honest)

- No kernel driver — kernel-mode integrity, early-boot activity, and PPL-protected process memory are out of scope.
- No AMSI integration code (documented as future work; AMSI is a scan *integration* point, not a scanner).
- No auto-remediation; all actions require user confirmation.
- WMI/COM availability varies by Windows SKU; collectors degrade gracefully (see `SystemAuditor`).
- Full scans are I/O bound (SHA-256 dominates).

## Documentation

- [docs/RESEARCH.md](docs/RESEARCH.md) — technical research (Windows internals, PE/COFF, Authenticode, MITRE ATT&CK, AMSI, Sysinternals)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — architecture and data model
- [docs/REPORT.md](docs/REPORT.md) — final 16-section implementation report