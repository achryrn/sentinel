Sentinel - production build
============================

Components
  serviceSentinel.Service.exe   backend host (LocalSystem service when installed;
                                  "Sentinel.Service.exe --run" runs it in console mode)
  cliSentinel.Cli.exe           headless client (status / scan / findings / ...)
  guiSentinel.Gui.exe           WPF dashboard
  toolsSentinel.Setup.exe       installer / uninstaller (self-contained, runs on any
                                  x64 Windows; self-elevates via UAC)

Requirements
  .NET 10 Desktop Runtime (x64) for the GUI and framework-dependent service/cli
  (installer itself needs nothing - the runtime is embedded in setup.exe)

Install (double-click, or:)
  install.bat        -> copies to %ProgramFiles%Sentinel, registers + starts the
                        "Sentinel" service (auto start, LocalSystem), writes the
                        Programs menu shortcuts and the Add/Remove Programs entry

Uninstall
  uninstall.bat      -> stops and removes the service, deletes program files.
                        Your database and quarantine stay in %ProgramData%Sentinel
                        (delete that folder manually if you want them gone)

Run without installing (e.g. for a quick look)
  run-gui.bat        -> launches the dashboard against a running service
  Sentinel.Service.exe --run          console-mode backend (needs admin shell for
                                      full privileges; still runs as normal user)
  Sentinel.Cli.exe status             talk to the running service

Typical sequence
  1. install.bat  (accept the UAC prompt)
  2. Start Menu -> Sentinel (or guiSentinel.Gui.exe)
  3. cliSentinel.Cli.exe scan C:someolder     or cliSentinel.Cli.exe scan --quick
  4. cliSentinel.Cli.exe findings                  review what was found

Data locations
  %ProgramData%Sentinelsentinel.db    SQLite store (bounded; ~2.6 MB steady state)
  %ProgramData%Sentinelules*.rule  user YARA-lite rules (auto-loaded)
  %ProgramData%SentinelQuarantine    quarantined files
  %ProgramData%Sentineldumps         memory dumps (auto-trimmed)

Security model (read-only, evidence-based)
  Scans never modify files, never inject, never auto-execute/delete. Quarantine
  moves files to the Quarantine folder and is always user-confirmed. AMSI is
  queried, not hooked. Kernel-driver-level coverage is out of scope by design.

Self-check after install
  cliSentinel.Cli.exe scan <path-to-an-EICAR-test-file>
  cliSentinel.Cli.exe findings   -> expect a Critical finding (conf 1.00) built
     from three independent signals: YARA-lite rule, AMSI provider, SHA-256 blacklist.

Build (from source)
  dotnet publish src/Sentinel.Service -c Release -r win-x64 --self-contained false -o dist/Sentinel/service
  dotnet publish src/Sentinel.Cli     -c Release -r win-x64 --self-contained false -o dist/Sentinel/cli
  dotnet publish src/Sentinel.Gui     -c Release -r win-x64 --self-contained false -o dist/Sentinel/gui
  dotnet publish src/Sentinel.Setup   -c Release -r win-x64 --self-contained true  -p:PublishSingleFile=true -o dist/Sentinel/tools
