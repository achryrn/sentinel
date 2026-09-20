using System.Text.Json;
using Sentinel.Core.Ipc;
using Sentinel.Core.Models;

namespace Sentinel.Cli;

/// <summary>
/// Sentinel command-line client. Thin host: talks to the service over the
/// named pipe only; never opens the database directly.
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        using var client = new IpcClient();
        if (!client.Connect(3000))
        {
            Console.Error.WriteLine("Cannot connect to Sentinel service. Is it running?");
            return 1;
        }

        string cmd = args[0].ToLowerInvariant();
        try
        {
            return cmd switch
            {
                "status" => await StatusAsync(client),
                "scan" => await ScanAsync(client, args[1..]),
                "findings" => await FindingsAsync(client),
                "evidence" => await EvidenceAsync(client, args[1..]),
                "events" => await EventsAsync(client),
                "quarantine" => await QuarantineAsync(client, args[1..]),
                "exclusions" => await ExclusionsAsync(client, args[1..]),
                "processes" => await ProcessesAsync(client),
                "network" => await NetworkAsync(client),
                "persistence" => await PersistenceAsync(client),
                "memory" => await MemoryAsync(client, args[1..]),
                "audit" => await AuditAsync(client),
                "dump" => await DumpAsync(client, args[1..]),
                "blacklist" => await BlacklistAsync(client, args[1..]),
                "rules" => await RulesAsync(client, args[1..]),
                "help" or "--help" or "-h" => PrintUsage(),
                _ => UnknownCommand(cmd),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    private static int PrintUsage()
    {
        Console.WriteLine("""
            Sentinel CLI - endpoint security scanner client

            Usage: sentinel <command> [options]

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
              blacklist              List known-bad hashes
              blacklist --add <sha256> [label]   Add a known-bad hash
              blacklist --remove <sha256>        Remove a known-bad hash
              rules                  Show active rule count
              rules --reload         Reload user rules from disk
              help                   Show this help
            """);
        return 0;
    }

    private static int UnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"Unknown command: {cmd}");
        return 1;
    }

    private static async Task<int> StatusAsync(IpcClient client)
    {
        var resp = await client.RequestAsync(IpcCommand.Status);
        if (resp.Code != 0)
        {
            Console.Error.WriteLine(resp.Error);
            return 1;
        }
        var s = JsonSerializer.Deserialize<JsonElement>(resp.PayloadJson!, IpcProtocol.JsonOptions);
        Console.WriteLine($"Running:          {s.GetProperty("running").GetBoolean()}");
        Console.WriteLine($"Active scan:      {s.GetProperty("activeScanId").GetString() ?? "(none)"}");
        Console.WriteLine($"Queued scans:     {s.GetProperty("queuedScans").GetInt32()}");
        Console.WriteLine($"Realtime monitor: {s.GetProperty("realtimeRunning").GetBoolean()}");
        Console.WriteLine($"Store:            {s.GetProperty("storePath").GetString()}");
        return 0;
    }

    private static async Task<int> ScanAsync(IpcClient client, string[] args)
    {
        IpcCommand cmd;
        object? payload = null;
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: sentinel scan <file|folder> | --quick | --full");
            return 1;
        }
        if (args[0] == "--quick")
        {
            cmd = IpcCommand.ScanQuick;
        }
        else if (args[0] == "--full")
        {
            cmd = IpcCommand.ScanFull;
        }
        else
        {
            cmd = Directory.Exists(args[0]) ? IpcCommand.ScanFolder : IpcCommand.ScanFile;
            payload = new { Path = args[0] };
        }

        Console.WriteLine("Scan started... (progress events are streamed; Ctrl+C to cancel)");
        var resp = await client.RequestAsync(cmd, payload);
        if (resp.Code != 0)
        {
            Console.Error.WriteLine(resp.Error);
            return 1;
        }
        Console.WriteLine("Scan completed.");
        if (!string.IsNullOrEmpty(resp.PayloadJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(resp.PayloadJson);
                if (doc.RootElement.ValueKind == JsonValueKind.Object
                    && doc.RootElement.TryGetProperty("filesScanned", out var fs))
                {
                    string mode = doc.RootElement.TryGetProperty("mode", out var m) ? m.GetString() ?? "?" : "?";
                    long bytes = doc.RootElement.TryGetProperty("bytesScanned", out var bs) ? bs.GetInt64() : 0;
                    Console.WriteLine($"  {mode} scan: {fs.GetInt64():N0} files, {FormatBytes(bytes)}.");
                }
            }
            catch (JsonException)
            {
            }
        }
        return 0;
    }

    private static string FormatBytes(long b)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = b;
        int i = 0;
        while (v >= 1024 && i < units.Length - 1)
        {
            v /= 1024;
            i++;
        }
        return $"{v:0.#} {units[i]}";
    }

    private static async Task<int> FindingsAsync(IpcClient client)
    {
        var findings = await client.RequestAsync<List<StoredFinding>>(IpcCommand.GetFindings);
        if (findings is null || findings.Count == 0)
        {
            Console.WriteLine("No findings.");
            return 0;
        }
        foreach (var f in findings)
        {
            Console.WriteLine($"[{f.Severity,-8}] score={f.RiskScore,5:0.0} conf={f.Confidence:0.00} {f.Title}");
            Console.WriteLine($"    entity: {f.EntityKey}");
            Console.WriteLine($"    action: {f.RecommendedAction}");
            Console.WriteLine($"    tactics: {string.Join(", ", DeserializeList(f.MitreTacticsJson))}");
            Console.WriteLine();
        }
        return 0;
    }

    private static async Task<int> EvidenceAsync(IpcClient client, string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: sentinel evidence <entity-id>");
            return 1;
        }
        var evidence = await client.RequestAsync<List<Evidence>>(IpcCommand.GetEvidence, new { EntityId = args[0] });
        if (evidence is null || evidence.Count == 0)
        {
            Console.WriteLine("No evidence for this entity.");
            return 0;
        }
        foreach (var e in evidence)
        {
            Console.WriteLine($"[{e.Severity,-8}] {e.Event} (conf={e.Confidence:0.00})");
            Console.WriteLine($"    {e.Explanation}");
        }
        return 0;
    }

    private static async Task<int> EventsAsync(IpcClient client)
    {
        var events = await client.RequestAsync<List<SentinelEvent>>(IpcCommand.GetEvents);
        if (events is null || events.Count == 0)
        {
            Console.WriteLine("No events.");
            return 0;
        }
        foreach (var e in events)
        {
            Console.WriteLine($"{e.TimestampUtc:yyyy-MM-dd HH:mm:ss} [{e.Severity,-7}] [{e.Category}] {e.Message}");
        }
        return 0;
    }

    private static async Task<int> QuarantineAsync(IpcClient client, string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: sentinel quarantine <path> | --list | --restore <id> | --delete <id>");
            return 1;
        }
        if (args[0] == "--list")
        {
            var items = await client.RequestAsync<List<QuarantineItem>>(IpcCommand.GetQuarantine);
            if (items is null || items.Count == 0)
            {
                Console.WriteLine("Quarantine is empty.");
                return 0;
            }
            foreach (var q in items)
            {
                Console.WriteLine($"{q.Id}  [{q.Status}]  {q.OriginalPath}  ({q.Size} bytes, sha256={q.Sha256[..16]}...)");
            }
            return 0;
        }
        if (args[0] == "--restore" && args.Length > 1)
        {
            var resp = await client.RequestAsync(IpcCommand.RestoreQuarantine, new { Id = args[1] });
            Console.WriteLine(resp.Code == 0 ? "Restored." : $"Failed: {resp.Error}");
            return resp.Code == 0 ? 0 : 1;
        }
        if (args[0] == "--delete" && args.Length > 1)
        {
            var resp = await client.RequestAsync(IpcCommand.DeleteQuarantine, new { Id = args[1] });
            Console.WriteLine(resp.Code == 0 ? "Deleted." : $"Failed: {resp.Error}");
            return resp.Code == 0 ? 0 : 1;
        }
        var qresp = await client.RequestAsync(IpcCommand.QuarantineFile, new { Path = args[0], Reason = "CLI request" });
        if (qresp.Code != 0)
        {
            Console.Error.WriteLine(qresp.Error);
            return 1;
        }
        Console.WriteLine($"Quarantined: {args[0]}");
        return 0;
    }

    private static async Task<int> ExclusionsAsync(IpcClient client, string[] args)
    {
        if (args.Length > 0 && args[0] == "--add" && args.Length >= 3)
        {
            var type = args[1].ToLowerInvariant() switch
            {
                "path" => ExclusionType.Path,
                "hash" => ExclusionType.Hash,
                "signer" => ExclusionType.Signer,
                _ => ExclusionType.Path,
            };
            var resp = await client.RequestAsync(IpcCommand.AddExclusion, new
            {
                Id = Guid.NewGuid().ToString("n"),
                Type = type,
                Value = args[2],
                AddedBy = "cli",
                AddedAtUtc = DateTime.UtcNow,
            });
            Console.WriteLine(resp.Code == 0 ? "Exclusion added." : $"Failed: {resp.Error}");
            return resp.Code == 0 ? 0 : 1;
        }
        if (args.Length > 0 && args[0] == "--remove" && args.Length > 1)
        {
            var resp = await client.RequestAsync(IpcCommand.RemoveExclusion, new { Id = args[1] });
            Console.WriteLine(resp.Code == 0 ? "Exclusion removed." : $"Failed: {resp.Error}");
            return resp.Code == 0 ? 0 : 1;
        }
        var exclusions = await client.RequestAsync<List<Exclusion>>(IpcCommand.GetExclusions);
        if (exclusions is null || exclusions.Count == 0)
        {
            Console.WriteLine("No exclusions.");
            return 0;
        }
        foreach (var e in exclusions)
        {
            Console.WriteLine($"{e.Id}  [{e.Type}]  {e.Value}  (by {e.AddedBy})");
        }
        return 0;
    }

    private static async Task<int> ProcessesAsync(IpcClient client)
    {
        var resp = await client.RequestAsync(IpcCommand.ScanProcess);
        if (resp.Code != 0)
        {
            Console.Error.WriteLine(resp.Error);
            return 1;
        }
        var procs = JsonSerializer.Deserialize<List<ProcessInfo>>(resp.PayloadJson!, IpcProtocol.JsonOptions);
        if (procs is null)
        {
            return 0;
        }
        foreach (var p in procs.OrderBy(p => p.Pid))
        {
            Console.WriteLine($"{p.Pid,6}  {p.Name,-32} {p.UserName ?? "?"}  elevated={p.IsElevated}  sig={p.SignatureStatus}");
        }
        return 0;
    }

    private static async Task<int> NetworkAsync(IpcClient client)
    {
        var resp = await client.RequestAsync(IpcCommand.ScanNetwork);
        if (resp.Code != 0)
        {
            Console.Error.WriteLine(resp.Error);
            return 1;
        }
        var snap = JsonSerializer.Deserialize<NetworkSnapshot>(resp.PayloadJson!, IpcProtocol.JsonOptions);
        if (snap is null)
        {
            return 0;
        }
        foreach (var c in snap.Connections.Where(c => !c.IsLoopback).OrderBy(c => c.ProcessName))
        {
            Console.WriteLine($"{c.Protocol,-4} {c.LocalAddress}:{c.LocalPort} -> {c.RemoteAddress}:{c.RemotePort}  {c.State ?? ""}  {c.ProcessName ?? "?"}");
        }
        return 0;
    }

    private static async Task<int> PersistenceAsync(IpcClient client)
    {
        var resp = await client.RequestAsync(IpcCommand.ScanPersistence);
        if (resp.Code != 0)
        {
            Console.Error.WriteLine(resp.Error);
            return 1;
        }
        var result = JsonSerializer.Deserialize<PersistenceScanResult>(resp.PayloadJson!, IpcProtocol.JsonOptions);
        if (result is null)
        {
            return 0;
        }
        foreach (var e in result.Entries)
        {
            Console.WriteLine($"[{e.Category,-12}] {e.Name,-40} {e.Command ?? ""}");
        }
        return 0;
    }

    private static async Task<int> MemoryAsync(IpcClient client, string[] args)
    {
        object? payload = null;
        if (args.Length > 0 && uint.TryParse(args[0], out uint pid))
        {
            payload = new { Pid = pid };
        }
        var resp = await client.RequestAsync(IpcCommand.ScanMemory, payload);
        if (resp.Code != 0)
        {
            Console.Error.WriteLine(resp.Error);
            return 1;
        }
        var results = JsonSerializer.Deserialize<List<MemoryAnalysisResult>>(resp.PayloadJson!, IpcProtocol.JsonOptions);
        if (results is null)
        {
            return 0;
        }
        foreach (var m in results)
        {
            Console.WriteLine($"{m.Pid,6} {m.ProcessName,-32} regions={m.RegionCount} suspicious={m.SuspiciousRegions.Count} threads={m.SuspiciousThreads.Count} denied={m.AccessDenied}");
        }
        return 0;
    }

    private static async Task<int> AuditAsync(IpcClient client)
    {
        var resp = await client.RequestAsync(IpcCommand.AuditSystem);
        if (resp.Code != 0)
        {
            Console.Error.WriteLine(resp.Error);
            return 1;
        }
        var result = JsonSerializer.Deserialize<SystemAuditResult>(resp.PayloadJson!, IpcProtocol.JsonOptions);
        if (result is null)
        {
            return 0;
        }
        Console.WriteLine($"OS:        {result.OsVersion} (build {result.OsBuild})");
        Console.WriteLine($"Defender:  {result.DefenderStatus ?? "unknown"} (enabled={result.DefenderEnabled})");
        Console.WriteLine($"Firewall:  enabled={result.FirewallEnabled} rules={result.FirewallRuleCount}");
        Console.WriteLine($"UAC:       enabled={result.UacEnabled} level={result.UacLevel}");
        Console.WriteLine($"Admins:    {result.LocalAdminCount} ({string.Join(", ", result.LocalAdmins)})");
        Console.WriteLine($"Guest:     {result.GuestEnabled}");
        Console.WriteLine($"RDP:       {result.RdpEnabled} exposed={result.RdpExposedToPublic}");
        Console.WriteLine($"SMB:       {result.SmbEnabled} exposed={result.SmbExposedToPublic}");
        Console.WriteLine($"Updates:   last={result.LastUpdateInstalledUtc:yyyy-MM-dd} ({result.DaysSinceLastUpdate} days ago)");
        foreach (var f in result.Findings)
        {
            Console.WriteLine($"  ! {f}");
        }
        return 0;
    }

    private static async Task<int> DumpAsync(IpcClient client, string[] args)
    {
        if (args.Length < 1 || !uint.TryParse(args[0], out uint pid))
        {
            Console.Error.WriteLine("Usage: sentinel dump <pid>");
            return 1;
        }
        var resp = await client.RequestAsync(IpcCommand.DumpProcessMemory, new { Pid = pid, FullMemory = false });
        if (resp.Code != 0)
        {
            Console.Error.WriteLine(resp.Error);
            return 1;
        }
        var result = JsonSerializer.Deserialize<MemoryDumpResult>(resp.PayloadJson!, IpcProtocol.JsonOptions);
        if (result is null)
        {
            return 0;
        }
        if (!result.Success)
        {
            Console.Error.WriteLine($"Dump failed: {result.Error}");
            return 1;
        }
        Console.WriteLine($"Dump written: {result.OutputPath} ({result.BytesWritten} bytes)");
        return 0;
    }

    private static async Task<int> BlacklistAsync(IpcClient client, string[] args)
    {
        if (args.Length > 0 && args[0] == "--add" && args.Length >= 2)
        {
            var sha = args[1].ToLowerInvariant();
            var label = args.Length > 2 ? string.Join(" ", args[2..]) : "user-added";
            var resp = await client.RequestAsync(IpcCommand.AddBlacklist, new { Sha256 = sha, Label = label, Verdict = "malware" });
            Console.WriteLine(resp.Code == 0 ? "Blacklist entry added." : $"Failed: {resp.Error}");
            return resp.Code == 0 ? 0 : 1;
        }
        if (args.Length > 0 && args[0] == "--remove" && args.Length > 1)
        {
            var resp = await client.RequestAsync(IpcCommand.RemoveBlacklist, new { Sha256 = args[1].ToLowerInvariant() });
            Console.WriteLine(resp.Code == 0 ? "Blacklist entry removed." : $"Failed: {resp.Error}");
            return resp.Code == 0 ? 0 : 1;
        }
        var entries = await client.RequestAsync<List<BlacklistEntry>>(IpcCommand.GetBlacklist);
        if (entries is null || entries.Count == 0)
        {
            Console.WriteLine("Blacklist is empty.");
            return 0;
        }
        foreach (var e in entries)
        {
            Console.WriteLine($"{e.Sha256}  {e.Verdict,-9}  {e.Label}  (by {e.AddedBy ?? "?"})");
        }
        return 0;
    }

    private static async Task<int> RulesAsync(IpcClient client, string[] args)
    {
        if (args.Length > 0 && args[0] == "--reload")
        {
            var resp = await client.RequestAsync(IpcCommand.ReloadRules);
            Console.WriteLine(resp.Code == 0 ? $"Rules reloaded ({resp.PayloadJson})." : $"Failed: {resp.Error}");
            return resp.Code == 0 ? 0 : 1;
        }
        var status = await client.RequestAsync(IpcCommand.Status);
        if (status.Code != 0)
        {
            Console.Error.WriteLine(status.Error);
            return 1;
        }
        var s = JsonSerializer.Deserialize<JsonElement>(status.PayloadJson!, IpcProtocol.JsonOptions);
        var rules = s.TryGetProperty("rulesCount", out var rc) ? rc.GetInt32() : 0;
        var amsi = s.TryGetProperty("amsiAvailable", out var aa) ? aa.GetBoolean() : false;
        var blacklist = s.TryGetProperty("blacklistCount", out var bc) ? bc.GetInt32() : 0;
        var privs = s.TryGetProperty("enabledPrivileges", out var ep) ? string.Join(", ", ep.EnumerateArray().Select(e => e.GetString())) : "(unknown)";
        Console.WriteLine($"Rules:            {rules}");
        Console.WriteLine($"AMSI:             {(amsi ? "available" : "unavailable")}");
        Console.WriteLine($"Blacklist:        {blacklist} entries");
        Console.WriteLine($"Privileges:       {privs}");
        return 0;
    }

    private static List<string> DeserializeList(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json, IpcProtocol.JsonOptions) ?? [];
        }
        catch
        {
            return [];
        }
    }
}