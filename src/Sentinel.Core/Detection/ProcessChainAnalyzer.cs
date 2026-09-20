using System.Text.Json;
using Sentinel.Core.Models;
using Sentinel.Core.Realtime;

namespace Sentinel.Core.Detection;

/// <summary>Details attached to a process-created realtime event.</summary>
public sealed record ChainProcess
{
    public required uint Pid { get; init; }
    public required string Name { get; init; }
    public string? CommandLine { get; init; }
    public uint? ParentPid { get; init; }
    public string? ExecutablePath { get; init; }
    public DateTime TimestampUtc { get; init; }
}

/// <summary>
/// Behavioral process-chain analysis: watches process creation and builds a
/// bounded process tree to catch the "well hidden" script/command-line style
/// attacks that static file scanning never sees - Office → PowerShell cradles,
/// encoded launches, hidden windows, credential tooling. Reads only the event
/// stream; never touches the processes. Bounded ring: memory stays flat.
/// </summary>
public sealed class ProcessChainAnalyzer
{
    private const int RingCapacity = 1024;

    private static readonly HashSet<string> s_scriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "conhost.exe", "wmic.exe",
    };

    private static readonly HashSet<string> s_networkTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "curl.exe", "wget.exe", "ncat.exe", "nc.exe", "socat.exe", "telnet.exe",
        "bitsadmin.exe", "certutil.exe", "aria2c.exe", "bittransfer",
    };

    private static readonly HashSet<string> s_officeHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "java.exe", "javaw.exe", "wmiprvse.exe",
    };

    private readonly Dictionary<uint, ChainProcess> _byPid = new();
    private readonly List<uint> _order = [];

    /// <summary>
    /// Records a process-created event and returns evidence for any rule that
    /// fires. Idempotent per (pid, name) pair; the ring evicts oldest entries.
    /// </summary>
    public IReadOnlyList<Evidence> Observe(RealtimeEvent ev)
    {
        if (!string.Equals(ev.Kind, "process-created", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        ChainProcess proc = ParseEvent(ev);
        if (string.IsNullOrEmpty(proc.Name))
        {
            return [];
        }

        lock (_byPid)
        {
            _byPid[proc.Pid] = proc;
            _order.Add(proc.Pid);
            while (_order.Count > RingCapacity)
            {
                _byPid.Remove(_order[0]);
                _order.RemoveAt(0);
            }
        }

        var evidence = new List<Evidence>(2);

        string lowerName = proc.Name.ToLowerInvariant();
        string cmd = proc.CommandLine ?? "";

        // --- encoded PowerShell / shell launch ---
        bool psHost = lowerName is "powershell.exe" or "pwsh.exe";
        if (psHost && (cmd.Contains("-enc", StringComparison.OrdinalIgnoreCase)
                       || cmd.Contains("-encodedcommand", StringComparison.OrdinalIgnoreCase)))
        {
            evidence.Add(ChainEv(proc, "chain-encoded-launch", Severity.High, 0.9,
                $"PowerShell launched with an encoded command: {cmd[..Math.Min(160, cmd.Length)]}",
                "Execution, Defense Evasion"));
        }

        // --- download-and-execute cradle in command line ---
        bool cradle = cmd.Contains("downloadstring", StringComparison.OrdinalIgnoreCase)
            || cmd.Contains("downloadfile", StringComparison.OrdinalIgnoreCase)
            || (cmd.Contains("invoke-expression", StringComparison.OrdinalIgnoreCase) && cmd.Contains("http", StringComparison.OrdinalIgnoreCase))
            || (psHost && (cmd.Contains("iex", StringComparison.OrdinalIgnoreCase) && cmd.Contains("http", StringComparison.OrdinalIgnoreCase)))
            || cmd.Contains("certutil -urlcache", StringComparison.OrdinalIgnoreCase)
            || cmd.Contains("bitsadmin /transfer", StringComparison.OrdinalIgnoreCase)
            || cmd.Contains("mshta", StringComparison.OrdinalIgnoreCase) && cmd.Contains("http", StringComparison.OrdinalIgnoreCase);
        if (cradle)
        {
            evidence.Add(ChainEv(proc, "chain-download-cradle", Severity.High, 0.85,
                $"Process launched with a download-and-execute command line: {cmd[..Math.Min(160, cmd.Length)]}",
                "Execution, Command and Control"));
        }

        // --- hidden window launch ---
        if (cmd.Contains("-w hidden", StringComparison.OrdinalIgnoreCase)
            || cmd.Contains("-windowstyle hidden", StringComparison.OrdinalIgnoreCase)
            || cmd.Contains("//b ", StringComparison.OrdinalIgnoreCase))
        {
            evidence.Add(ChainEv(proc, "chain-hidden-launch", Severity.Medium, 0.75,
                $"Process launched in a hidden window: {cmd[..Math.Min(160, cmd.Length)]}",
                "Defense Evasion"));
        }

        // --- credential-access tooling ---
        if (cmd.Contains("mimikatz", StringComparison.OrdinalIgnoreCase)
            || cmd.Contains("sekurlsa", StringComparison.OrdinalIgnoreCase)
            || cmd.Contains("lsass", StringComparison.OrdinalIgnoreCase) && cmd.Contains("dump", StringComparison.OrdinalIgnoreCase)
            || cmd.Contains("ntds.dit", StringComparison.OrdinalIgnoreCase))
        {
            evidence.Add(ChainEv(proc, "chain-credential-tool", Severity.Critical, 0.9,
                "Process command line references credential-access tooling (mimikatz/sekurlsa/LSASS dump).",
                "Credential Access"));
        }

        // --- parent chain ---
        if (proc.ParentPid is uint ppid)
        {
            ChainProcess parent = Lookup(ppid);
            if (parent is not null)
            {
                string parLower = parent.Name.ToLowerInvariant();
                bool parentIsScriptHost = s_scriptHosts.Contains(parLower);
                bool childIsNetworkTool = s_networkTools.Contains(lowerName) || cmd.Contains("http", StringComparison.OrdinalIgnoreCase);
                bool childIsScriptHost = s_scriptHosts.Contains(lowerName);

                if (parentIsScriptHost && (childIsNetworkTool || childIsScriptHost))
                {
                    evidence.Add(ChainEv(proc, "chain-script-host-child", Severity.Medium, 0.7,
                        $"Script host '{parent.Name}' spawned '{proc.Name}' - classic chained execution pattern.",
                        "Execution"));
                }
                if (s_officeHosts.Contains(parLower) && (childIsScriptHost || childIsNetworkTool))
                {
                    evidence.Add(ChainEv(proc, "chain-office-macro-child", Severity.High, 0.8,
                        $"Office/document host '{parent.Name}' spawned '{proc.Name}' - macro->shell cradle pattern.",
                        "Execution, Initial Access"));
                }
                if (parentIsScriptHost && cmd.Contains("schtasks", StringComparison.OrdinalIgnoreCase))
                {
                    evidence.Add(ChainEv(proc, "chain-schtasks-persistence", Severity.Medium, 0.7,
                        $"Script host '{parent.Name}' created a scheduled task.",
                        "Persistence"));
                }
            }
        }

        return evidence;
    }

    public ChainProcess? Lookup(uint pid)
    {
        lock (_byPid)
        {
            return _byPid.TryGetValue(pid, out var p) ? p : null;
        }
    }

    private static ChainProcess ParseEvent(RealtimeEvent ev)
    {
        string? name = null, cmd = null, exe = null;
        uint? ppid = null;
        if (!string.IsNullOrEmpty(ev.DetailsJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(ev.DetailsJson);
                if (doc.RootElement.TryGetProperty("name", out var n)) name = n.GetString();
                if (doc.RootElement.TryGetProperty("commandLine", out var c)) cmd = c.GetString();
                if (doc.RootElement.TryGetProperty("parentPid", out var p)
                    && p.ValueKind == System.Text.Json.JsonValueKind.Number
                    && p.TryGetUInt32(out uint up))
                {
                    ppid = up;
                }
                if (doc.RootElement.TryGetProperty("executablePath", out var e)) exe = e.GetString();
            }
            catch (JsonException)
            {
            }
        }
        name ??= ev.Message is { } m && m.StartsWith("Process created:", StringComparison.OrdinalIgnoreCase)
            ? m["Process created:".Length..].Trim() : null;
        _ = uint.TryParse(ev.Entity, out uint pid);
        return new ChainProcess
        {
            Pid = pid,
            Name = name ?? "unknown",
            CommandLine = cmd,
            ParentPid = ppid,
            ExecutablePath = exe,
            TimestampUtc = ev.TimestampUtc,
        };
    }

    private static Evidence ChainEv(ChainProcess p, string evt, Severity severity, double confidence, string explanation, string tacticCommaList)
    {
        return new Evidence
        {
            Source = "process",
            Timestamp = DateTime.UtcNow,
            EntityType = "process",
            EntityId = p.Pid.ToString(),
            Event = evt,
            Severity = severity,
            Confidence = confidence,
            Explanation = explanation,
            DetailsJson = JsonSerializer.Serialize(new
            {
                name = p.Name,
                pid = p.Pid,
                parentPid = p.ParentPid,
                commandLine = p.CommandLine,
                executablePath = p.ExecutablePath,
                tactics = tacticCommaList,
            }),
        };
    }
}