using System.Text;
using Sentinel.Core.Models;
using Sentinel.Core.Realtime;
using Sentinel.Core.Storage;

namespace Sentinel.Core.Detection;

/// <summary>
/// Facade over the content-based detection engines the service feeds from both
/// scan results and realtime events:
///
///   * YARA-lite rule engine (embedded pack + user rules in %ProgramData%\Sentinel\rules\*.rule)
///   * script heuristics (PowerShell / VBS / JScript / batch obfuscation & cradle patterns)
///   * AMSI scan of script content (hands content to Defender & other AMSI providers)
///   * known-bad SHA-256 blacklist (seeded with EICAR; user-extensible)
///   * process-chain analysis (script-host spawn chains, encoded launches)
///
/// Everything is read-only: content is only read and scanned, never modified or
/// executed. All results are Evidence items flowing through the normal pipeline.
/// </summary>
public sealed class DetectionServices : IDisposable
{
    private const int MaxAnalyzeBytes = 4 * 1024 * 1024;

    private readonly SentinelStore _store;
    private readonly AmsiScanner _amsi = new();
    private readonly ProcessChainAnalyzer _chains = new();
    private readonly List<Rule> _rules;

    public DetectionServices(SentinelStore store)
    {
        _store = store;
        _rules = new List<Rule>(RuleEngine.Parse(DefaultRules.Content));
        LoadUserRules();
        SeedBlacklist();
    }

    public IReadOnlyList<Rule> Rules => _rules;
    public AmsiScanner Amsi => _amsi;
    public ProcessChainAnalyzer Chains => _chains;
    public bool AmsiAvailable => _amsi.IsAvailable;

    /// <summary>User-supplied rule directory; *.rule files are merged into the engine.</summary>
    public string RulesDir { get; } = Path.Combine(Path.GetDirectoryName(SentinelStore.DefaultDbPath)!, "rules");

    /// <summary>Reloads user rules from disk (service start + on demand).</summary>
    public int ReloadUserRules()
    {
        _rules.Clear();
        _rules.AddRange(RuleEngine.Parse(DefaultRules.Content));
        LoadUserRules();
        return _rules.Count;
    }

    private void LoadUserRules()
    {
        try
        {
            if (!Directory.Exists(RulesDir))
            {
                return;
            }
            foreach (string file in Directory.EnumerateFiles(RulesDir, "*.rule", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    var parsed = RuleEngine.Parse(File.ReadAllText(file));
                    _rules.AddRange(parsed);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    /// <summary>Seeds the known-bad hash blacklist with the canonical EICAR test hash.</summary>
    public void SeedBlacklist()
    {
        const string eicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        if (_store.LookupBlacklist(eicarSha256) is null)
        {
            _store.UpsertBlacklist(eicarSha256, "malware", "EICAR anti-malware test file", "test", "system");
        }
    }

    /// <summary>
    /// Content analysis of one file: AMSI + rule engine + script heuristics.
    /// Reads the file at most once. Only script/executable-content-like files
    /// are analyzed (bounded to <see cref="MaxAnalyzeBytes"/>).
    /// </summary>
    public IReadOnlyList<Evidence> AnalyzeFileContent(string path)
    {
        var evidence = new List<Evidence>(2);
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length <= 0 || fi.Length > MaxAnalyzeBytes)
            {
                return evidence;
            }
            bool script = ScriptAnalyzer.IsScriptFile(path);
            string ext = Path.GetExtension(Path.GetFileName(path)).ToLowerInvariant();
            // Executable-content formats and small text files are analyzed too:
            // EICAR test files and disguised script payloads often carry a
            // benign-looking extension (.txt/.com/.scr) while containing a
            // malicious body.
            bool smallText = ext is ".txt" or ".com" or ".scr" or "" && fi.Length <= 256 * 1024;
            bool smallNoExt = string.IsNullOrEmpty(ext) && fi.Length <= 256 * 1024;
            if (!script && !smallNoExt && !smallText)
            {
                return evidence;
            }

            byte[] bytes = new byte[(int)fi.Length];
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                int read = 0;
                while (read < bytes.Length)
                {
                    int n = fs.Read(bytes, read, bytes.Length - read);
                    if (n == 0)
                    {
                        break;
                    }
                    read += n;
                }
                if (read < bytes.Length)
                {
                    bytes = bytes.AsSpan(0, read).ToArray();
                }
            }

            // 1) AMSI - every provider on the box gets a vote.
            if (_amsi.Scan(bytes, Path.GetFileName(path)) == AmsiVerdict.Detected)
            {
                evidence.Add(Ev(path, "amsi-detected", Severity.Critical, 0.95,
                    "AMSI provider flagged this content as malicious.", "Execution, Defense Evasion"));
            }

            // 2) Rule engine - signature matches on content.
            foreach (var match in RuleEngine.Match(bytes, _rules))
            {
                var r = match.Rule;
                string matched = string.Join(", ", match.StringCounts.Keys);
                evidence.Add(Ev(path, "rule-" + r.Name, r.Severity, r.Confidence,
                    $"Rule '{r.Name}' matched ({matched}): {r.Description ?? "content signature"}", string.Join(", ", r.Tactics)));
            }

            // 3) Script heuristics.
            if (script)
            {
                string text = Decode(bytes);
                evidence.AddRange(ScriptAnalyzer.AnalyzeText(path, text));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
        }
        return evidence;
    }

    /// <summary>Feeds a realtime process-created event into the chain analyzer.</summary>
    public IReadOnlyList<Evidence> ObserveProcessEvent(RealtimeEvent ev) => _chains.Observe(ev);

    private static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        }
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        }
        return Encoding.Latin1.GetString(bytes);
    }

    private static Evidence Ev(string entity, string evt, Severity severity, double confidence, string explanation, string tacticCommaList)
    {
        return new Evidence
        {
            Source = "detection",
            Timestamp = DateTime.UtcNow,
            EntityType = "file",
            EntityId = entity,
            Event = evt,
            Severity = severity,
            Confidence = confidence,
            Explanation = explanation,
            DetailsJson = "{\"tactics\":\"" + tacticCommaList + "\"}",
        };
    }

    public void Dispose() => _amsi.Dispose();
}
