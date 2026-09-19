using System.Security.Cryptography;
using System.Text;
using Sentinel.Core.Models;

namespace Sentinel.Core.Detection;

/// <summary>
/// Correlates individual evidence items into findings: groups evidence by entity
/// within a time window, links related evidence (e.g. same process across memory +
/// network + persistence), and produces composite, explainable findings with
/// MITRE ATT&amp;CK tags.
///
/// Finding identity is STABLE: a finding is keyed on its entity (not on a per-run
/// GUID), so repeated scans / audit cycles update the same row (occurrence count,
/// last-seen) instead of duplicating rows — the pre-hardening build inserted a new
/// GUID row per entity on every correlation pass, which is what ballooned the
/// store to tens of GB. Findings are additionally gated so weak single signals
/// stay as evidence and only meaningful combinations become findings.
/// </summary>
public sealed class CorrelationEngine
{
    /// <summary>Default correlation time window.</summary>
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromSeconds(60);

    private readonly TimeSpan _window;
    private readonly object _lock = new();
    private readonly List<Evidence> _recent = [];
    private readonly Dictionary<string, List<Evidence>> _byEntity = new(StringComparer.Ordinal);

    public CorrelationEngine(TimeSpan? window = null)
    {
        _window = window ?? DefaultWindow;
    }

    /// <summary>
    /// Correlates a batch of evidence. Prunes evidence older than the window,
    /// groups by entity key, and emits findings for entities with multiple
    /// distinct signals (or one high-severity signal).
    /// </summary>
    public IReadOnlyList<Finding> Correlate(IEnumerable<Evidence> evidence)
    {
        var findings = new List<Finding>();
        var cutoff = DateTime.UtcNow - _window;

        lock (_lock)
        {
            foreach (var e in evidence)
            {
                _recent.Add(e);
            }
            _recent.RemoveAll(e => e.Timestamp < cutoff);

            _byEntity.Clear();
            foreach (var e in _recent)
            {
                if (!_byEntity.TryGetValue(e.EntityId, out var list))
                {
                    list = [];
                    _byEntity[e.EntityId] = list;
                }
                list.Add(e);
            }

            foreach (var (entityId, items) in _byEntity)
            {
                if (items.Count == 0)
                {
                    continue;
                }
                var finding = BuildFinding(entityId, items);
                if (finding is not null)
                {
                    findings.Add(finding);
                }
            }
        }

        return findings;
    }

    private Finding? BuildFinding(string entityId, List<Evidence> items)
    {
        var distinct = items.GroupBy(e => e.Event).Select(g => g.First()).ToList();
        if (distinct.Count == 0)
        {
            return null;
        }

        // Gate: only promote to a finding when the signal is meaningful.
        // A single weak signal (unsigned exe, MOTW, no-ASLR, ...) stays as
        // evidence — it is not a verdict and would only add review noise.
        var max = distinct.Max(e => e.Severity);
        double maxConf = distinct.Max(e => e.Confidence);
        bool meaningful = distinct.Count >= 2 || max >= Severity.Medium || maxConf >= 0.75;
        if (!meaningful)
        {
            return null;
        }

        var confidence = Math.Min(1.0, 0.3 + distinct.Sum(e => e.Confidence) * 0.35);
        var tactics = distinct.SelectMany(e => ExtractTactics(e)).Distinct().ToList();

        string title = distinct.Count == 1
            ? $"{max} — {distinct[0].Explanation}"
            : $"{max} — {distinct.Count} correlated signals on {entityId}";

        string action = RecommendAction(max, distinct);

        return new Finding
        {
            Id = StableEntityId(entityId),
            EvidenceIds = distinct.Select(e => e.Key).ToList(),
            EntityKey = entityId,
            Title = title,
            Severity = max,
            Confidence = Math.Round(confidence, 2),
            Reasons = distinct.Select(e => e.Explanation).ToList(),
            MitreTactics = tactics,
            RecommendedAction = action,
            FirstSeenUtc = items.Min(e => e.Timestamp),
            OccurrenceCount = items.Count,
            RiskScore = RiskAssessor.ScoreOf(distinct),
        };
    }

    /// <summary>
    /// Deterministic finding id for an entity: SHA-256 of the entity key, hex,
    /// prefixed. The same entity always maps to the same id, so correlated
    /// findings converge on one store row across scans instead of duplicating.
    /// </summary>
    public static string StableEntityId(string entityKey)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("sentinel-finding:" + entityKey));
        return "fnd-" + Convert.ToHexStringLower(hash)[..32];
    }

    private static string RecommendAction(Severity max, List<Evidence> items)
    {
        if (max >= Severity.High)
        {
            return "Immediate review: quarantine the file or terminate the process after user confirmation.";
        }
        if (max == Severity.Medium)
        {
            return "Review the entity in the UI and decide whether to allow it (add exclusion if trusted).";
        }
        return "Informational — monitor; no action required.";
    }

    private static readonly HashSet<string> s_tacticKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "persistence", "privilege", "defense", "execution", "credential", "discovery",
        "lateral", "collection", "command", "control", "exfil", "impact", "initial",
    };

    private static List<string> ExtractTactics(Evidence e)
    {
        var found = new List<string>();
        foreach (var kw in s_tacticKeywords)
        {
            if (e.Explanation.Contains(kw, StringComparison.OrdinalIgnoreCase)
                || e.Event.Contains(kw, StringComparison.OrdinalIgnoreCase))
            {
                found.Add(MapTactic(kw));
            }
        }
        return found.Distinct().ToList();
    }

    private static string MapTactic(string kw) => kw switch
    {
        "persistence" => "Persistence",
        "privilege" => "Privilege Escalation",
        "defense" => "Defense Evasion",
        "execution" => "Execution",
        "credential" => "Credential Access",
        "discovery" => "Discovery",
        "lateral" => "Lateral Movement",
        "collection" => "Collection",
        "command" => "Command and Control",
        "control" => "Command and Control",
        "exfil" => "Exfiltration",
        "impact" => "Impact",
        "initial" => "Initial Access",
        _ => "Execution",
    };
}

/// <summary>
/// Weighted, explainable risk scoring per entity. Each reason contributes
/// (severity × confidence × weight) with explicit capping; a finding is never
/// a bare number — the full reason list is always presented.
/// </summary>
public static class RiskAssessor
{
    public static double ScoreOf(IEnumerable<Evidence> items)
    {
        double total = 0;
        foreach (var e in items)
        {
            double w = WeightOf(e.Event);
            total += SeverityWeight(e.Severity) * e.Confidence * w;
        }
        return Math.Round(Math.Min(100, total * 10), 1);
    }

    public static RiskAssessment Assess(string entityKey, IEnumerable<Evidence> items)
    {
        var list = items.ToList();
        double score = ScoreOf(list);
        Severity sev = list.Count == 0 ? Severity.Info : list.Max(e => e.Severity);
        return new RiskAssessment
        {
            EntityKey = entityKey,
            Score = score,
            Severity = sev,
            Reasons = list.Select(e => e.Explanation).ToList(),
            Evidence = list,
        };
    }

    /// <summary>Severity weight: Info=1, Low=2, Medium=3, High=4, Critical=5.</summary>
    private static double SeverityWeight(Severity s) => s switch
    {
        Severity.Info => 1,
        Severity.Low => 2,
        Severity.Medium => 3,
        Severity.High => 4,
        Severity.Critical => 5,
        _ => 1,
    };

    /// <summary>Per-rule weights; defaults to 1.</summary>
    private static double WeightOf(string evt) => evt switch
    {
        "rwx-private-region" or "invalid-signature" or "defender-disabled" or "firewall-disabled" => 2.0,
        "high-entropy-private-exec" or "thread-outside-module" or "persistence-missing-target" => 1.5,
        _ => 1.0,
    };
}