using Sentinel.Core.Detection;
using Sentinel.Core.Models;

namespace Sentinel.Tests;

public class CorrelationEngineTests
{
    private static Evidence Ev(
        string entityId,
        string evt,
        Severity severity = Severity.Medium,
        double confidence = 0.6,
        string? explanation = null,
        DateTime? timestamp = null)
    {
        return new Evidence
        {
            Source = "file",
            Timestamp = timestamp ?? DateTime.UtcNow,
            EntityType = "file",
            EntityId = entityId,
            Event = evt,
            Severity = severity,
            Confidence = confidence,
            Explanation = explanation ?? $"{evt} on {entityId}",
        };
    }

    [Fact]
    public void SingleHighSeverityEvidence_ProducesFinding()
    {
        var engine = new CorrelationEngine();
        var e = Ev(@"C:\evil\evil.exe", "invalid-signature", Severity.High, 0.8);

        var findings = engine.Correlate([e]);

        var f = Assert.Single(findings);
        Assert.Equal(@"C:\evil\evil.exe", f.EntityKey);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(@"file|C:\evil\evil.exe|invalid-signature", Assert.Single(f.EvidenceIds));
        Assert.Equal(1, f.OccurrenceCount);
        Assert.True(f.RiskScore > 0);
        Assert.Contains("Immediate review", f.RecommendedAction);
    }

    [Fact]
    public void MultipleDistinctEvents_CorrelateIntoSingleFinding()
    {
        var engine = new CorrelationEngine();
        var now = DateTime.UtcNow;
        var e1 = Ev(@"C:\evil\evil.exe", "unsigned-executable", Severity.Low, 0.5, "Executable is unsigned.", now);
        var e2 = Ev(@"C:\evil\evil.exe", "high-entropy-pe", Severity.Medium, 0.55, "PE file has high entropy.", now);
        var e3 = Ev(@"C:\evil\evil.exe", "rwx-section", Severity.Medium, 0.6, "PE section is RWX.", now);

        var findings = engine.Correlate([e1, e2, e3]);

        var f = Assert.Single(findings);
        Assert.Equal(3, f.EvidenceIds.Count);
        Assert.Equal(3, f.OccurrenceCount);
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Contains("3 correlated signals", f.Title);
        Assert.Equal(3, f.Reasons.Count);
        // Confidence = min(1, 0.3 + (0.5+0.55+0.6)*0.35) = min(1, 0.8775) = 0.88
        Assert.Equal(0.88, f.Confidence);
    }

    [Fact]
    public void DuplicateEvents_Deduplicated()
    {
        var engine = new CorrelationEngine();
        var now = DateTime.UtcNow;
        var e1 = Ev(@"C:\evil\evil.exe", "unsigned-executable", Severity.Low, 0.5, "Executable 'evil.exe' is unsigned.", now);
        var e2 = Ev(@"C:\evil\evil.exe", "unsigned-executable", Severity.Low, 0.5, "Executable 'evil.exe' is unsigned.", now.AddSeconds(1));

        var findings = engine.Correlate([e1, e2]);

        var f = Assert.Single(findings);
        Assert.Single(f.EvidenceIds); // distinct events only
        Assert.Equal(2, f.OccurrenceCount); // but occurrence count reflects all
    }

    [Fact]
    public void RiskScore_CappedAt100()
    {
        var engine = new CorrelationEngine();
        var now = DateTime.UtcNow;
        var items = new List<Evidence>();
        for (int i = 0; i < 10; i++)
        {
            items.Add(Ev("entity-x", $"event-{i}", Severity.Critical, 1.0, "Critical signal.", now));
        }

        var findings = engine.Correlate(items);

        var f = Assert.Single(findings);
        Assert.Equal(100, f.RiskScore);
    }

    [Fact]
    public void OldEvidence_PrunedByWindow()
    {
        var engine = new CorrelationEngine(TimeSpan.FromSeconds(60));
        var old = Ev(@"C:\evil\evil.exe", "unsigned-executable", Severity.Low, 0.5,
            "Executable 'evil.exe' is unsigned.", DateTime.UtcNow.AddMinutes(-10));

        var findings = engine.Correlate([old]);

        Assert.Empty(findings);
    }

    [Fact]
    public void EvidenceAcrossCalls_AccumulatesWithinWindow()
    {
        var engine = new CorrelationEngine(TimeSpan.FromMinutes(5));
        var now = DateTime.UtcNow;
        var e1 = Ev(@"C:\evil\evil.exe", "unsigned-executable", Severity.Low, 0.5, "Unsigned.", now);
        var e2 = Ev(@"C:\evil\evil.exe", "rwx-section", Severity.Medium, 0.6, "RWX.", now.AddSeconds(10));

        var first = engine.Correlate([e1]);
        Assert.Single(first);

        var second = engine.Correlate([e2]);
        var f = Assert.Single(second);
        Assert.Equal(2, f.EvidenceIds.Count);
    }

    [Fact]
    public void TacticExtraction_FromExplanation()
    {
        var engine = new CorrelationEngine();
        var e = Ev(@"C:\evil\evil.exe", "startup-folder-item", Severity.Low, 0.5,
            "Item 'evil' in the startup folder — persistence mechanism.", DateTime.UtcNow);

        var findings = engine.Correlate([e]);

        var f = Assert.Single(findings);
        Assert.Contains("Persistence", f.MitreTactics);
    }

    [Fact]
    public void TacticExtraction_DefenseEvasion()
    {
        var engine = new CorrelationEngine();
        var e = Ev(@"C:\evil\evil.exe", "defender-disabled", Severity.High, 0.8,
            "Windows Defender real-time protection is disabled — defense evasion.", DateTime.UtcNow);

        var findings = engine.Correlate([e]);

        var f = Assert.Single(findings);
        Assert.Contains("Defense Evasion", f.MitreTactics);
    }

    [Fact]
    public void RecommendAction_BySeverity()
    {
        var now = DateTime.UtcNow;

        var high = new CorrelationEngine().Correlate([Ev("a", "invalid-signature", Severity.High, 0.8, "Bad sig.", now)]);
        Assert.Contains("Immediate review", high[0].RecommendedAction);

        var med = new CorrelationEngine().Correlate([Ev("b", "untrusted-signer", Severity.Medium, 0.6, "Untrusted.", now)]);
        Assert.Contains("Review the entity", med[0].RecommendedAction);

        var low = new CorrelationEngine().Correlate([Ev("c", "unsigned-executable", Severity.Low, 0.5, "Unsigned.", now)]);
        Assert.Contains("Informational", low[0].RecommendedAction);
    }

    [Fact]
    public void DifferentEntities_ProduceSeparateFindings()
    {
        var engine = new CorrelationEngine();
        var now = DateTime.UtcNow;
        var e1 = Ev(@"C:\a\a.exe", "unsigned-executable", Severity.Low, 0.5, "Unsigned.", now);
        var e2 = Ev(@"C:\b\b.exe", "unsigned-executable", Severity.Low, 0.5, "Unsigned.", now);

        var findings = engine.Correlate([e1, e2]);

        Assert.Equal(2, findings.Count);
        Assert.Equal(2, findings.Select(f => f.EntityKey).Distinct().Count());
    }

    // ---------- RiskAssessor ----------

    [Fact]
    public void RiskAssessor_Empty_ZeroScore()
    {
        Assert.Equal(0, RiskAssessor.ScoreOf([]));
    }

    [Fact]
    public void RiskAssessor_WeightsSeverity()
    {
        var now = DateTime.UtcNow;
        var low = Ev("x", "unsigned-executable", Severity.Low, 0.5, "Unsigned.", now);
        var high = Ev("x", "invalid-signature", Severity.High, 0.8, "Invalid.", now);

        double lowScore = RiskAssessor.ScoreOf([low]);
        double highScore = RiskAssessor.ScoreOf([high]);

        Assert.True(highScore > lowScore);
        Assert.InRange(lowScore, 0, 100);
        Assert.InRange(highScore, 0, 100);
    }

    [Fact]
    public void RiskAssessor_Assess_ReturnsReasons()
    {
        var now = DateTime.UtcNow;
        var e = Ev(@"C:\evil\evil.exe", "invalid-signature", Severity.High, 0.8, "Broken signature.", now);

        var assessment = RiskAssessor.Assess(@"C:\evil\evil.exe", [e]);

        Assert.Equal(@"C:\evil\evil.exe", assessment.EntityKey);
        Assert.Equal(Severity.High, assessment.Severity);
        Assert.Contains("Broken signature.", assessment.Reasons);
        Assert.Single(assessment.Evidence);
        Assert.InRange(assessment.Score, 0, 100);
    }

    [Fact]
    public void RiskAssessor_Empty_InfoSeverity()
    {
        var assessment = RiskAssessor.Assess("nothing", []);
        Assert.Equal(Severity.Info, assessment.Severity);
        Assert.Equal(0, assessment.Score);
    }
}