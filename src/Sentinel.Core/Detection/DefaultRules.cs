namespace Sentinel.Core.Detection;

/// <summary>
/// Embedded default rule pack (YARA-lite). Users can drop additional
/// <c>*.rule</c> files into <c>%ProgramData%\Sentinel\rules</c> - they are
/// merged in at service start (see <see cref="DetectionServices"/>).
/// </summary>
public static class DefaultRules
{
    public const string Content = """
        // ===== EICAR anti-malware test file (safe, canonical) =====
        rule eicar_test_file {
          meta:
            description = "EICAR anti-malware test file - used to verify detection works"
            severity = "critical"
            confidence = 1.0
            tactics = "Impact"
          strings:
            $a = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
          condition:
            $a
        }

        // ===== PowerShell download-and-execute (fileless dropper core) =====
        rule powershell_download_execute {
          meta:
            description = "PowerShell download cradle - IEX/DownloadString pattern"
            severity = "high"
            confidence = 0.9
            tactics = "Execution, Command and Control"
          strings:
            $a = "invoke-expression" ascii nocase
            $b = "downloadstring" ascii nocase
            $c = "downloadfile" ascii nocase
            $d = "frombase64string" ascii nocase
          condition:
            ($a and ($b or $c or $d)) or ($b and 2 of ($a, $c, $d))
        }

        rule powershell_encoded_command {
          meta:
            description = "Encoded PowerShell launch (-enc / -encodedcommand)"
            severity = "high"
            confidence = 0.85
            tactics = "Execution, Defense Evasion"
          strings:
            $a = "encodedcommand" ascii nocase
            $b = "-enc" ascii
          condition:
            $a or $b
        }

        // ===== credential access =====
        rule mimikatz_indicators {
          meta:
            description = "Mimikatz / credential-dumping indicators"
            severity = "critical"
            confidence = 0.9
            tactics = "Credential Access"
          strings:
            $a = "sekurlsa" ascii nocase
            $b = "mimikatz" ascii nocase
            $c = "lsass" ascii nocase
          condition:
            $a or $b or ($c and 1 of ($a, $b))
        }

        // ===== VBS / JScript dropper =====
        rule vbs_shell_dropper {
          meta:
            description = "VBScript creates a shell object and runs something"
            severity = "high"
            confidence = 0.85
            tactics = "Execution"
          strings:
            $a = "wscript.shell" ascii nocase
            $b = "createobject(" ascii nocase
            $c = ".run " ascii nocase
            $d = "scripting.filesystemobject" ascii nocase
          condition:
            $b and ($a or $d) and $c
        }

        rule js_activex_downloader {
          meta:
            description = "JScript ActiveX downloader pattern"
            severity = "high"
            confidence = 0.8
            tactics = "Execution, Command and Control"
          strings:
            $a = "activexobject" ascii nocase
            $b = "msxml2.xmlhttp" ascii nocase
            $c = "wscript.shell" ascii nocase
            $d = "xmlhttp" ascii nocase
          condition:
            $a and ($b or $d) and $c
        }

        // ===== common C2 beacons / payload markers =====
        rule cobalt_beacon_indicators {
          meta:
            description = "Cobalt Strike beacon string markers"
            severity = "high"
            confidence = 0.75
            tactics = "Command and Control"
          strings:
            $a = "beacon_" ascii nocase
            $b = "windows/beacon" ascii nocase
            $c = "aggressive_load" ascii nocase
          condition:
            2 of them
        }

        rule generic_http_beacon {
          meta:
            description = "Repeated generic beacon URL patterns"
            severity = "medium"
            confidence = 0.55
            tactics = "Command and Control"
          strings:
            $a = "/get.php" nocase
            $b = "/config.php" nocase
            $c = "/submit.php" nocase
          condition:
            2 of them
        }

        // ===== batch / cmd persistence =====
        rule batch_persistence_install {
          meta:
            description = "Batch file installing persistence (startup / schtasks)"
            severity = "medium"
            confidence = 0.7
            tactics = "Persistence"
          strings:
            $a = "startup" ascii nocase
            $b = "schtasks" ascii nocase
            $c = "reg add" ascii nocase
            $d = "currentversion\run" ascii nocase
            $e = "copy " ascii nocase
          condition:
            ($b or $d) and ($a or $c or $e)
        }

        // ===== obfuscated helper =====
        rule char_code_obfuscation {
          meta:
            description = "char-code assembly used to hide strings"
            severity = "medium"
            confidence = 0.6
            tactics = "Defense Evasion"
          strings:
            $a = "[char]" ascii nocase
            $b = "chr(" ascii nocase
            $c = "chrw(" ascii nocase
          condition:
            2 of them
        }
        """;
}
