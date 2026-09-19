using System.Text;
using Sentinel.Core.Hashing;
using Sentinel.Core.Models;

namespace Sentinel.Core.Detection;

/// <summary>
/// Static analysis of script content (PowerShell, batch, VBS, JScript, HTA,
/// WSF...). Script-based infections are the most common "well hidden" malware
/// of the last decade — fileless downloaders, encoded PowerShell, macro/script
/// droppers. This analyzer flags the classic precursor patterns with high
/// precision and explainable evidence.
/// </summary>
public static class ScriptAnalyzer
{
    /// <summary>Max bytes of script content analyzed (4 MiB).</summary>
    public const int MaxAnalyzeBytes = 4 * 1024 * 1024;

    private static readonly HashSet<string> s_scriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".ps1xml", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".hta", ".wsf", ".wsh", ".msi", ".mht", ".sct", ".vba", ".bas",
    };

    private static readonly string[] s_downloadCradleTokens =
    [
        "downloadstring", "downloadfile", "invoke-webrequest", "invoke-restmethod", "iwr",
        "webclient", "bitsadmin /transfer", "certutil -urlcache", "certutil -decode",
        "start-bitstransfer", "invoke-expression", "iex(", "iex ", "frombase64string",
        "curl ", "wget ", "http://", "https://",
    ];

    private static readonly string[] s_executeTokens =
    [
        "rundll32", "regsvr32", "mshta", "wscript", "cscript", "start-process",
        "wmic process call create", "schtasks /create", "powershell -enc",
        "-encodedcommand", " -enc ", " -e ", "set-content", "out-file", "add-mpnotification",
    ];

    public static bool IsScriptFile(string path)
    {
        string ext = Path.GetExtension(path);
        return s_scriptExtensions.Contains(ext);
    }

    /// <summary>
    /// Reads up to <see cref="MaxAnalyzeBytes"/> bytes of script text and returns
    /// evidence. Encoding is detected: UTF-16 BOM preferred, else Latin-1 (so
    /// batch files with OEM codepage bytes still match ASCII tokens).
    /// </summary>
    public static IReadOnlyList<Evidence> Analyze(string path, CancellationToken ct = default)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length <= 0 || fi.Length > MaxAnalyzeBytes)
            {
                return [];
            }
            byte[] bytes = new byte[(int)fi.Length];
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int read = 0;
            while (read < bytes.Length)
            {
                ct.ThrowIfCancellationRequested();
                int n = fs.Read(bytes, read, bytes.Length - read);
                if (n == 0)
                {
                    break;
                }
                read += n;
            }
            string text = Decode(bytes.AsSpan(0, read));
            return AnalyzeText(path, text);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            return [];
        }
    }

    /// <summary>Analyzes already-decoded script text (unit-testable).</summary>
    public static IReadOnlyList<Evidence> AnalyzeText(string path, string text)
    {
        var evidence = new List<Evidence>();
        if (string.IsNullOrEmpty(text))
        {
            return evidence;
        }

        string lower = text.ToLowerInvariant();

        // --- encoded / encoded-command launch ---
        if (RegexSafe(@"-enc(odedcommand)??\s", lower) || lower.Contains("-encodedcommand")
            || lower.Contains(" -enc ") || lower.Contains(" -e ") && HasLongToken(text))
        {
            evidence.Add(Ev(path, "script-encoded-command", Severity.High, 0.85,
                "Script contains an encoded-command / '-enc' launch pattern — classic fileless execution.", tactics: "Execution, Defense Evasion"));
        }

        // --- download cradle ---
        int cradle = CountTokens(lower, s_downloadCradleTokens);
        if (cradle >= 2 || lower.Contains("downloadstring") || lower.Contains("downloadfile")
            || (lower.Contains("invoke-expression") && lower.Contains("http"))
            || lower.Contains("bitsadmin") || lower.Contains("certutil -urlcache"))
        {
            evidence.Add(Ev(path, "script-download-cradle", Severity.High, 0.8,
                $"Script contains a download-and-execute cradle ({cradle} indicators) — typical malware delivery.", tactics: "Execution, Command and Control"));
        }

        // --- execute/launch chains ---
        int exec = CountTokens(lower, s_executeTokens);
        if (exec >= 2)
        {
            evidence.Add(Ev(path, "script-execute-chain", Severity.Medium, 0.65,
                $"Script chains {exec} process-launch techniques (rundll32/regsvr32/mshta/wmic/...).", tactics: "Execution"));
        }

        // --- obfuscation signals ---
        int obf = 0;
        int charCodes = CountOccurrences(lower, "chr(") + CountOccurrences(lower, "char(") + CountOccurrences(lower, "[char]");
        if (charCodes >= 4) obf++;
        if (charCodes >= 10) obf++; // heavy char-code assembly is itself suspicious
        if (lower.Contains("frombase64string") || HasBigBase64(lower)) obf++;
        if (lower.Contains("split") && lower.Contains("join") && lower.Contains("'")) obf++;
        int spacedSigns = CountOccurrences(lower, " + '") + CountOccurrences(lower, "' + ") + CountOccurrences(lower, " & chr(");
        if (spacedSigns >= 12) obf++;
        double entropy = 0;
        if (text.Length < 2 * 1024 * 1024)
        {
            entropy = Entropy.ShannonBitsPerByte(Encoding.UTF8.GetBytes(text));
            if (entropy > 6.6 && text.Length > 2048) obf++;
        }
        if (obf >= 2)
        {
            string detail = $"obfuscation signals: char-code {lower.Contains("[char]") || lower.Contains("chr(") || lower.Contains("char(")}, base64 {HasBigBase64(lower)}, concat {spacedSigns}, entropy {entropy:F2}";
            evidence.Add(Ev(path, "script-obfuscated", Severity.Medium, 0.7,
                $"Script is likely obfuscated ({detail}).", tactics: "Defense Evasion"));
        }

        // --- suspicious persistence hooks in script ---
        if (lower.Contains(@"\\currentversion\\run") || lower.Contains("scheduledtasks")
            || lower.Contains("schtasks /create") || lower.Contains("startup folder") || lower.Contains(@"\\startup\\"))
        {
            evidence.Add(Ev(path, "script-persistence-hook", Severity.Medium, 0.6,
                "Script manipulates persistence mechanisms (run keys / scheduled tasks / startup).", tactics: "Persistence"));
        }

        // --- credential targeting ---
        if (lower.Contains("lsass") || lower.Contains("sam") || lower.Contains("security hive")
            || lower.Contains("mimikatz") || lower.Contains("sekurlsa") || lower.Contains("ntds.dit"))
        {
            evidence.Add(Ev(path, "script-credential-access", Severity.High, 0.85,
                "Script references credential material (LSASS / SAM / ntds).", tactics: "Credential Access"));
        }

        return evidence;
    }

    private static string Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes[2..]);
        }
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(bytes[3..]);
        }
        // Latin-1 keeps every byte meaningful for ASCII token search.
        return Encoding.Latin1.GetString(bytes);
    }

    private static int CountTokens(string lower, string[] tokens)
    {
        int count = 0;
        foreach (var t in tokens)
        {
            if (lower.Contains(t, StringComparison.Ordinal))
            {
                count++;
            }
        }
        return count;
    }

    private static int CountOccurrences(string text, string needle)
    {
        int count = 0;
        int idx = 0;
        while ((idx = text.IndexOf(needle, idx, StringComparison.Ordinal)) >= 0)
        {
            count++;
            idx += needle.Length;
        }
        return count;
    }

    private static bool HasBigBase64(string lower)
    {
        // A base64 blob is long runs of [A-Za-z0-9+/=].
        int run = 0;
        foreach (char c in lower)
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=')
            {
                run++;
                if (run >= 300)
                {
                    return true;
                }
            }
            else
            {
                run = 0;
            }
        }
        return false;
    }

    private static bool HasLongToken(string text)
    {
        // '-e' followed by a long argument suggests encoded command passed inline.
        foreach (string tok in new[] { "-e ", "-enc " })
        {
            int idx = text.IndexOf(tok, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0 && idx + tok.Length + 60 < text.Length)
            {
                return true;
            }
        }
        return false;
    }

    private static bool RegexSafe(string pattern, string lower)
        => System.Text.RegularExpressions.Regex.IsMatch(lower, pattern, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(50));

    private static Evidence Ev(string entity, string evt, Severity severity, double confidence, string explanation, string? tactics = null)
    {
        return new Evidence
        {
            Source = "script",
            Timestamp = DateTime.UtcNow,
            EntityType = "file",
            EntityId = entity,
            Event = evt,
            Severity = severity,
            Confidence = confidence,
            Explanation = explanation,
            DetailsJson = tactics is null ? null : "{\"tactics\":\"" + tactics + "\"}",
        };
    }
}