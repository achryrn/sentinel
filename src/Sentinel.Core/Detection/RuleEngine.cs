using System.Text;
using Sentinel.Core.Models;

namespace Sentinel.Core.Detection;

/// <summary>Kind of a rule string.</summary>
public enum RuleStringKind
{
    /// <summary>Plain ASCII/UTF-8 pattern.</summary>
    Ascii,

    /// <summary>UTF-16LE pattern (each byte followed by 0x00).</summary>
    Wide,

    /// <summary>Hex pattern, e.g. "4D 5A ?? 00 00". '?' matches any byte.</summary>
    Hex,
}

/// <summary>One string within a rule.</summary>
public sealed record RuleString
{
    public required string Id { get; init; }        // "$a"
    public required RuleStringKind Kind { get; init; }
    public required string Text { get; init; }      // literal text (escapes resolved) or hex pattern
    public bool Nocase { get; init; }
}

/// <summary>A parsed matching rule (YARA-lite).</summary>
public sealed class Rule
{
    public required string Name { get; init; }
    public string? Description { get; init; }
    public Severity Severity { get; init; } = Severity.Medium;
    public double Confidence { get; init; } = 0.7;
    public string[] Tactics { get; init; } = [];
    public IReadOnlyList<RuleString> Strings { get; init; } = [];
    public required RuleCondition Condition { get; init; }
}

/// <summary>Condition AST for <see cref="Rule"/>.</summary>
public abstract record RuleCondition;

/// <summary>"$a" - the string is present.</summary>
public sealed record StringPresent(string Id) : RuleCondition;

/// <summary>"#a &gt;= N" - occurrence count check.</summary>
public sealed record CountAtLeast(string Id, int N) : RuleCondition;

/// <summary>"all of them".</summary>
public sealed record AllOfCondition : RuleCondition;

/// <summary>"any of them".</summary>
public sealed record AnyOfCondition : RuleCondition;

/// <summary>"N of them" - at least N of the rule's strings present.</summary>
public sealed record NOfCondition(int N) : RuleCondition;

/// <summary>"A and B".</summary>
public sealed record AndCondition(RuleCondition A, RuleCondition B) : RuleCondition;

/// <summary>"A or B".</summary>
public sealed record OrCondition(RuleCondition A, RuleCondition B) : RuleCondition;

/// <summary>"not A".</summary>
public sealed record NotCondition(RuleCondition A) : RuleCondition;

/// <summary>One rule match with the strings that hit and their occurrence counts.</summary>
public sealed record RuleMatch
{
    public required Rule Rule { get; init; }
    public required IReadOnlyDictionary<string, int> StringCounts { get; init; }
}

/// <summary>
/// A compact YARA-compatible rule engine: rules are declared in a YARA-like
/// syntax (meta/strings/condition) and matched against file/script content.
/// This gives Sentinel genuine signature-based detection on top of the
/// static heuristics, so known-bad content is caught with high confidence
/// instead of producing weak "signals".
///
/// Supported syntax subset:
/// <code>
/// rule name {
///   meta:
///     description = "text"
///     severity = "high"          // info|low|medium|high|critical
///     confidence = 0.9           // 0..1
///     tactics = "execution, defense evasion"
///   strings:
///     $a = "text" ascii nocase   // modifiers: ascii | wide | nocase (combinable)
///     $b = { 4D 5A ?? 00 }       // hex with '?' wildcards
///   condition:
///     $a and $b or 2 of them
/// }
/// </code>
/// Conditions support $name, #name (count), any/all/N of them, and/or/not, parens.
/// Regex strings are rejected (rule is skipped) to keep the engine deterministic.
/// </summary>
public static class RuleEngine
{
    private const int MaxRuleScanBytes = 8 * 1024 * 1024;

    /// <summary>Matches a byte buffer against rules. Bounded to <see cref="MaxRuleScanBytes"/>.</summary>
    public static IReadOnlyList<RuleMatch> Match(ReadOnlySpan<byte> data, IReadOnlyList<Rule> rules)
    {
        var matches = new List<RuleMatch>();
        if (rules.Count == 0 || data.Length == 0)
        {
            return matches;
        }
        var span = data.Length <= MaxRuleScanBytes ? data : data[..MaxRuleScanBytes];

        foreach (var rule in rules)
        {
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var rs in rule.Strings)
            {
                int c = CountOccurrences(span, rs);
                if (c > 0)
                {
                    counts[rs.Id] = c;
                }
            }
            if (Evaluate(rule.Condition, rule.Strings, counts, out _))
            {
                matches.Add(new RuleMatch { Rule = rule, StringCounts = counts });
            }
        }
        return matches;
    }

    /// <summary>Matches a file's content (bounded read). Returns empty when unreadable or too large.</summary>
    public static IReadOnlyList<RuleMatch> MatchFile(string path, IReadOnlyList<Rule> rules)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length <= 0 || fi.Length > MaxRuleScanBytes)
            {
                return [];
            }
            byte[] buffer = new byte[(int)fi.Length];
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int read = 0;
            while (read < buffer.Length)
            {
                int n = fs.Read(buffer, read, buffer.Length - read);
                if (n == 0)
                {
                    break;
                }
                read += n;
            }
            return Match(buffer.AsSpan(0, read), rules);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return [];
        }
    }

    // ---------- condition evaluation ----------

    private static bool Evaluate(RuleCondition cond, IReadOnlyList<RuleString> strings,
        IReadOnlyDictionary<string, int> counts, out int countTotal)
    {
        countTotal = 0;
        switch (cond)
        {
            case StringPresent sp:
                return counts.TryGetValue(sp.Id, out int csp) && csp > 0;
            case CountAtLeast ca:
                return counts.TryGetValue(ca.Id, out int cca) && cca >= ca.N;
            case AnyOfCondition:
                countTotal = strings.Count(rs => counts.ContainsKey(rs.Id));
                return countTotal > 0;
            case AllOfCondition:
                countTotal = strings.Count(rs => counts.ContainsKey(rs.Id));
                return countTotal == strings.Count && strings.Count > 0;
            case NOfCondition noc:
                countTotal = strings.Count(rs => counts.ContainsKey(rs.Id));
                return countTotal >= noc.N;
            case AndCondition and:
            {
                bool a = Evaluate(and.A, strings, counts, out int ca);
                bool b = Evaluate(and.B, strings, counts, out int cb);
                countTotal = Math.Max(ca, cb);
                return a && b;
            }
            case OrCondition or:
            {
                bool a = Evaluate(or.A, strings, counts, out int ca);
                bool b = Evaluate(or.B, strings, counts, out int cb);
                countTotal = Math.Max(ca, cb);
                return a || b;
            }
            case NotCondition not:
            {
                bool a = Evaluate(not.A, strings, counts, out int c);
                countTotal = c;
                return !a;
            }
            default:
                return false;
        }
    }

    // ---------- string matching ----------

    private static int CountOccurrences(ReadOnlySpan<byte> data, RuleString rs)
    {
        byte[] pattern = rs.Kind switch
        {
            RuleStringKind.Hex => ParseHexPattern(rs.Text),
            RuleStringKind.Wide => ToWideBytes(rs.Text),
            _ => Encoding.UTF8.GetBytes(rs.Text),
        };
        if (pattern.Length == 0)
        {
            return 0;
        }
        return rs.Nocase ? CountCaseInsensitive(data, pattern) : CountPlain(data, pattern);
    }

    private static int CountPlain(ReadOnlySpan<byte> data, byte[] pattern)
    {
        bool hasWildcard = pattern.Contains((byte)'?');
        if (hasWildcard)
        {
            return CountWithWildcards(data, pattern);
        }
        int count = 0;
        int idx = data.IndexOf(pattern);
        while (idx >= 0)
        {
            count++;
            int next = data[(idx + pattern.Length)..].IndexOf(pattern);
            if (next < 0)
            {
                break;
            }
            idx += pattern.Length + next;
        }
        return count;
    }

    private static int CountCaseInsensitive(ReadOnlySpan<byte> data, byte[] pattern)
    {
        byte[] lower = ToLowerAscii(pattern);
        int count = 0;
        for (int i = 0; i + pattern.Length <= data.Length;)
        {
            bool eq = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                byte b = data[i + j];
                if (b >= (byte)'A' && b <= (byte)'Z')
                {
                    b += (byte)('a' - 'A');
                }
                if (b != lower[j])
                {
                    eq = false;
                    break;
                }
            }
            if (eq)
            {
                count++;
                i += pattern.Length;
            }
            else
            {
                i++;
            }
        }
        return count;
    }

    private static int CountWithWildcards(ReadOnlySpan<byte> data, byte[] pattern)
    {
        int count = 0;
        for (int i = 0; i + pattern.Length <= data.Length;)
        {
            bool eq = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (pattern[j] != (byte)'?' && data[i + j] != pattern[j])
                {
                    eq = false;
                    break;
                }
            }
            if (eq)
            {
                count++;
                i += pattern.Length;
            }
            else
            {
                i++;
            }
        }
        return count;
    }

    private static byte[] ToLowerAscii(byte[] bytes)
    {
        var lower = new byte[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            lower[i] = b >= (byte)'A' && b <= (byte)'Z' ? (byte)(b + ('a' - 'A')) : b;
        }
        return lower;
    }

    private static byte[] ToWideBytes(string text)
    {
        var bytes = new List<byte>(text.Length * 2);
        foreach (char c in text)
        {
            bytes.Add((byte)c);
            bytes.Add(0);
        }
        return [.. bytes];
    }

    /// <summary>Parses "4D 5A ?? 00" into bytes; '?' kept as 0x3F marker.</summary>
    private static byte[] ParseHexPattern(string hex)
    {
        var bytes = new List<byte>(hex.Length / 2 + 1);
        string cleaned = hex.Replace(" ", "").Replace("\t", "").Replace("\r", "").Replace("\n", "");
        for (int i = 0; i < cleaned.Length; i += 2)
        {
            string pair = cleaned.Substring(i, Math.Min(2, cleaned.Length - i));
            if (pair.All(c => c == '?'))
            {
                bytes.Add((byte)'?');
            }
            else if (byte.TryParse(pair, System.Globalization.NumberStyles.HexNumber, null, out byte b))
            {
                bytes.Add(b);
            }
            else
            {
                // Malformed pair - wildcard so the string simply never matches.
                bytes.Add((byte)'?');
            }
        }
        return [.. bytes];
    }

    // ---------- parsing ----------

    /// <summary>
    /// Parses YARA-lite rule text into rules. Unsupported constructs (regex
    /// strings, imports, identifiers we cannot evaluate) cause that rule to be
    /// skipped - a parse failure never aborts the whole pack.
    /// </summary>
    public static IReadOnlyList<Rule> Parse(string text)
    {
        var rules = new List<Rule>();
        int pos = 0;
        while (true)
        {
            pos = SkipWsAndComments(text, pos);
            if (pos >= text.Length)
            {
                break;
            }
            if (!text.AsSpan(pos).StartsWith("rule", StringComparison.OrdinalIgnoreCase))
            {
                // Unknown top-level token - skip to next 'rule' keyword.
                int next = text.IndexOf("rule", pos + 1, StringComparison.OrdinalIgnoreCase);
                if (next < 0)
                {
                    break;
                }
                pos = next;
                continue;
            }
            pos += 4;
            pos = SkipWsAndComments(text, pos);
            int nameStart = pos;
            while (pos < text.Length && (char.IsLetterOrDigit(text[pos]) || text[pos] == '_'))
            {
                pos++;
            }
            if (pos == nameStart)
            {
                continue;
            }
            string name = text[nameStart..pos];
            pos = SkipWsAndComments(text, pos);
            if (pos >= text.Length || text[pos] != '{')
            {
                continue;
            }
            pos++;
            int end = FindClosingBrace(text, pos);
            if (end < 0)
            {
                break;
            }
            string body = text[pos..end];
            pos = end + 1;

            var rule = ParseRuleBody(name, body);
            if (rule is not null)
            {
                rules.Add(rule);
            }
        }
        return rules;
    }

    private static Rule? ParseRuleBody(string name, string body)
    {
        int pos = 0;
        string? description = null;
        Severity severity = Severity.Medium;
        double confidence = 0.7;
        string[] tactics = [];
        var strings = new List<RuleString>();
        RuleCondition? condition = null;
        string section = "";

        while (pos < body.Length)
        {
            pos = SkipWsAndComments(body, pos);
            if (pos >= body.Length)
            {
                break;
            }
            // Section header?
            int colon = body.IndexOf(':', pos);
            if (colon > pos && colon - pos < 40 && !body[pos..colon].Contains(' '))
            {
                string maybe = body[pos..colon].Trim();
                if (maybe is "meta" or "strings" or "condition")
                {
                    section = maybe;
                    pos = colon + 1;
                    continue;
                }
            }

            if (section == "meta")
            {
                string line = NextStatement(body, ref pos);
                if (line.Length == 0)
                {
                    continue;
                }
                int eq = line.IndexOf('=');
                if (eq <= 0)
                {
                    continue;
                }
                string key = line[..eq].Trim().ToLowerInvariant();
                string value = Unquote(line[(eq + 1)..].Trim());
                switch (key)
                {
                    case "description": description = value; break;
                    case "severity":
                        severity = value.ToLowerInvariant() switch
                        {
                            "info" => Severity.Info,
                            "low" => Severity.Low,
                            "medium" => Severity.Medium,
                            "high" => Severity.High,
                            "critical" => Severity.Critical,
                            _ => Severity.Medium,
                        };
                        break;
                    case "confidence":
                        if (double.TryParse(value, System.Globalization.CultureInfo.InvariantCulture, out double c))
                        {
                            confidence = Math.Clamp(c, 0, 1);
                        }
                        break;
                    case "tactics":
                        tactics = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        break;
                }
            }
            else if (section == "strings")
            {
                string line = NextStatement(body, ref pos);
                if (line.Length == 0)
                {
                    continue;
                }
                if (line.StartsWith('}'))
                {
                    continue;
                }
                if (!line.StartsWith('$'))
                {
                    continue;
                }
                int eq = line.IndexOf('=');
                if (eq < 0)
                {
                    continue;
                }
                string id = line[..eq].Trim();
                string rest = line[(eq + 1)..].Trim();
                if (rest.StartsWith('/'))
                {
                    continue; // regex unsupported - skip this string
                }
                if (rest.StartsWith('{'))
                {
                    int close = rest.IndexOf('}');
                    if (close < 0)
                    {
                        continue;
                    }
                    strings.Add(new RuleString
                    {
                        Id = id,
                        Kind = RuleStringKind.Hex,
                        Text = rest[1..close],
                    });
                }
                else if (rest.StartsWith('"'))
                {
                    (string literal, string modifiers) = ParseLiteral(rest);
                    if (literal is null)
                    {
                        continue;
                    }
                    string mods = modifiers.ToLowerInvariant();
                    strings.Add(new RuleString
                    {
                        Id = id,
                        Kind = mods.Contains("wide") ? RuleStringKind.Wide : RuleStringKind.Ascii,
                        Text = literal,
                        Nocase = mods.Contains("nocase"),
                    });
                }
            }
            else if (section == "condition")
            {
                string condText = body[pos..].Trim().TrimEnd('}').Trim();
                condition = ParseCondition(condText);
                break;
            }
            else
            {
                break; // no section yet - malformed body
            }
        }

        if (condition is null || strings.Count == 0)
        {
            return null;
        }

        return new Rule
        {
            Name = name,
            Description = description,
            Severity = severity,
            Confidence = confidence,
            Tactics = tactics,
            Strings = strings,
            Condition = condition,
        };
    }

    private static (string Literal, string Modifiers) ParseLiteral(string rest)
    {
        // rest starts with '"'; find the closing quote honoring backslash escapes.
        var sb = new StringBuilder();
        int i = 1;
        while (i < rest.Length)
        {
            char c = rest[i];
            if (c == '\\' && i + 1 < rest.Length)
            {
                char n = rest[i + 1];
                if (n == 'x' && i + 3 < rest.Length && byte.TryParse(rest.Substring(i + 2, 2), System.Globalization.NumberStyles.HexNumber, null, out byte hx))
                {
                    sb.Append((char)hx);
                    i += 4;
                    continue;
                }
                if (n == 'n') { sb.Append('\n'); i += 2; continue; }
                if (n == 'r') { sb.Append('\r'); i += 2; continue; }
                if (n == 't') { sb.Append('\t'); i += 2; continue; }
                if (n == '\\') { sb.Append('\\'); i += 2; continue; } // escaped backslash
                sb.Append('\\'); // unknown escape: keep the backslash and the char (e.g. "\P")
                sb.Append(n);
                i += 2;
                continue;
            }
            if (c == '"')
            {
                return (sb.ToString(), rest[(i + 1)..].Trim());
            }
            sb.Append(c);
            i++;
        }
        return (null!, "");
    }

    /// <summary>
    /// Reads one rule statement starting at <paramref name="pos"/>, terminated by
    /// ';' or a newline (both styles accepted), and advances the position.
    /// </summary>
    private static string NextStatement(string body, ref int pos)
    {
        int end = body.Length;
        int semi = body.IndexOf(';', pos);
        int nl = body.IndexOfAny(['\n', '\r'], pos);
        if (semi >= 0 && semi < end)
        {
            end = semi;
        }
        if (nl >= 0 && nl < end)
        {
            end = nl;
        }
        string line = body[pos..end].Trim();
        pos = Math.Min(end + 1, body.Length);
        return line;
    }

    private static string Unquote(string s)
    {
        if (s.Length >= 2 && s[0] == '"' && s[^1] == '"')
        {
            return s[1..^1];
        }
        return s;
    }

    private static RuleCondition? ParseCondition(string text)
    {
        var p = new CondParser(text);
        try
        {
            var c = p.ParseOr();
            p.SkipWs();
            return p.Pos < p.Text.Length ? null : c;
        }
        catch
        {
            return null;
        }
    }

    private sealed class CondParser(string text)
    {
        public string Text = text;
        public int Pos;

        public void SkipWs()
        {
            while (Pos < Text.Length && char.IsWhiteSpace(Text[Pos]))
            {
                Pos++;
            }
        }

        public RuleCondition ParseOr()
        {
            var a = ParseAnd();
            SkipWs();
            while (Pos + 2 < Text.Length && Text.AsSpan(Pos, 2).Equals("or", StringComparison.OrdinalIgnoreCase)
                   && (Pos + 2 >= Text.Length || !char.IsLetterOrDigit(Text[Pos + 2])))
            {
                Pos += 2;
                var b = ParseAnd();
                a = new OrCondition(a, b);
                SkipWs();
            }
            return a;
        }

        public RuleCondition ParseAnd()
        {
            var a = ParseUnary();
            SkipWs();
            while (Pos + 3 < Text.Length && Text.AsSpan(Pos, 3).Equals("and", StringComparison.OrdinalIgnoreCase)
                   && (Pos + 3 >= Text.Length || !char.IsLetterOrDigit(Text[Pos + 3])))
            {
                Pos += 3;
                var b = ParseUnary();
                a = new AndCondition(a, b);
                SkipWs();
            }
            return a;
        }

        public RuleCondition ParseUnary()
        {
            SkipWs();
            if (Pos + 3 <= Text.Length && Text.AsSpan(Pos, 3).Equals("not", StringComparison.OrdinalIgnoreCase)
                && (Pos + 3 >= Text.Length || !char.IsLetterOrDigit(Text[Pos + 3])))
            {
                Pos += 3;
                return new NotCondition(ParseUnary());
            }
            if (Pos < Text.Length && Text[Pos] == '(')
            {
                Pos++;
                var inner = ParseOr();
                SkipWs();
                if (Pos < Text.Length && Text[Pos] == ')')
                {
                    Pos++;
                }
                return inner;
            }
            return ParseAtom();
        }

        public RuleCondition ParseAtom()
        {
            SkipWs();
            if (Pos < Text.Length && Text[Pos] == '$')
            {
                int start = ++Pos;
                while (Pos < Text.Length && (char.IsLetterOrDigit(Text[Pos]) || Text[Pos] == '_'))
                {
                    Pos++;
                }
                string id = Text[start..Pos];
                return new StringPresent("$" + id);
            }
            if (Pos < Text.Length && Text[Pos] == '#')
            {
                Pos++;
                int start = Pos;
                while (Pos < Text.Length && (char.IsLetterOrDigit(Text[Pos]) || Text[Pos] == '_'))
                {
                    Pos++;
                }
                string id = "$" + Text[start..Pos];
                SkipWs();
                int min = ReadInt();
                return new CountAtLeast(id, min);
            }
            // "any of them" / "all of them" / "N of them"
            int wordStart = Pos;
            while (Pos < Text.Length && char.IsLetterOrDigit(Text[Pos]))
            {
                Pos++;
            }
            string word = Text[wordStart..Pos].ToLowerInvariant();
            if (word is "any" or "all")
            {
                SkipWs();
                if (Pos + 2 <= Text.Length && Text.AsSpan(Pos, 2).Equals("of", StringComparison.OrdinalIgnoreCase))
                {
                    Pos += 2;
                    SkipWs();
                    ReadThem();
                    return word == "any" ? new AnyOfCondition() : new AllOfCondition();
                }
            }
            if (int.TryParse(word, out int n))
            {
                SkipWs();
                if (Pos + 2 <= Text.Length && Text.AsSpan(Pos, 2).Equals("of", StringComparison.OrdinalIgnoreCase))
                {
                    Pos += 2;
                    SkipWs();
                    // "N of ($a, $b, $c)" - a narrower set; keep the same semantics
                    // by re-using NOfCondition (engine counts all strings present).
                    if (Pos < Text.Length && Text[Pos] == '(')
                    {
                        int close = Text.IndexOf(')', Pos);
                        if (close > Pos)
                        {
                            Pos = close + 1;
                        }
                        return new NOfCondition(n);
                    }
                    ReadThem();
                    return new NOfCondition(n);
                }
            }
            throw new InvalidOperationException($"Cannot parse condition token '{word}'");
        }

        private void ReadThem()
        {
            SkipWs();
            if (Pos + 4 <= Text.Length && Text.AsSpan(Pos, 4).Equals("them", StringComparison.OrdinalIgnoreCase))
            {
                Pos += 4;
            }
        }

        private int ReadInt()
        {
            SkipWs();
            int start = Pos;
            while (Pos < Text.Length && char.IsDigit(Text[Pos]))
            {
                Pos++;
            }
            if (Pos == start)
            {
                return 1;
            }
            // absorb '>=' / '>' / '==' / '<' suffixes (interpreted as >=)
            SkipWs();
            while (Pos < Text.Length && Text[Pos] is '>' or '=' or '<' or '!')
            {
                Pos++;
            }
            return int.Parse(Text.AsSpan(start, Pos - start));
        }
    }

    private static int FindClosingBrace(string text, int start)
    {
        int depth = 1;
        bool inQuote = false;
        for (int i = start; i < text.Length; i++)
        {
            char c = text[i];
            if (inQuote)
            {
                if (c == '\\' && i + 1 < text.Length)
                {
                    i++; // skip escaped char inside string
                }
                else if (c == '"')
                {
                    inQuote = false;
                }
                continue;
            }
            if (c == '"')
            {
                inQuote = true;
            }
            else if (c == '{')
            {
                depth++;
            }
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }
        }
        return -1;
    }

    private static int SkipWsAndComments(string text, int pos)
    {
        while (pos < text.Length)
        {
            if (char.IsWhiteSpace(text[pos]))
            {
                pos++;
            }
            else if (pos + 1 < text.Length && text[pos] == '/' && text[pos + 1] == '/')
            {
                int nl = text.IndexOf('\n', pos);
                pos = nl < 0 ? text.Length : nl + 1;
            }
            else
            {
                break;
            }
        }
        return pos;
    }
}