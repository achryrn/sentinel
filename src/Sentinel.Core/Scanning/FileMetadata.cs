using System.Runtime.InteropServices;
using System.Text;
using Sentinel.Core.Native;

namespace Sentinel.Core.Scanning;

/// <summary>
/// File metadata extraction: alternate data streams (via FindFirstStreamW/FindNextStreamW)
/// and Mark-of-the-Web (Zone.Identifier ADS parsing). Read-only; never modifies files.
/// </summary>
public static class FileMetadata
{
    /// <summary>Enumerates alternate data streams of a file. Returns empty list on failure.</summary>
    public static IReadOnlyList<Models.AdDataStream> GetAlternateDataStreams(string path)
    {
        var result = new List<Models.AdDataStream>();
        try
        {
            IntPtr h = NativeMethods.FindFirstStreamW(path, 0, out NativeMethods.WIN32_FIND_STREAM_DATA data, 0);
            if (h == new IntPtr(-1))
            {
                return result;
            }

            try
            {
                do
                {
                    string name = data.cStreamName;
                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }
                    // Skip the default stream "::$DATA" - it is the file itself.
                    if (name.Equals("::$DATA", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    result.Add(new Models.AdDataStream { Name = name, Size = data.StreamSize });
                }
                while (NativeMethods.FindNextStreamW(h, out data));
            }
            finally
            {
                NativeMethods.FindClose(h);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DllNotFoundException or EntryPointNotFoundException)
        {
            // Best effort only.
        }

        return result;
    }

    /// <summary>
    /// Reads the Zone.Identifier ADS (Mark-of-the-Web) if present.
    /// Returns (hasMotw, zoneId, referrerUrl).
    /// </summary>
    public static (bool HasMotw, int? ZoneId, string? ReferrerUrl) ReadMotw(string path)
    {
        try
        {
            string adsPath = path + ":Zone.Identifier";
            if (!File.Exists(adsPath))
            {
                return (false, null, null);
            }

            string content = File.ReadAllText(adsPath, Encoding.Unicode);
            int? zoneId = null;
            string? referrer = null;

            foreach (string rawLine in content.Split('\n'))
            {
                string line = rawLine.Trim();
                if (line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase))
                {
                    if (int.TryParse(line["ZoneId=".Length..].Trim(), out int z) && z >= 0)
                    {
                        zoneId = z;
                    }
                }
                else if (line.StartsWith("ReferrerUrl=", StringComparison.OrdinalIgnoreCase))
                {
                    referrer = line["ReferrerUrl=".Length..].Trim();
                }
            }

            return (true, zoneId, referrer);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return (false, null, null);
        }
    }

    /// <summary>Gets basic file attributes (hidden/system/reparse) via File.GetAttributes.</summary>
    public static (bool HiddenOrSystem, bool ReparsePoint) GetAttributes(string path)
    {
        try
        {
            var attrs = File.GetAttributes(path);
            bool hidden = (attrs & FileAttributes.Hidden) != 0 || (attrs & FileAttributes.System) != 0;
            bool reparse = (attrs & FileAttributes.ReparsePoint) != 0;
            return (hidden, reparse);
        }
        catch
        {
            return (false, false);
        }
    }
}