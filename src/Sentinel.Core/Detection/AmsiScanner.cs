using System.Runtime.InteropServices;

namespace Sentinel.Core.Detection;

/// <summary>AMSI verdict on scanned content.</summary>
public enum AmsiVerdict
{
    /// <summary>amsi.dll unavailable or failed to initialize — no verdict.</summary>
    Unavailable,
    /// <summary>Content was scanned and is clean (or not detected).</summary>
    Clean,
    /// <summary>Content was scanned and flagged by an AMSI provider.</summary>
    Detected,
}

/// <summary>
/// AMSI (Antimalware Scan Interface) integration. Windows 10+ ships amsi.dll;
/// script engines (PowerShell, JScript, VBA, ...) and many AVs use it to hand
/// content to registered providers (Defender, third parties). Sentinel calls it
/// on script/archive content so every AMSI provider on the box — not just our
/// own rules — gets a chance to flag the payload. The call is best-effort and
/// strictly read-only: when amsi.dll is missing or providers are absent there is
/// simply no verdict.
/// </summary>
public sealed class AmsiScanner : IDisposable
{
    // AMSI_RESULT thresholds: >= AMSI_RESULT_BLOCKED_BY_ADMIN_BEGIN (0x4000)
    // means a provider actively flagged the content (includes DETECTED).
    private const int AmsiResultBlockedByAdmin = 0x4000;
    private const int MaxScanBytes = 4 * 1024 * 1024;

    private IntPtr _context;
    private bool _available;
    private readonly object _gate = new();

    /// <summary>AMSI is present on Windows 10 16299+; absence is handled gracefully.</summary>
    public bool IsAvailable
    {
        get
        {
            EnsureInit();
            return _available;
        }
    }

    private void EnsureInit()
    {
        if (_context != IntPtr.Zero)
        {
            return;
        }
        lock (_gate)
        {
            if (_context != IntPtr.Zero)
            {
                return;
            }
            try
            {
                IntPtr ctx = IntPtr.Zero;
                int hr = AmsiInitialize("Sentinel", out ctx);
                if (hr == 0 && ctx != IntPtr.Zero)
                {
                    _context = ctx;
                    _available = true;
                }
            }
            catch (DllNotFoundException)
            {
                _available = false;
            }
            catch (EntryPointNotFoundException)
            {
                _available = false;
            }
        }
    }

    /// <summary>
    /// Scans a byte buffer with AMSI. Returns <see cref="AmsiVerdict.Detected"/>
    /// when any provider flags it. Content over 4 MiB is truncated (providers cap
    /// buffers anyway). Safe to call from multiple threads.
    /// </summary>
    public AmsiVerdict Scan(ReadOnlySpan<byte> content, string contentName)
    {
        EnsureInit();
        if (!_available || _context == IntPtr.Zero || content.IsEmpty)
        {
            return AmsiVerdict.Unavailable;
        }

        int len = Math.Min(content.Length, MaxScanBytes);
        int result = 0;
        int hr = AmsiScanBuffer(_context, ref MemoryMarshal.GetReference(content), (uint)len, contentName, 0, ref result);
        if (hr != 0)
        {
            return AmsiVerdict.Unavailable;
        }
        return result >= AmsiResultBlockedByAdmin ? AmsiVerdict.Detected : AmsiVerdict.Clean;
    }

    /// <summary>Scans a text buffer with AMSI.</summary>
    public AmsiVerdict Scan(string content, string contentName)
    {
        if (string.IsNullOrEmpty(content))
        {
            return AmsiVerdict.Unavailable;
        }
        return Scan(System.Text.Encoding.UTF8.GetBytes(content), contentName);
    }

    /// <summary>Scans a file's content with AMSI (bounded read).</summary>
    public AmsiVerdict ScanFile(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length <= 0 || fi.Length > MaxScanBytes)
            {
                return AmsiVerdict.Unavailable;
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
            return Scan(buffer.AsSpan(0, read), Path.GetFileName(path));
        }
        catch (Exception)
        {
            return AmsiVerdict.Unavailable;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_context != IntPtr.Zero)
            {
                AmsiUninitialize(_context);
                _context = IntPtr.Zero;
                _available = false;
            }
        }
    }

    // ---------- P/Invoke (late-bound by the loader on Win10+) ----------

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr amsiContext);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern int AmsiScanBuffer(IntPtr amsiContext, ref byte buffer, uint length,
        [MarshalAs(UnmanagedType.LPWStr)] string contentName, ulong contentSource, ref int result);

    [DllImport("amsi.dll", ExactSpelling = true)]
    private static extern void AmsiUninitialize(IntPtr amsiContext);
}