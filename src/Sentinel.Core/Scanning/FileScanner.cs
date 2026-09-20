using Sentinel.Core.Hashing;
using Sentinel.Core.Models;
using Sentinel.Core.Pe;
using Sentinel.Core.Signing;
using Sentinel.Core.Storage;

namespace Sentinel.Core.Scanning;

/// <summary>Options for a file/folder scan.</summary>
public sealed class FileScanOptions
{
    /// <summary>Root paths to scan (files or directories).</summary>
    public required IReadOnlyList<string> Targets { get; init; }

    /// <summary>When true, recurse into subdirectories.</summary>
    public bool Recurse { get; init; } = true;

    /// <summary>Hash algorithms to compute for each file.</summary>
    public HashAlgorithms HashAlgorithms { get; init; } = HashAlgorithms.Sha256;

    /// <summary>When true, verify Authenticode signatures for PE files.</summary>
    public bool VerifySignatures { get; init; } = true;

    /// <summary>When true, parse PE structure for PE files.</summary>
    public bool ParsePe { get; init; } = true;

    /// <summary>When true, compute whole-file Shannon entropy.</summary>
    public bool ComputeEntropy { get; init; } = true;

    /// <summary>When true, enumerate alternate data streams.</summary>
    public bool EnumerateAds { get; init; } = true;

    /// <summary>When true, read Zone.Identifier (MOTW).</summary>
    public bool CheckMotw { get; init; } = true;

    /// <summary>Maximum file size to hash (bytes); larger files are reported without hashes.</summary>
    public long MaxHashSize { get; init; } = 512L * 1024 * 1024;

    /// <summary>Maximum file size to fully read for entropy (bytes).</summary>
    public long MaxEntropySize { get; init; } = 64L * 1024 * 1024;

    /// <summary>Active exclusion rules (path/hash/signer).</summary>
    public IReadOnlyList<Exclusion> Exclusions { get; init; } = [];

    /// <summary>When true, excluded files are skipped entirely (not reported).</summary>
    public bool SkipExcluded { get; init; } = true;

    /// <summary>Directories to skip by name (e.g., "Windows", "node_modules").</summary>
    public IReadOnlyList<string> SkipDirectoryNames { get; init; } = [];

    /// <summary>Maximum files to report (safety cap).</summary>
    public long MaxFiles { get; init; } = 500_000;

    /// <summary>
    /// Optional store used for the path+size+lastWrite hash cache. When set,
    /// repeat scans of unchanged files reuse cached hashes (huge speedup for
    /// full scans); cache rows are bounded by the store cleaner.
    /// </summary>
    public SentinelStore? Store { get; init; }
}

/// <summary>
/// Scans files/folders producing <see cref="FileReport"/> items. Honest progress:
/// when the target set is fully enumerable the total is counted first (exact percent);
/// otherwise progress is indeterminate (percent = null). Cancellation is cooperative.
/// </summary>
public sealed class FileScanner
{
    private readonly FileScanOptions _options;
    private readonly IProgress<ScanProgress>? _progress;
    private readonly CancellationToken _ct;

    public FileScanner(FileScanOptions options, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        _options = options;
        _progress = progress;
        _ct = cancellationToken;
    }

    /// <summary>Runs the scan, yielding one report per file.</summary>
    public async IAsyncEnumerable<FileReport> ScanAsync()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var state = new ScanState2();

        // Pre-enumerate to get an exact count when possible (bounded by MaxFiles).
        var roots = new List<string>();
        foreach (string target in _options.Targets)
        {
            _ct.ThrowIfCancellationRequested();
            if (Directory.Exists(target))
            {
                roots.Add(target);
            }
            else if (File.Exists(target))
            {
                roots.Add(target);
            }
        }

        if (roots.Count == 0)
        {
            yield break;
        }

        bool allDirectories = roots.All(r => Directory.Exists(r));
        if (allDirectories)
        {
            long total = 0;
            foreach (string r in roots)
            {
                total += CountFiles(r);
            }
            state.Total = total;
        }

        Report(ScanState.Running, state, null, sw);

        foreach (string root in roots)
        {
            if (Directory.Exists(root))
            {
                await foreach (var report in ScanDirectoryAsync(root, state, sw))
                {
                    yield return report;
                }
            }
            else
            {
                var report = await AnalyzeFileAsync(root, state, sw);
                if (report is not null)
                {
                    yield return report;
                }
            }
        }

        Report(ScanState.Completed, state, null, sw);
    }

    private sealed class ScanState2
    {
        public long Total = -1;
        public long Processed;
        public long Bytes;
    }

    private async IAsyncEnumerable<FileReport> ScanDirectoryAsync(
        string dir, ScanState2 state, System.Diagnostics.Stopwatch sw)
    {
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir, "*", _options.Recurse
                ? SearchOption.AllDirectories
                : SearchOption.TopDirectoryOnly);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (string file in files)
        {
            _ct.ThrowIfCancellationRequested();

            if (state.Processed >= _options.MaxFiles)
            {
                break;
            }

            // Skip directories by name (cheap filter on the path).
            if (ShouldSkipPath(file))
            {
                continue;
            }

            var report = await AnalyzeFileAsync(file, state, sw);
            if (report is not null)
            {
                yield return report;
            }
        }
    }

    private bool ShouldSkipPath(string path)
    {
        foreach (string name in _options.SkipDirectoryNames)
        {
            if (path.Contains("\\" + name + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private async Task<FileReport?> AnalyzeFileAsync(
        string path, ScanState2 state, System.Diagnostics.Stopwatch sw)
    {
        _ct.ThrowIfCancellationRequested();

        FileInfo fi;
        try
        {
            fi = new FileInfo(path);
            if (!fi.Exists)
            {
                return null;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }

        // Exclusion check (path-based).
        if (_options.SkipExcluded && IsExcluded(path))
        {
            return null;
        }

        // Hash/signer exclusions are evaluated after analysis in the detection layer;
        // here we only skip exact path matches to avoid wasted work.

        var notes = new List<string>();
        var ads = _options.EnumerateAds ? FileMetadata.GetAlternateDataStreams(path) : [];
        var (hasMotw, motwZoneId, referrer) = _options.CheckMotw ? FileMetadata.ReadMotw(path) : (false, null, null);
        var (hidden, reparse) = FileMetadata.GetAttributes(path);

        string? sha256 = null, sha1 = null, md5 = null;
        double? entropy = null;
        PeInfo? pe = null;
        SignatureStatus sigStatus = SignatureStatus.Unknown;
        string? signer = null;

        bool isPeCandidate = IsLikelyPe(fi.Name);

        // Hash cache: skip re-hashing when size + last-write match a previous scan.
        var cached = _options.Store?.GetHashCache(path, fi.Length, fi.LastWriteTimeUtc);
        if (cached is not null)
        {
            (sha256, sha1, md5) = cached.Value;
        }

        if (sha256 is null && fi.Length <= _options.MaxHashSize)
        {
            try
            {
                var hash = await HashService.ComputeFileAsync(path, _options.HashAlgorithms, null, _ct);
                sha256 = hash.Sha256;
                sha1 = hash.Sha1;
                md5 = hash.Md5;
                _options.Store?.SetHashCache(path, fi.Length, fi.LastWriteTimeUtc, sha256, sha1, md5);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException)
            {
                if (ex is OperationCanceledException)
                {
                    throw;
                }
            }
        }
        else if (sha256 is null)
        {
            notes.Add($"File larger than hash cap ({_options.MaxHashSize / (1024 * 1024)} MiB) - hash skipped.");
        }

        // Known-bad hash blacklist check (when a store is attached and a hash exists).
        string? knownMalwareLabel = null;
        if (sha256 is not null && _options.Store is not null)
        {
            var bl = _options.Store.LookupBlacklist(sha256);
            if (bl is not null)
            {
                knownMalwareLabel = bl.Label;
                notes.Add($"KNOWN MALWARE HASH: {bl.Label} ({(bl.Verdict ?? "malware")})");
            }
        }

        if (isPeCandidate && fi.Length <= _options.MaxEntropySize)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                entropy = Entropy.ShannonBitsPerByte(await ReadAllAsync(fs, _ct));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        if (isPeCandidate)
        {
            pe = PeParser.Parse(path, computeSectionEntropy: true);
            if (pe.IsPe)
            {
                notes.Add($"{pe.MachineName} {(pe.Is64Bit ? "64-bit" : "32-bit")} PE, {pe.Sections.Count} sections");
                if (pe.TimestampAnomaly is not null)
                {
                    notes.Add(pe.TimestampAnomaly);
                }
                if (pe.Sections.Any(s => s.IsExecutable && s.IsWritable))
                {
                    notes.Add("Executable+Writable section present (RWX) - unusual for normal compilers.");
                }
                if (pe.Sections.Any(s => s.Entropy is > Entropy.HighEntropyThreshold))
                {
                    notes.Add("Section entropy above 7.2 bits/byte - possible packing/encryption.");
                }
                if (pe.OverlaySize > 0)
                {
                    notes.Add($"Overlay of {pe.OverlaySize} bytes after last section.");
                }
                if (pe.TlsCallbacks.Count > 0)
                {
                    notes.Add($"{pe.TlsCallbacks.Count} TLS callback(s) - executes before entry point.");
                }
                if (pe.HasPdb)
                {
                    notes.Add("PDB debug info present.");
                }
                if (!pe.HasAslr)
                {
                    notes.Add("ASLR (DYNAMIC_BASE) not set.");
                }
                if (!pe.HasNxCompat)
                {
                    notes.Add("NX_COMPAT not set - DEP may be disabled.");
                }
            }
            else if (pe.Status == PeParseStatus.Corrupt)
            {
                notes.Add($"PE structure corrupt: {pe.Error}");
            }

            if (_options.VerifySignatures)
            {
                var sig = SignatureVerifier.Verify(path, extractSigner: true);
                sigStatus = sig.Status;
                signer = sig.SignerName;
                if (sig.Status == SignatureStatus.SignedUntrusted)
                {
                    notes.Add($"Signature present but not trusted: {sig.Explanation}");
                }
                else if (sig.Status == SignatureStatus.SignatureInvalid)
                {
                    notes.Add($"Signature invalid: {sig.Explanation}");
                }
            }
        }

        state.Processed++;
        state.Bytes += fi.Length;
        Report(ScanState.Running, state, path, sw);

        return new FileReport
        {
            Path = path,
            FileName = fi.Name,
            Size = fi.Length,
            CreationTimeUtc = fi.CreationTimeUtc,
            LastWriteTimeUtc = fi.LastWriteTimeUtc,
            LastAccessTimeUtc = fi.LastAccessTimeUtc,
            IsDirectory = false,
            IsPe = pe?.IsPe ?? false,
            Sha256 = sha256,
            Sha1 = sha1,
            Md5 = md5,
            SignatureStatus = sigStatus,
            SignerName = signer,
            Pe = pe,
            AlternateDataStreams = ads,
            HasMotw = hasMotw,
            MotwZoneId = motwZoneId,
            MotwReferrerUrl = referrer,
            Entropy = entropy,
            IsHiddenOrSystem = hidden,
            IsReparsePoint = reparse,
            IsExcluded = false,
            Notes = notes,
            KnownMalwareLabel = knownMalwareLabel,
        };
    }

    private static bool IsLikelyPe(string fileName)
    {
        string ext = Path.GetExtension(fileName);
        return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".scr", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".cpl", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".drv", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsExcluded(string path)
    {
        foreach (var ex in _options.Exclusions)
        {
            if (ex.Type == ExclusionType.Path && MatchesPath(ex.Value, path))
            {
                return true;
            }
        }
        return false;
    }

    private static bool MatchesPath(string pattern, string path)
    {
        if (pattern.EndsWith("\\", StringComparison.Ordinal) || pattern.EndsWith("/", StringComparison.Ordinal))
        {
            return path.StartsWith(pattern, StringComparison.OrdinalIgnoreCase);
        }
        return path.Equals(pattern, StringComparison.OrdinalIgnoreCase);
    }

    private long CountFiles(string root)
    {
        long count = 0;
        try
        {
            foreach (string _ in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                if (++count >= _options.MaxFiles)
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
        return count;
    }

    private void Report(ScanState scanState, ScanState2 state, string? current, System.Diagnostics.Stopwatch sw)
    {
        _progress?.Report(new ScanProgress
        {
            State = scanState,
            FilesTotal = state.Total,
            FilesProcessed = state.Processed,
            BytesProcessed = state.Bytes,
            CurrentItem = current,
            Percent = state.Total > 0 ? Math.Min(1.0, (double)state.Processed / state.Total) : null,
            FilesPerSecond = sw.Elapsed.TotalSeconds > 0 ? state.Processed / sw.Elapsed.TotalSeconds : 0,
            Eta = state.Total > 0 && state.Processed > 0 && sw.Elapsed.TotalSeconds > 0
                ? TimeSpan.FromSeconds((state.Total - state.Processed) / (state.Processed / sw.Elapsed.TotalSeconds))
                : null,
        });
    }

    private static async Task<byte[]> ReadAllAsync(FileStream fs, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        await fs.CopyToAsync(ms, ct);
        return ms.ToArray();
    }
}