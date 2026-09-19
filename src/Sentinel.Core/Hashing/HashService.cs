using System.Security.Cryptography;

namespace Sentinel.Core.Hashing;

/// <summary>Which hash algorithms to compute for a file.</summary>
[Flags]
public enum HashAlgorithms
{
    /// <summary>SHA-256 only (primary, NIST SP 800-131A approved).</summary>
    Sha256 = 1,

    /// <summary>SHA-1 (legacy; retained for compatibility with old threat intel feeds).</summary>
    Sha1 = 2,

    /// <summary>MD5 (legacy; retained for compatibility with old threat intel feeds).</summary>
    Md5 = 4,

    /// <summary>All supported algorithms.</summary>
    All = Sha256 | Sha1 | Md5,
}

/// <summary>Result of hashing a file.</summary>
public sealed record HashResult
{
    /// <summary>SHA-256 hash, lowercase hex.</summary>
    public required string Sha256 { get; init; }

    /// <summary>SHA-1 hash, lowercase hex; null when not requested.</summary>
    public string? Sha1 { get; init; }

    /// <summary>MD5 hash, lowercase hex; null when not requested.</summary>
    public string? Md5 { get; init; }

    /// <summary>Total bytes hashed.</summary>
    public long FileSize { get; init; }

    /// <summary>Time spent hashing.</summary>
    public TimeSpan Duration { get; init; }
}

/// <summary>
/// Streaming file hashing built on <see cref="IncrementalHash"/>. Reads in 1 MiB chunks,
/// is cancellation-aware, and reports progress as bytes-read/total-bytes when the stream
/// length is known (file size), otherwise indeterminate progress.
/// </summary>
public static class HashService
{
    /// <summary>Chunk size for streaming reads (1 MiB).</summary>
    public const int ChunkSize = 1024 * 1024;

    private static readonly byte[] s_buffer = GC.AllocateUninitializedArray<byte>(ChunkSize, pinned: false);

    /// <summary>
    /// Computes hashes for a file. SHA-256 is always computed; SHA-1/MD5 only when requested.
    /// </summary>
    /// <param name="path">Full path to the file.</param>
    /// <param name="algorithms">Which algorithms to compute.</param>
    /// <param name="progress">Progress handler receiving 0..1 (based on file length). May be null.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<HashResult> ComputeFileAsync(
        string path,
        HashAlgorithms algorithms = HashAlgorithms.Sha256,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var sw = System.Diagnostics.Stopwatch.StartNew();

        using var fs = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            ChunkSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        long length = fs.Length;
        long totalRead = 0;

        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var sha1 = (algorithms & HashAlgorithms.Sha1) != 0
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA1)
            : null;
        using var md5 = (algorithms & HashAlgorithms.Md5) != 0
            ? IncrementalHash.CreateHash(HashAlgorithmName.MD5)
            : null;

        byte[] buffer = s_buffer;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int read = await fs.ReadAsync(buffer.AsMemory(0, ChunkSize), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            sha256.AppendData(buffer, 0, read);
            sha1?.AppendData(buffer, 0, read);
            md5?.AppendData(buffer, 0, read);

            totalRead += read;
            if (progress is not null && length > 0)
            {
                progress.Report((double)totalRead / length);
            }
        }

        sw.Stop();

        return new HashResult
        {
            Sha256 = Convert.ToHexStringLower(sha256.GetHashAndReset()),
            Sha1 = sha1 is null ? null : Convert.ToHexStringLower(sha1.GetHashAndReset()),
            Md5 = md5 is null ? null : Convert.ToHexStringLower(md5.GetHashAndReset()),
            FileSize = totalRead,
            Duration = sw.Elapsed,
        };
    }

    /// <summary>Converts a byte array to lowercase hex without allocation overhead concerns.</summary>
    public static string ToHexLower(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    /// <summary>Normalizes a user-supplied hash to lowercase hex; returns null when malformed.</summary>
    public static string? NormalizeHex(string? hash)
    {
        if (string.IsNullOrWhiteSpace(hash))
        {
            return null;
        }

        string trimmed = hash.Trim();
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[2..];
        }

        if (trimmed.Length == 0 || trimmed.Length % 2 != 0 || !trimmed.All(Uri.IsHexDigit))
        {
            return null;
        }

        return trimmed.ToLowerInvariant();
    }
}
