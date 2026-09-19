namespace Sentinel.Core.Hashing;

/// <summary>
/// Shannon entropy calculation. Used to flag packed/encrypted payloads and to characterize
/// PE sections (e.g., a code section with entropy near 8.0 is atypical for normal compilers).
/// </summary>
public static class Entropy
{
    /// <summary>
    /// Computes Shannon entropy in bits per byte (0..8) for a buffer.
    /// An empty buffer returns 0.
    /// </summary>
    public static double ShannonBitsPerByte(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (byte b in data)
        {
            counts[b]++;
        }

        int total = data.Length;
        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0)
            {
                continue;
            }

            double p = (double)counts[i] / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    /// <summary>Rounded convenience overload returning a value in 0..8 with 3 decimal places.</summary>
    public static double ShannonBitsPerByte(byte[] data) => Math.Round(ShannonBitsPerByte(data.AsSpan()), 3);

    /// <summary>
    /// Computes per-block entropy for a stream (e.g., PE sections). Reads the stream from its
    /// current position, in <paramref name="blockSize"/> chunks; the final partial block is included.
    /// </summary>
    /// <returns>A list of (offset, entropy) pairs, one per block.</returns>
    public static async Task<IReadOnlyList<(long Offset, double Entropy)>> ComputeBlockEntropyAsync(
        Stream stream,
        int blockSize,
        int maxBlocks = 4096,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (blockSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(blockSize));
        }

        var results = new List<(long, double)>(Math.Min(maxBlocks, 256));
        byte[] buffer = new byte[blockSize];
        long offset = stream.Position;

        while (results.Count < maxBlocks)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int read = await stream.ReadAsync(buffer.AsMemory(0, blockSize), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            results.Add((offset, ShannonBitsPerByte(buffer.AsSpan(0, read))));
            offset += read;
        }

        return results;
    }

    /// <summary>
    /// Classification helper: entropy above this value for a full PE section suggests packing/encryption.
    /// (Common heuristic; never used alone as a detection — always correlated with other evidence.)
    /// </summary>
    public const double HighEntropyThreshold = 7.2;
}
