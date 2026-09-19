using Sentinel.Core.Hashing;

namespace Sentinel.Tests;

public class HashServiceTests
{
    // Known test vectors (NIST / RFC 1321).
    private const string EmptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const string EmptySha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    private const string EmptyMd5 = "d41d8cd98f00b204e9800998ecf8427e";

    private static string TempFile(byte[] content)
    {
        string path = Path.Combine(Path.GetTempPath(), $"sentinel-test-{Guid.NewGuid():n}.bin");
        File.WriteAllBytes(path, content);
        return path;
    }

    [Fact]
    public async Task EmptyFile_AllAlgorithms_MatchesKnownVectors()
    {
        string path = TempFile([]);
        try
        {
            var result = await HashService.ComputeFileAsync(path, HashAlgorithms.All);

            Assert.Equal(EmptySha256, result.Sha256);
            Assert.Equal(EmptySha1, result.Sha1);
            Assert.Equal(EmptyMd5, result.Md5);
            Assert.Equal(0, result.FileSize);
            Assert.True(result.Duration >= TimeSpan.Zero);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task KnownContent_MatchesReferenceHashes()
    {
        // "abc" — NIST SHA-256/SHA-1 and RFC 1321 MD5 vectors.
        byte[] content = "abc"u8.ToArray();
        string path = TempFile(content);
        try
        {
            var result = await HashService.ComputeFileAsync(path, HashAlgorithms.All);

            Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", result.Sha256);
            Assert.Equal("a9993e364706816aba3e25717850c26c9cd0d89d", result.Sha1);
            Assert.Equal("900150983cd24fb0d6963f7d28e17f72", result.Md5);
            Assert.Equal(3, result.FileSize);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Sha256Only_LeavesOthersNull()
    {
        string path = TempFile("hello"u8.ToArray());
        try
        {
            var result = await HashService.ComputeFileAsync(path, HashAlgorithms.Sha256);

            Assert.NotNull(result.Sha256);
            Assert.Null(result.Sha1);
            Assert.Null(result.Md5);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LargeFile_StreamsCorrectly()
    {
        // 5 MiB of patterned data — exercises multi-chunk streaming.
        var content = new byte[5 * 1024 * 1024];
        for (int i = 0; i < content.Length; i++)
        {
            content[i] = (byte)(i % 251);
        }
        string path = TempFile(content);
        try
        {
            var result = await HashService.ComputeFileAsync(path, HashAlgorithms.Sha256);

            Assert.Equal(content.Length, result.FileSize);
            Assert.Equal(64, result.Sha256.Length);
            Assert.Matches("^[0-9a-f]{64}$", result.Sha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Cancellation_ThrowsOperationCanceled()
    {
        var content = new byte[8 * 1024 * 1024];
        string path = TempFile(content);
        try
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                HashService.ComputeFileAsync(path, HashAlgorithms.All, cancellationToken: cts.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task MissingFile_ThrowsFileNotFound()
    {
        // Parent dir exists (temp), file itself does not — yields FileNotFoundException.
        string path = Path.Combine(Path.GetTempPath(), $"sentinel-missing-{Guid.NewGuid():n}.bin");
        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            HashService.ComputeFileAsync(path));
    }

    [Fact]
    public async Task NullPath_ThrowsArgument()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            HashService.ComputeFileAsync("   "));
    }

    [Fact]
    public async Task Progress_ReportsMonotonicValues()
    {
        var content = new byte[2 * 1024 * 1024];
        string path = TempFile(content);
        try
        {
            var seen = new List<double>();
            var progress = new Progress<double>(v => seen.Add(v));

            await HashService.ComputeFileAsync(path, HashAlgorithms.Sha256, progress);

            Assert.NotEmpty(seen);
            Assert.All(seen, v => Assert.InRange(v, 0.0, 1.0));
            Assert.Equal(seen.OrderBy(v => v), seen); // monotonic
        }
        finally
        {
            File.Delete(path);
        }
    }
}