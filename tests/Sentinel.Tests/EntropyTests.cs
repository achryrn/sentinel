using Sentinel.Core.Hashing;

namespace Sentinel.Tests;

public class EntropyTests
{
    [Fact]
    public void EmptyBuffer_ReturnsZero()
    {
        Assert.Equal(0, Entropy.ShannonBitsPerByte(ReadOnlySpan<byte>.Empty));
        Assert.Equal(0, Entropy.ShannonBitsPerByte([]));
    }

    [Fact]
    public void SingleByteValue_ReturnsZero()
    {
        // All bytes identical → no uncertainty.
        Assert.Equal(0, Entropy.ShannonBitsPerByte(new byte[] { 0x41, 0x41, 0x41, 0x41 }));
    }

    [Fact]
    public void UniformDistribution_ReturnsEight()
    {
        // All 256 byte values present exactly once → 8 bits/byte.
        var data = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            data[i] = (byte)i;
        }
        Assert.Equal(8.0, Entropy.ShannonBitsPerByte(data), 6);
    }

    [Fact]
    public void HalfDistribution_ReturnsOne()
    {
        // Two symbols, equal probability → 1 bit/byte.
        var data = new byte[1024];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i % 2 == 0 ? 0x00 : 0xFF);
        }
        Assert.Equal(1.0, Entropy.ShannonBitsPerByte(data), 6);
    }

    [Fact]
    public void ByteArrayOverload_RoundsToThreeDecimals()
    {
        var data = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            data[i] = (byte)i;
        }
        Assert.Equal(8.0, Entropy.ShannonBitsPerByte(data));
    }

    [Fact]
    public void HighEntropyThreshold_IsAboveTypicalCompiledCode()
    {
        // Typical compiler output sits well below 7.2 bits/byte.
        Assert.True(Entropy.HighEntropyThreshold > 7.0);
        Assert.True(Entropy.HighEntropyThreshold < 8.0);
    }

    [Fact]
    public async Task ComputeBlockEntropyAsync_ReadsFromCurrentPosition()
    {
        var data = new byte[1000];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i % 256);
        }
        using var ms = new MemoryStream(data);
        ms.Position = 100; // parser-style: start mid-stream

        var blocks = await Entropy.ComputeBlockEntropyAsync(ms, blockSize: 256);

        Assert.Equal(4, blocks.Count); // 900 bytes / 256 → 3 full + 1 partial
        Assert.Equal(100L, blocks[0].Offset);
        Assert.Equal(356L, blocks[1].Offset);
        Assert.Equal(612L, blocks[2].Offset);
        Assert.Equal(868L, blocks[3].Offset);
        Assert.Equal(132, 1000 - blocks[3].Offset); // last block is 132 bytes
        Assert.All(blocks, b => Assert.InRange(b.Entropy, 0, 8));
    }

    [Fact]
    public async Task ComputeBlockEntropyAsync_RespectsMaxBlocks()
    {
        var data = new byte[10_000];
        using var ms = new MemoryStream(data);

        var blocks = await Entropy.ComputeBlockEntropyAsync(ms, blockSize: 100, maxBlocks: 5);

        Assert.Equal(5, blocks.Count);
    }

    [Fact]
    public async Task ComputeBlockEntropyAsync_ThrowsOnInvalidBlockSize()
    {
        using var ms = new MemoryStream([1, 2, 3]);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            Entropy.ComputeBlockEntropyAsync(ms, blockSize: 0));
    }

    [Fact]
    public async Task ComputeBlockEntropyAsync_ThrowsOnNullStream()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Entropy.ComputeBlockEntropyAsync(null!, blockSize: 256));
    }

    [Fact]
    public async Task ComputeBlockEntropyAsync_EmptyStream_ReturnsEmpty()
    {
        using var ms = new MemoryStream();
        var blocks = await Entropy.ComputeBlockEntropyAsync(ms, blockSize: 256);
        Assert.Empty(blocks);
    }
}