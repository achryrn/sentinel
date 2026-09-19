using System.Buffers.Binary;
using Sentinel.Core.Pe;

namespace Sentinel.Tests;

public class PeParserTests
{
    private static PeInfo ParseBytes(byte[] bytes, bool computeEntropy = true)
    {
        using var ms = new MemoryStream(bytes);
        return PeParser.Parse(ms, computeEntropy);
    }

    // ---------- happy path ----------

    [Fact]
    public void MinimalPe64_ParsesOk()
    {
        var info = ParseBytes(PeFactory.BuildPe64());

        Assert.Equal(PeParseStatus.Ok, info.Status);
        Assert.True(info.IsPe);
        Assert.True(info.Is64Bit);
        Assert.Equal(PeParser.MachineAmd64, info.Machine);
        Assert.Equal("x64 (AMD64)", info.MachineName);
        Assert.Equal(1u, info.NumberOfSections);
        Assert.Equal(0x1000u, info.AddressOfEntryPoint);
        Assert.Equal(0x140000000UL, info.ImageBase);
        Assert.Equal(3u, info.Subsystem);
        Assert.Single(info.Sections);
        Assert.Equal(".text", info.Sections[0].Name);
        Assert.True(info.Sections[0].IsExecutable);
        Assert.False(info.Sections[0].IsWritable);
        Assert.True(info.Sections[0].IsCode);
        Assert.NotNull(info.LinkTimeUtc);
    }

    [Fact]
    public void MinimalPe64_HasAslrAndNx()
    {
        var info = ParseBytes(PeFactory.BuildPe64(dllCharacteristics: 0x0160));

        Assert.True(info.HasAslr);      // DYNAMIC_BASE
        Assert.True(info.HasNxCompat);  // NX_COMPAT
        Assert.False(info.IsDll);
    }

    [Fact]
    public void Pe64_WithoutMitigations_FlagsMissing()
    {
        var info = ParseBytes(PeFactory.BuildPe64(dllCharacteristics: 0x0000));

        Assert.False(info.HasAslr);
        Assert.False(info.HasNxCompat);
    }

    [Fact]
    public void Pe32_ParsesOk()
    {
        var info = ParseBytes(PeFactory.BuildPe32());

        Assert.Equal(PeParseStatus.Ok, info.Status);
        Assert.False(info.Is64Bit);
        Assert.Equal(PeParser.MachineI386, info.Machine);
        Assert.Equal("x86 (I386)", info.MachineName);
        Assert.Equal(0x400000UL, info.ImageBase);
    }

    [Fact]
    public void SectionEntropy_ComputedForUniformData()
    {
        // 0x00..0xFF repeating → entropy ≈ 8.0.
        var data = new byte[4096];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i % 256);
        }
        var info = ParseBytes(PeFactory.BuildPe64(sectionData: data));

        Assert.Equal(PeParseStatus.Ok, info.Status);
        Assert.NotNull(info.Sections[0].Entropy);
        Assert.InRange(info.Sections[0].Entropy!.Value, 7.9, 8.0);
    }

    [Fact]
    public void SectionEntropy_SkippedWhenDisabled()
    {
        var info = ParseBytes(PeFactory.BuildPe64(), computeEntropy: false);

        Assert.Equal(PeParseStatus.Ok, info.Status);
        Assert.Null(info.Sections[0].Entropy);
    }

    [Fact]
    public void Overlay_Detected()
    {
        var overlay = new byte[512];
        for (int i = 0; i < overlay.Length; i++)
        {
            overlay[i] = 0xCC;
        }
        var info = ParseBytes(PeFactory.BuildPe64(overlayBytes: overlay));

        Assert.Equal(PeParseStatus.Ok, info.Status);
        Assert.Equal(512, info.OverlaySize);
    }

    [Fact]
    public void NoOverlay_Zero()
    {
        var info = ParseBytes(PeFactory.BuildPe64());
        Assert.Equal(0, info.OverlaySize);
    }

    [Fact]
    public void ZeroTimestamp_IsAnomaly()
    {
        var info = ParseBytes(PeFactory.BuildPe64(timeDateStamp: 0));
        Assert.NotNull(info.TimestampAnomaly);
        Assert.Contains("zero", info.TimestampAnomaly, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FutureTimestamp_IsAnomaly()
    {
        uint future = (uint)(DateTimeOffset.UtcNow.AddYears(5).ToUnixTimeSeconds());
        var info = ParseBytes(PeFactory.BuildPe64(timeDateStamp: future));
        Assert.NotNull(info.TimestampAnomaly);
        Assert.Contains("future", info.TimestampAnomaly, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NormalTimestamp_NoAnomaly()
    {
        uint normal = (uint)DateTimeOffset.UtcNow.AddDays(-30).ToUnixTimeSeconds();
        var info = ParseBytes(PeFactory.BuildPe64(timeDateStamp: normal));
        Assert.Null(info.TimestampAnomaly);
    }

    // ---------- malformed inputs ----------

    [Fact]
    public void TooShort_NotPe()
    {
        var info = ParseBytes(new byte[0x20]);
        Assert.Equal(PeParseStatus.NotPe, info.Status);
        Assert.False(info.IsPe);
    }

    [Fact]
    public void NoMzMagic_NotPe()
    {
        var bytes = new byte[0x80];
        bytes[0] = (byte)'X';
        bytes[1] = (byte)'Y';
        var info = ParseBytes(bytes);
        Assert.Equal(PeParseStatus.NotPe, info.Status);
    }

    [Fact]
    public void BadELfanew_Corrupt()
    {
        var bytes = PeFactory.BuildPe64();
        // Point e_lfanew past the end of the file.
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x3C, 4), (uint)bytes.Length + 100);
        var info = ParseBytes(bytes);
        Assert.Equal(PeParseStatus.Corrupt, info.Status);
    }

    [Fact]
    public void MissingPeSignature_Corrupt()
    {
        var bytes = PeFactory.BuildPe64();
        // Overwrite "PE\0\0" with garbage.
        bytes[0x40] = 0x00;
        bytes[0x41] = 0x00;
        bytes[0x42] = 0x00;
        bytes[0x43] = 0x00;
        var info = ParseBytes(bytes);
        Assert.Equal(PeParseStatus.Corrupt, info.Status);
    }

    [Fact]
    public void ZeroSections_Corrupt()
    {
        var bytes = PeFactory.BuildPe64();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x46, 2), 0); // NumberOfSections = 0
        var info = ParseBytes(bytes);
        Assert.Equal(PeParseStatus.Corrupt, info.Status);
    }

    [Fact]
    public void UnsupportedMachine_Corrupt()
    {
        var bytes = PeFactory.BuildPe64();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x44, 2), 0x1234); // Machine = unknown
        var info = ParseBytes(bytes);
        Assert.Equal(PeParseStatus.UnsupportedArchitecture, info.Status);
    }

    [Fact]
    public void NullStream_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => PeParser.Parse((Stream)null!));
    }

    [Fact]
    public void EmptyPath_Throws()
    {
        Assert.Throws<ArgumentException>(() => PeParser.Parse("  "));
    }

    [Fact]
    public void MissingFile_ThrowsFileNotFound()
    {
        // Parent dir exists (temp), file itself does not — yields FileNotFoundException.
        string path = Path.Combine(Path.GetTempPath(), $"sentinel-missing-{Guid.NewGuid():n}.exe");
        Assert.Throws<FileNotFoundException>(() => PeParser.Parse(path));
    }

    // ---------- file-based parse ----------

    [Fact]
    public void ParseFromDisk_MatchesStreamParse()
    {
        string path = Path.Combine(Path.GetTempPath(), $"sentinel-pe-{Guid.NewGuid():n}.exe");
        try
        {
            File.WriteAllBytes(path, PeFactory.BuildPe64());
            var info = PeParser.Parse(path);

            Assert.Equal(PeParseStatus.Ok, info.Status);
            Assert.True(info.Is64Bit);
        }
        finally
        {
            File.Delete(path);
        }
    }
}