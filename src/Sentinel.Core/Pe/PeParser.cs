namespace Sentinel.Core.Pe;

/// <summary>Outcome of PE parsing.</summary>
public enum PeParseStatus
{
    /// <summary>File parsed successfully as a PE image.</summary>
    Ok,

    /// <summary>File does not start with the MZ magic — not a PE at all.</summary>
    NotPe,

    /// <summary>MZ present but header layout is corrupt (bad e_lfanew, bad signature, truncated, etc.).</summary>
    Corrupt,

    /// <summary>Unsupported machine type or architecture.</summary>
    UnsupportedArchitecture,
}

/// <summary>A parsed PE section.</summary>
public sealed record PeSection
{
    public required string Name { get; init; }
    public required uint VirtualSize { get; init; }
    public required uint VirtualAddress { get; init; }
    public required uint RawSize { get; init; }
    public required uint RawPointer { get; init; }
    public required uint Characteristics { get; init; }

    public bool IsExecutable => (Characteristics & ImageSectionCharacteristics.Executable) != 0;
    public bool IsWritable => (Characteristics & ImageSectionCharacteristics.Writable) != 0;
    public bool IsCode => (Characteristics & ImageSectionCharacteristics.Code) != 0;
    public bool IsInitializedData => (Characteristics & ImageSectionCharacteristics.InitializedData) != 0;
    public bool IsUninitializedData => (Characteristics & ImageSectionCharacteristics.UninitializedData) != 0;

    /// <summary>Shannon entropy (bits/byte) of the raw section data, or null if not computed / unreadable.</summary>
    public double? Entropy { get; init; }

    /// <summary>True when virtual size is far larger than raw size (e.g., unpacking stub grows at runtime).</summary>
    public bool HasRuntimeGrowth => RawSize > 0 && VirtualSize > RawSize * 4;
}

/// <summary>A single import (module + symbol).</summary>
public sealed record PeImport
{
    public required string Module { get; init; }
    public string? Name { get; init; }
    public ushort? Ordinal { get; init; }
    public override string ToString() => Name ?? $"#{Ordinal}";
}

/// <summary>A single exported symbol.</summary>
public sealed record PeExport
{
    public required string Name { get; init; }
    public required uint Rva { get; init; }
    public required ushort Ordinal { get; init; }
}

/// <summary>Result of parsing a PE image. All offsets are bounds-checked during parsing.</summary>
public sealed class PeInfo
{
    public required PeParseStatus Status { get; init; }
    public string? Error { get; init; }

    /// <summary>True when <see cref="Status"/> is <see cref="PeParseStatus.Ok"/>.</summary>
    public bool IsPe => Status == PeParseStatus.Ok;

    // ----- DOS / NT headers -----
    public bool Is64Bit { get; init; }
    public ushort Machine { get; init; }
    public string MachineName { get; init; } = "";
    public uint NumberOfSections { get; init; }
    public uint TimeDateStamp { get; init; }
    public DateTimeOffset? LinkTimeUtc { get; init; }
    public ushort Characteristics { get; init; }
    public ushort DllCharacteristics { get; init; }
    public uint Subsystem { get; init; }
    public uint AddressOfEntryPoint { get; init; }
    public ulong ImageBase { get; init; }
    public uint SizeOfImage { get; init; }
    public uint SizeOfHeaders { get; init; }
    public uint CheckSum { get; init; }
    public uint OptionalHeaderSize { get; init; }

    // ----- data directories -----
    public uint? ExportDirectoryRva { get; init; }
    public uint? ImportDirectoryRva { get; init; }
    public uint? ResourceDirectoryRva { get; init; }
    public uint? TlsDirectoryRva { get; init; }
    public uint? DebugDirectoryRva { get; init; }
    public uint? SecurityDirectoryOffset { get; init; }
    public uint? SecurityDirectorySize { get; init; }

    // ----- parsed content -----
    public IReadOnlyList<PeSection> Sections { get; init; } = [];
    public IReadOnlyList<PeImport> Imports { get; init; } = [];
    public IReadOnlyList<PeExport> Exports { get; init; } = [];
    public IReadOnlyList<string> ResourceTypes { get; init; } = [];
    public IReadOnlyList<uint> TlsCallbacks { get; init; } = [];
    public IReadOnlyList<PeDebugEntry> DebugEntries { get; init; } = [];

    /// <summary>Bytes after the last section's raw data (possible appended payload).</summary>
    public long OverlaySize { get; init; }

    /// <summary>True when a CodeView (PDB) debug entry exists.</summary>
    public bool HasPdb => DebugEntries.Any(d => d.Type == PeDebugType.CodeView);

    /// <summary>Human-readable security feature summary.</summary>
    public bool HasAslr => (DllCharacteristics & ImageDllCharacteristics.DynamicBase) != 0;
    public bool HasNxCompat => (DllCharacteristics & ImageDllCharacteristics.NxCompat) != 0;
    public bool HasSafeSeh => (DllCharacteristics & ImageDllCharacteristics.NoSeh) != 0;
    public bool HasForceIntegrity => (DllCharacteristics & ImageDllCharacteristics.ForceIntegrity) != 0;
    public bool HasGuardCf => (DllCharacteristics & ImageDllCharacteristics.GuardCf) != 0;
    public bool IsDll => (Characteristics & ImageFileCharacteristics.Dll) != 0;

    public string? TimestampAnomaly
    {
        get
        {
            if (TimeDateStamp == 0)
            {
                return "Link timestamp is zero (common with some build tools / reproducible builds).";
            }
            if (TimeDateStamp == 0xFFFFFFFF)
            {
                return "Link timestamp is 0xFFFFFFFF (deliberately invalidated — common with packed/obfuscated binaries).";
            }
            if (LinkTimeUtc is { } t && t > DateTimeOffset.UtcNow.AddDays(1))
            {
                return $"Link timestamp is in the future ({t:u}).";
            }
            return null;
        }
    }
}

public enum PeDebugType
{
    Unknown = 0,
    Coff = 1,
    CodeView = 2,
    Fpo = 3,
    Misc = 4,
    Exception = 5,
    Fixup = 6,
    OmapToSrc = 7,
    OmapFromSrc = 8,
    Borland = 9,
    Reserved = 10,
    Clsid = 11,
    Reproducible = 16,
    EmbeddedPortablePdb = 17,
    PdbChecksum = 19,
}

public sealed record PeDebugEntry
{
    public required PeDebugType Type { get; init; }
    public required uint TimeDateStamp { get; init; }
    public required uint SizeOfData { get; init; }
}

/// <summary>PE image section characteristics constants.</summary>
public static class ImageSectionCharacteristics
{
    public const uint Code = 0x00000020;
    public const uint InitializedData = 0x00000040;
    public const uint UninitializedData = 0x00000080;
    public const uint Executable = 0x20000000;
    public const uint Readable = 0x40000000;
    public const uint Writable = 0x80000000;
}

/// <summary>PE file header characteristics.</summary>
public static class ImageFileCharacteristics
{
    public const ushort Dll = 0x2000;
    public const ushort LargeAddressAware = 0x0020;
}

/// <summary>Optional header DLL characteristics.</summary>
public static class ImageDllCharacteristics
{
    public const ushort HighEntropyVa = 0x0020;
    public const ushort DynamicBase = 0x0040;
    public const ushort ForceIntegrity = 0x0080;
    public const ushort NxCompat = 0x0100;
    public const ushort NoSeh = 0x0400;
    public const ushort NoBind = 0x0800;
    public const ushort AppContainer = 0x1000;
    public const ushort WdmDriver = 0x2000;
    public const ushort GuardCf = 0x4000;
    public const ushort TerminalServerAware = 0x8000;
}

/// <summary>
/// Bounds-checked, fully managed PE parser. Reads DOS/COFF/Optional headers, section table,
/// imports, exports, TLS callbacks, resources, debug directory and overlay. Never executes
/// anything; the file is only read.
/// </summary>
public sealed class PeParser
{
    private const ushort DosMagic = 0x5A4D; // "MZ"
    private const uint PeSignature = 0x00004550; // "PE\0\0"
    private const ushort Magic32 = 0x10B;
    private const ushort Magic64 = 0x20B;
    private const uint MaxSections = 96; // sanity cap (spec allows 96 for 32-bit)
    private const uint MaxImports = 16_384;
    private const uint MaxExports = 65_536;
    private const uint MaxTlsCallbacks = 4096;
    private const uint MaxResourceTypes = 4096;

    public const ushort MachineI386 = 0x014C;
    public const ushort MachineAmd64 = 0x8664;
    public const ushort MachineArm64 = 0xAA64;

    private sealed record Pe32Headers(
        long NtHeaderOffset,
        uint NumberOfSections, uint TimeDateStamp, ushort Characteristics,
        ushort OptionalMagic, ulong ImageBase, uint AddressOfEntryPoint, uint SizeOfImage,
        uint SizeOfHeaders, uint CheckSum, ushort DllCharacteristics, uint Subsystem,
        uint OptionalHeaderSize, uint[] DirectoryRvas, uint[] DirectorySizes);

    /// <summary>Parses a PE file from disk.</summary>
    public static PeInfo Parse(string path, bool computeSectionEntropy = true, int maxEntropyPerSection = 8 * 1024 * 1024)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
        return Parse(fs, computeSectionEntropy, maxEntropyPerSection);
    }

    /// <summary>Parses a PE image from an open stream (read from current position).</summary>
    public static PeInfo Parse(Stream stream, bool computeSectionEntropy = true, int maxEntropyPerSection = 8 * 1024 * 1024)
    {
        ArgumentNullException.ThrowIfNull(stream);
        long fileLength = stream.Length - stream.Position;

        try
        {
            // ---- DOS header ----
            if (fileLength < 0x40)
            {
                return Fail(PeParseStatus.NotPe, "File is shorter than the DOS header.");
            }

            stream.Position = 0;
            Span<byte> dos = stackalloc byte[0x40];
            ReadExact(stream, dos);
            ushort dosMagic = ReadU16(dos, 0);
            if (dosMagic != DosMagic)
            {
                return Fail(PeParseStatus.NotPe, "File does not start with MZ — not a PE image.");
            }

            int e_lfanew = ReadI32(dos, 0x3C);
            if (e_lfanew <= 0 || e_lfanew + 4 > fileLength)
            {
                return Fail(PeParseStatus.Corrupt, "Invalid e_lfanew offset.");
            }

            // ---- NT headers ----
            stream.Position = e_lfanew;
            Span<byte> ntSig = stackalloc byte[4];
            ReadExact(stream, ntSig);
            if (ReadU32(ntSig, 0) != PeSignature)
            {
                return Fail(PeParseStatus.Corrupt, "PE signature not found at e_lfanew.");
            }

            Span<byte> fileHeader = stackalloc byte[20];
            ReadExact(stream, fileHeader);
            ushort machine = ReadU16(fileHeader, 0);
            ushort numberOfSections = ReadU16(fileHeader, 2);
            uint timeDateStamp = ReadU32(fileHeader, 4);
            ushort characteristics = ReadU16(fileHeader, 18);
            ushort sizeOfOptionalHeader = ReadU16(fileHeader, 16);

            if (numberOfSections == 0 || numberOfSections > MaxSections)
            {
                return Fail(PeParseStatus.Corrupt, $"Unreasonable section count: {numberOfSections}.");
            }
            if (sizeOfOptionalHeader < 2)
            {
                return Fail(PeParseStatus.Corrupt, "Optional header too small.");
            }
            if (machine is not MachineI386 and not MachineAmd64 and not MachineArm64)
            {
                return Fail(PeParseStatus.UnsupportedArchitecture, $"Unsupported machine type 0x{machine:X4}.");
            }

            // ---- Optional header ----
            int optHeaderLen = Math.Min((int)sizeOfOptionalHeader, 256);
        Span<byte> opt = stackalloc byte[optHeaderLen];
            ReadExact(stream, opt);
            ushort magic = ReadU16(opt, 0);
            bool is64 = magic switch
            {
                Magic32 => false,
                Magic64 => true,
                _ => false,
            };
            if (magic is not Magic32 and not Magic64)
            {
                return Fail(PeParseStatus.Corrupt, $"Unknown optional header magic 0x{magic:X4}.");
            }

            // Fields are at the same offsets in PE32 and PE32+ except ImageBase (24+8 vs 28+4)
            // and NumberOfRvaAndSizes (108 vs 92).
            ulong imageBase = is64 ? ReadU64(opt, 24) : ReadU32(opt, 28);
            uint addressOfEntryPoint = ReadU32(opt, 16);
            uint sizeOfImage = ReadU32(opt, 56);
            uint sizeOfHeaders = ReadU32(opt, 60);
            uint checkSum = ReadU32(opt, 64);
            ushort subsystem = ReadU16(opt, 68);
            ushort dllCharacteristics = ReadU16(opt, 70);
            uint numberOfRvaAndSizes = ReadU32(opt, is64 ? 108 : 92);

            if (numberOfRvaAndSizes > 16)
            {
                numberOfRvaAndSizes = 16; // spec caps at 16
            }

            uint[] dirRvas = new uint[16];
            uint[] dirSizes = new uint[16];
            int dirTableOffset = is64 ? 112 : 96;
            for (int i = 0; i < numberOfRvaAndSizes; i++)
            {
                int off = dirTableOffset + i * 8;
                if (off + 8 > opt.Length)
                {
                    break;
                }
                dirRvas[i] = ReadU32(opt, off);
                dirSizes[i] = ReadU32(opt, off + 4);
            }

            var headers = new Pe32Headers(
                e_lfanew, numberOfSections, timeDateStamp, characteristics, magic, imageBase,
                addressOfEntryPoint, sizeOfImage, sizeOfHeaders, checkSum, dllCharacteristics,
                subsystem, sizeOfOptionalHeader, dirRvas, dirSizes);

            // ---- Section table ----
            var sections = ReadSections(stream, headers, fileLength, computeSectionEntropy);
            if (sections.Count == 0)
            {
                return Fail(PeParseStatus.Corrupt, "Section table is empty or unreadable.");
            }

            var overlay = ComputeOverlay(sections, fileLength);

            // ---- Imports / exports / TLS / resources / debug ----
            var imports = ReadImports(stream, headers, sections, fileLength);
            var exports = ReadExports(stream, headers, sections, fileLength);
            var tlsCallbacks = ReadTlsCallbacks(stream, headers, sections, fileLength);
            var resourceTypes = ReadResourceTypes(stream, headers, sections, fileLength);
            var debugEntries = ReadDebugEntries(stream, headers, sections, fileLength);

            DateTimeOffset? linkTime = timeDateStamp is 0 or 0xFFFFFFFF
                ? null
                : DateTimeOffset.FromUnixTimeSeconds(timeDateStamp);

            return new PeInfo
            {
                Status = PeParseStatus.Ok,
                Is64Bit = is64,
                Machine = machine,
                MachineName = MachineName(machine),
                NumberOfSections = numberOfSections,
                TimeDateStamp = timeDateStamp,
                LinkTimeUtc = linkTime,
                Characteristics = characteristics,
                DllCharacteristics = dllCharacteristics,
                Subsystem = subsystem,
                AddressOfEntryPoint = addressOfEntryPoint,
                ImageBase = imageBase,
                SizeOfImage = sizeOfImage,
                SizeOfHeaders = sizeOfHeaders,
                CheckSum = checkSum,
                OptionalHeaderSize = sizeOfOptionalHeader,
                ExportDirectoryRva = dirRvas[0] != 0 ? dirRvas[0] : null,
                ImportDirectoryRva = dirRvas[1] != 0 ? dirRvas[1] : null,
                ResourceDirectoryRva = dirRvas[2] != 0 ? dirRvas[2] : null,
                TlsDirectoryRva = dirRvas[9] != 0 ? dirRvas[9] : null,
                DebugDirectoryRva = dirRvas[6] != 0 ? dirRvas[6] : null,
                SecurityDirectoryOffset = dirRvas[4] != 0 ? dirRvas[4] : null,
                SecurityDirectorySize = dirSizes[4],
                Sections = sections,
                Imports = imports,
                Exports = exports,
                ResourceTypes = resourceTypes,
                TlsCallbacks = tlsCallbacks,
                DebugEntries = debugEntries,
                OverlaySize = overlay,
            };
        }
        catch (EndOfStreamException)
        {
            return Fail(PeParseStatus.Corrupt, "File ended unexpectedly while parsing headers.");
        }
        catch (IOException ex)
        {
            return Fail(PeParseStatus.Corrupt, $"I/O error while parsing: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            return Fail(PeParseStatus.Corrupt, $"Access denied while parsing: {ex.Message}");
        }
    }

    private static PeInfo Fail(PeParseStatus status, string message) => new() { Status = status, Error = message };

    private static string MachineName(ushort machine) => machine switch
    {
        MachineI386 => "x86 (I386)",
        MachineAmd64 => "x64 (AMD64)",
        MachineArm64 => "ARM64",
        _ => $"0x{machine:X4}",
    };

    private static List<PeSection> ReadSections(Stream stream, Pe32Headers h, long fileLength, bool computeSectionEntropy)
    {
        var list = new List<PeSection>((int)h.NumberOfSections);
        // Section table begins right after the optional header:
        // NT header (at h.NtHeaderOffset) = signature(4) + file header(20) + optional header(sizeOfOptionalHeader)
        long sectionTableOffset = h.NtHeaderOffset + 4 + 20 + h.OptionalHeaderSize;

        for (uint i = 0; i < h.NumberOfSections; i++)
        {
            long off = sectionTableOffset + i * 40;
            if (off + 40 > fileLength)
            {
                break;
            }

            stream.Position = off;
            Span<byte> sec = stackalloc byte[40];
            ReadExact(stream, sec);

            string name = ReadAnsi(sec, 0, 8).TrimEnd('\0', ' ');
            uint virtualSize = ReadU32(sec, 8);
            uint virtualAddress = ReadU32(sec, 12);
            uint rawSize = ReadU32(sec, 16);
            uint rawPointer = ReadU32(sec, 20);
            uint characteristics = ReadU32(sec, 36);

            double? entropy = null;
            if (computeSectionEntropy && rawSize > 0 && rawPointer > 0 && rawPointer + rawSize <= fileLength && rawSize <= int.MaxValue)
            {
                // entropy over bounded window for performance
                int readLen = (int)Math.Min(rawSize, 16 * 1024 * 1024);
                var buf = new byte[readLen];
                stream.Position = rawPointer;
                int got = stream.Read(buf, 0, readLen);
                entropy = Hashing.Entropy.ShannonBitsPerByte(buf.AsSpan(0, got));
            }

            list.Add(new PeSection
            {
                Name = name,
                VirtualSize = virtualSize,
                VirtualAddress = virtualAddress,
                RawSize = rawSize,
                RawPointer = rawPointer,
                Characteristics = characteristics,
                Entropy = entropy,
            });
        }

        return list;
    }

    private static long ComputeOverlay(List<PeSection> sections, long fileLength)
    {
        long end = sections.Count == 0 ? 0 : sections.Max(s => (long)s.RawPointer + s.RawSize);
        return Math.Max(0, fileLength - end);
    }

    // ---------- RVA → file offset ----------

    private static long RvaToOffset(uint rva, List<PeSection> sections)
    {
        foreach (var s in sections)
        {
            if (s.RawSize == 0)
            {
                continue;
            }
            uint virtLen = Math.Max(s.VirtualSize, s.RawSize);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + virtLen)
            {
                return s.RawPointer + (rva - s.VirtualAddress);
            }
        }
        return -1;
    }

    private static string? ReadStringAtRva(Stream stream, uint rva, List<PeSection> sections, long fileLength, int maxLen = 1024)
    {
        long off = RvaToOffset(rva, sections);
        if (off < 0 || off >= fileLength)
        {
            return null;
        }

        stream.Position = off;
        int avail = (int)Math.Min(maxLen, fileLength - off);
        Span<byte> buf = stackalloc byte[256];
        var sb = new System.Text.StringBuilder();
        while (avail > 0)
        {
            int take = Math.Min(avail, buf.Length);
            stream.ReadExactly(buf[..take]);
            int end = buf[..take].IndexOf((byte)0);
            int count = end >= 0 ? end : take;
            sb.Append(System.Text.Encoding.ASCII.GetString(buf[..count]));
            if (end >= 0)
            {
                break;
            }
            avail -= take;
            if (sb.Length >= maxLen)
            {
                break;
            }
        }
        return sb.ToString();
    }

    private static bool ReadBytesAtRva(Stream stream, uint rva, List<PeSection> sections, long fileLength, Span<byte> dest)
    {
        long off = RvaToOffset(rva, sections);
        if (off < 0 || off + dest.Length > fileLength)
        {
            return false;
        }
        stream.Position = off;
        ReadExact(stream, dest);
        return true;
    }

    // ---------- Imports ----------

    private static List<PeImport> ReadImports(Stream stream, Pe32Headers h, List<PeSection> sections, long fileLength)
    {
        var result = new List<PeImport>();
        uint dirRva = h.DirectoryRvas[1];
        if (dirRva == 0 || h.DirectorySizes[1] == 0)
        {
            return result;
        }

        const int descriptorSize = 20;
        for (int i = 0; i < MaxImports; i++)
        {
            Span<byte> desc = stackalloc byte[descriptorSize];
            if (!ReadBytesAtRva(stream, dirRva + (uint)(i * descriptorSize), sections, fileLength, desc))
            {
                break;
            }
            uint originalFirstThunk = ReadU32(desc, 0);
            uint nameRva = ReadU32(desc, 12);
            uint firstThunk = ReadU32(desc, 16);
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
            {
                break; // terminator
            }
            if (nameRva == 0)
            {
                continue;
            }

            string? module = ReadStringAtRva(stream, nameRva, sections, fileLength);
            if (module is null)
            {
                continue;
            }

            uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            bool is64 = h.OptionalMagic == Magic64;
            uint thunkSize = is64 ? 8u : 4u;
            ulong ordinalFlag = is64 ? 0x8000000000000000UL : 0x80000000UL;

            for (int t = 0; t < 65536; t++)
            {
                Span<byte> thunkBuf = stackalloc byte[8];
                if (!ReadBytesAtRva(stream, thunkRva + (uint)(t * thunkSize), sections, fileLength, thunkBuf[..(int)thunkSize]))
                {
                    break;
                }
                ulong value = is64 ? ReadU64(thunkBuf, 0) : ReadU32(thunkBuf, 0);
                if (value == 0)
                {
                    break; // end of thunk array
                }
                if ((value & ordinalFlag) != 0)
                {
                    result.Add(new PeImport { Module = module, Ordinal = (ushort)(value & 0xFFFF) });
                }
                else
                {
                    uint hintNameRva = (uint)(value & 0x7FFFFFFF);
                    if (hintNameRva == 0)
                    {
                        continue;
                    }
                    long off = RvaToOffset(hintNameRva, sections);
                    if (off < 0 || off + 2 > fileLength)
                    {
                        continue;
                    }
                    string? func = ReadStringAtRva(stream, hintNameRva + 2, sections, fileLength, 256);
                    result.Add(new PeImport { Module = module, Name = func });
                }
            }
        }

        return result;
    }

    // ---------- Exports ----------

    private static List<PeExport> ReadExports(Stream stream, Pe32Headers h, List<PeSection> sections, long fileLength)
    {
        var result = new List<PeExport>();
        uint dirRva = h.DirectoryRvas[0];
        if (dirRva == 0 || h.DirectorySizes[0] == 0)
        {
            return result;
        }

        Span<byte> dir = stackalloc byte[40];
        if (!ReadBytesAtRva(stream, dirRva, sections, fileLength, dir))
        {
            return result;
        }

        uint numberOfFunctions = ReadU32(dir, 20);
        uint numberOfNames = ReadU32(dir, 24);
        uint addressOfFunctions = ReadU32(dir, 28);
        uint addressOfNames = ReadU32(dir, 32);
        uint addressOfNameOrdinals = ReadU32(dir, 36);

        if (numberOfNames == 0 || numberOfNames > MaxExports)
        {
            return result;
        }

        Span<byte> funcBuf = stackalloc byte[4];
        for (uint i = 0; i < numberOfNames; i++)
        {
            if (!ReadBytesAtRva(stream, addressOfNames + i * 4, sections, fileLength, funcBuf))
            {
                break;
            }
            uint nameRva = ReadU32(funcBuf, 0);
            string? name = ReadStringAtRva(stream, nameRva, sections, fileLength, 256);
            if (name is null)
            {
                continue;
            }

            ushort ordinal = 0xFFFF;
            if (i < numberOfFunctions)
            {
                Span<byte> ordBuf = stackalloc byte[2];
                if (ReadBytesAtRva(stream, addressOfNameOrdinals + i * 2, sections, fileLength, ordBuf))
                {
                    ordinal = ReadU16(ordBuf, 0);
                }
            }

            uint funcRva = 0;
            if (ordinal < numberOfFunctions)
            {
                Span<byte> f = stackalloc byte[4];
                if (ReadBytesAtRva(stream, addressOfFunctions + (uint)ordinal * 4, sections, fileLength, f))
                {
                    funcRva = ReadU32(f, 0);
                }
            }

            result.Add(new PeExport { Name = name, Rva = funcRva, Ordinal = ordinal });
        }

        return result;
    }

    // ---------- TLS callbacks ----------

    private static List<uint> ReadTlsCallbacks(Stream stream, Pe32Headers h, List<PeSection> sections, long fileLength)
    {
        var result = new List<uint>();
        uint dirRva = h.DirectoryRvas[9];
        if (dirRva == 0 || h.DirectorySizes[9] == 0)
        {
            return result;
        }

        bool is64 = h.OptionalMagic == Magic64;
        int dirSize = is64 ? 40 : 24;
        Span<byte> dir = stackalloc byte[40];
        if (!ReadBytesAtRva(stream, dirRva, sections, fileLength, dir[..dirSize]))
        {
            return result;
        }

        uint callbacksRva = is64 ? ReadU32(dir, 24) : ReadU32(dir, 12);
        if (callbacksRva == 0)
        {
            return result;
        }

        for (int i = 0; i < MaxTlsCallbacks; i++)
        {
            Span<byte> cb = stackalloc byte[8];
            if (!ReadBytesAtRva(stream, callbacksRva + (uint)(i * (is64 ? 8 : 4)), sections, fileLength, cb[..(is64 ? 8 : 4)]))
            {
                break;
            }
            ulong value = is64 ? ReadU64(cb, 0) : ReadU32(cb, 0);
            if (value == 0)
            {
                break;
            }
            result.Add((uint)(value & 0xFFFFFFFF));
        }

        return result;
    }

    // ---------- Resources (top-level types only) ----------

    private static List<string> ReadResourceTypes(Stream stream, Pe32Headers h, List<PeSection> sections, long fileLength)
    {
        var result = new List<string>();
        uint dirRva = h.DirectoryRvas[2];
        if (dirRva == 0 || h.DirectorySizes[2] == 0)
        {
            return result;
        }

        Span<byte> root = stackalloc byte[16];
        if (!ReadBytesAtRva(stream, dirRva, sections, fileLength, root))
        {
            return result;
        }

        uint namedEntries = ReadU16(root, 12);
        uint idEntries = ReadU16(root, 14);
        if (namedEntries + idEntries > MaxResourceTypes)
        {
            return result;
        }

        for (uint i = 0; i < namedEntries + idEntries; i++)
        {
            Span<byte> entry = stackalloc byte[8];
            if (!ReadBytesAtRva(stream, dirRva + 16 + i * 8, sections, fileLength, entry))
            {
                break;
            }
            uint nameId = ReadU32(entry, 0);
            if ((nameId & 0x80000000) != 0)
            {
                string? name = ReadStringAtRva(stream, nameId & 0x7FFFFFFF, sections, fileLength, 64);
                if (name is not null)
                {
                    result.Add(name);
                }
            }
            else
            {
                result.Add(nameId switch
                {
                    1 => "CURSOR",
                    2 => "BITMAP",
                    3 => "ICON",
                    4 => "MENU",
                    5 => "DIALOG",
                    6 => "STRING",
                    7 => "FONTDIR",
                    8 => "FONT",
                    9 => "ACCELERATOR",
                    10 => "RCDATA",
                    11 => "MESSAGETABLE",
                    12 => "GROUP_CURSOR",
                    14 => "GROUP_ICON",
                    16 => "VERSION",
                    17 => "DLGINCLUDE",
                    19 => "PLUGPLAY",
                    20 => "VXD",
                    21 => "ANICURSOR",
                    22 => "ANIICON",
                    23 => "HTML",
                    24 => "MANIFEST",
                    _ => $"ID_{nameId}",
                });
            }
        }

        return result;
    }

    // ---------- Debug directory ----------

    private static List<PeDebugEntry> ReadDebugEntries(Stream stream, Pe32Headers h, List<PeSection> sections, long fileLength)
    {
        var result = new List<PeDebugEntry>();
        uint dirRva = h.DirectoryRvas[6];
        uint dirSize = h.DirectorySizes[6];
        if (dirRva == 0 || dirSize == 0)
        {
            return result;
        }

        const int entrySize = 28;
        uint count = dirSize / entrySize;
        if (count > 1024)
        {
            count = 1024;
        }

        for (uint i = 0; i < count; i++)
        {
            Span<byte> e = stackalloc byte[entrySize];
            if (!ReadBytesAtRva(stream, dirRva + i * entrySize, sections, fileLength, e))
            {
                break;
            }
            uint type = ReadU32(e, 12);
            uint ts = ReadU32(e, 4);
            uint dataSize = ReadU32(e, 16);
            result.Add(new PeDebugEntry
            {
                Type = type switch
                {
                    1 => PeDebugType.Coff,
                    2 => PeDebugType.CodeView,
                    3 => PeDebugType.Fpo,
                    4 => PeDebugType.Misc,
                    5 => PeDebugType.Exception,
                    6 => PeDebugType.Fixup,
                    7 => PeDebugType.OmapToSrc,
                    8 => PeDebugType.OmapFromSrc,
                    9 => PeDebugType.Borland,
                    11 => PeDebugType.Clsid,
                    16 => PeDebugType.Reproducible,
                    17 => PeDebugType.EmbeddedPortablePdb,
                    19 => PeDebugType.PdbChecksum,
                    _ => PeDebugType.Unknown,
                },
                TimeDateStamp = ts,
                SizeOfData = dataSize,
            });
        }

        return result;
    }

    // ---------- binary helpers (little-endian) ----------

    private static void ReadExact(Stream stream, Span<byte> buffer) => stream.ReadExactly(buffer);

    private static ushort ReadU16(ReadOnlySpan<byte> b, int off) => (ushort)(b[off] | (b[off + 1] << 8));

    private static uint ReadU32(ReadOnlySpan<byte> b, int off) =>
        (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));

    private static int ReadI32(ReadOnlySpan<byte> b, int off) => unchecked((int)ReadU32(b, off));

    private static ulong ReadU64(ReadOnlySpan<byte> b, int off) =>
        (ulong)ReadU32(b, off) | ((ulong)ReadU32(b, off + 4) << 32);

    private static string ReadAnsi(ReadOnlySpan<byte> b, int off, int len)
    {
        int end = off;
        while (end < off + len && b[end] != 0)
        {
            end++;
        }
        return System.Text.Encoding.ASCII.GetString(b[off..end]);
    }
}
