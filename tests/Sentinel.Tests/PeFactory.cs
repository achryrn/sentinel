using System.Buffers.Binary;

namespace Sentinel.Tests;

/// <summary>
/// Builds minimal synthetic PE images in memory for parser tests.
/// Safe simulations only — no real binaries, no execution.
/// </summary>
internal static class PeFactory
{
    /// <summary>
    /// Builds a minimal PE32+ (x64) image with one .text section.
    /// </summary>
    /// <param name="timeDateStamp">COFF timestamp; 0 triggers the timestamp-anomaly rule.</param>
    /// <param name="dllCharacteristics">Optional header DLL characteristics (ASLR/NX flags).</param>
    /// <param name="sectionCharacteristics">.text section characteristics.</param>
    /// <param name="sectionData">Raw bytes for the section (defaults to 0x90 NOPs).</param>
    /// <param name="overlayBytes">Extra bytes appended past the last section (overlay).</param>
    public static byte[] BuildPe64(
        uint timeDateStamp = 0x60000000,
        ushort dllCharacteristics = 0x0160, // DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
        uint sectionCharacteristics = 0x60000020, // CODE | EXECUTE | READ
        byte[]? sectionData = null,
        byte[]? overlayBytes = null)
    {
        sectionData ??= new byte[0x100]; // NOP-filled .text
        overlayBytes ??= [];

        const int dosSize = 0x40;
        const int ntHeadersSize = 4 + 20 + 240; // signature + file header + PE32+ optional header
        const int sectionTableSize = 40;
        const int sectionAlignment = 0x1000;
        const int fileAlignment = 0x200;

        int headersSize = dosSize + ntHeadersSize + sectionTableSize;
        int rawSectionSize = (int)Math.Ceiling(sectionData.Length / (double)fileAlignment) * fileAlignment;
        int totalSize = headersSize + rawSectionSize + overlayBytes.Length;

        var buf = new byte[totalSize];

        // ---- DOS header ----
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(0, 2), 0x5A4D); // "MZ"
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x3C, 4), (uint)dosSize); // e_lfanew

        // ---- NT signature ----
        int p = dosSize;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p, 4), 0x00004550); // "PE\0\0"
        p += 4;

        // ---- COFF file header (20 bytes) ----
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p, 2), 0x8664); // Machine AMD64
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 2, 2), 1); // NumberOfSections
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 4, 4), timeDateStamp);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 8, 4), 0); // PointerToSymbolTable
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 12, 4), 0); // NumberOfSymbols
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 16, 2), 240); // SizeOfOptionalHeader
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 18, 2), 0x0022); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        p += 20;

        // ---- PE32+ optional header (240 bytes) ----
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p, 2), 0x20B); // Magic PE32+
        buf[p + 2] = 0; // MajorLinkerVersion
        buf[p + 3] = 0; // MinorLinkerVersion
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 4, 4), 0); // SizeOfCode
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 8, 4), 0); // SizeOfInitializedData
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 12, 4), 0); // SizeOfUninitializedData
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 16, 4), 0x1000); // AddressOfEntryPoint
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 20, 4), 0x1000); // BaseOfCode
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(p + 24, 8), 0x140000000); // ImageBase
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 32, 4), 0x1000); // SectionAlignment
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 36, 4), fileAlignment); // FileAlignment
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 40, 2), 6); // MajorOperatingSystemVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 42, 2), 0); // MinorOperatingSystemVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 44, 2), 6); // MajorImageVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 46, 2), 0); // MinorImageVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 48, 2), 6); // MajorSubsystemVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 50, 2), 0); // MinorSubsystemVersion
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 52, 4), 0); // Win32VersionValue
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 56, 4), 0x2000); // SizeOfImage
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 60, 4), (uint)headersSize); // SizeOfHeaders
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 64, 4), 0); // CheckSum
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 68, 2), 3); // Subsystem: CUI
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 70, 2), dllCharacteristics);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(p + 72, 8), 0x100000); // SizeOfStackReserve
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(p + 80, 8), 0x1000); // SizeOfStackCommit
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(p + 88, 8), 0x100000); // SizeOfHeapReserve
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(p + 96, 8), 0x1000); // SizeOfHeapCommit
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 104, 4), 0); // LoaderFlags
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 108, 4), 16); // NumberOfRvaAndSizes
        // Data directories (16 × 8 bytes) all zero — no imports/exports/TLS/debug.
        // (p + 112 .. p + 240 remain zero)

        // ---- Section table (1 × 40 bytes) ----
        int sec = dosSize + ntHeadersSize;
        ".text\0\0\0"u8.CopyTo(buf.AsSpan(sec, 8)); // name ".text\0\0\0"
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 8, 4), (uint)sectionData.Length); // VirtualSize
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 12, 4), 0x1000); // VirtualAddress
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 16, 4), (uint)rawSectionSize); // SizeOfRawData
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 20, 4), (uint)headersSize); // PointerToRawData
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 24, 4), 0); // PointerToRelocations
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 28, 4), 0); // PointerToLinenumbers
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(sec + 32, 2), 0); // NumberOfRelocations
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(sec + 34, 2), 0); // NumberOfLinenumbers
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 36, 4), sectionCharacteristics);

        // ---- Section raw data ----
        sectionData.CopyTo(buf.AsSpan(headersSize, sectionData.Length));

        // ---- Overlay ----
        if (overlayBytes is { Length: > 0 })
        {
            overlayBytes.CopyTo(buf.AsSpan(headersSize + rawSectionSize, overlayBytes.Length));
        }

        return buf;
    }

    /// <summary>Builds a PE32 (x86) image with one section.</summary>
    public static byte[] BuildPe32(
        uint timeDateStamp = 0x60000000,
        ushort dllCharacteristics = 0x0140, // DYNAMIC_BASE | NX_COMPAT
        uint sectionCharacteristics = 0x60000020)
    {
        const int peSize = 0x40;
        const int ntHeadersSize = 4 + 20 + 224; // PE32 optional header is 224 bytes
        const int sectionTableSize = 40;
        const int fileAlignment = 0x200;
        const int sectionDataLen = 0x100;

        int headersSize = peSize + ntHeadersSize + sectionTableSize;
        int rawSectionSize = (int)Math.Ceiling(sectionDataLen / (double)fileAlignment) * fileAlignment;
        var buf = new byte[headersSize + rawSectionSize];

        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(0, 2), 0x5A4D);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x3C, 4), (uint)peSize);

        int p = peSize;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p, 4), 0x00004550);
        p += 4;

        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p, 2), 0x014C); // Machine I386
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 2, 2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 4, 4), timeDateStamp);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 8, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 12, 4), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 16, 2), 224);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 18, 2), 0x0102); // EXECUTABLE_IMAGE | 32BIT_MACHINE
        p += 20;

        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p, 2), 0x10B); // Magic PE32
        buf[p + 2] = 0;
        buf[p + 3] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 4, 4), 0); // SizeOfCode
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 8, 4), 0); // SizeOfInitializedData
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 12, 4), 0); // SizeOfUninitializedData
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 16, 4), 0x1000); // AddressOfEntryPoint
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 20, 4), 0x1000); // BaseOfCode
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 24, 4), 0x1000); // BaseOfData
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 28, 4), 0x400000); // ImageBase (32-bit)
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 32, 4), 0x1000); // SectionAlignment
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 36, 4), fileAlignment); // FileAlignment
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 40, 2), 6); // MajorOperatingSystemVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 42, 2), 0); // MinorOperatingSystemVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 44, 2), 6); // MajorImageVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 46, 2), 0); // MinorImageVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 48, 2), 6); // MajorSubsystemVersion
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 50, 2), 0); // MinorSubsystemVersion
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 52, 4), 0); // Win32VersionValue
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 56, 4), 0x2000); // SizeOfImage
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 60, 4), (uint)headersSize); // SizeOfHeaders
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 64, 4), 0); // CheckSum
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 68, 2), 3); // Subsystem
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(p + 70, 2), dllCharacteristics); // DllCharacteristics
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 72, 4), 0x100000); // SizeOfStackReserve
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 76, 4), 0x1000); // SizeOfStackCommit
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 80, 4), 0x100000); // SizeOfHeapReserve
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 84, 4), 0x1000); // SizeOfHeapCommit
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 88, 4), 0); // LoaderFlags
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(p + 92, 4), 16); // NumberOfRvaAndSizes
        // Data directories (16 × 8) zeroed.

        int sec = peSize + ntHeadersSize;
        buf.AsSpan(sec, 8).Fill((byte)' ');
        buf[sec + 7] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 8, 4), sectionDataLen);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 12, 4), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 16, 4), (uint)rawSectionSize);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 20, 4), (uint)headersSize);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 24, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 28, 4), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(sec + 32, 2), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(sec + 34, 2), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(sec + 36, 4), sectionCharacteristics);

        return buf;
    }
}