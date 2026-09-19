using System.Runtime.InteropServices;
using Sentinel.Core.Hashing;
using Sentinel.Core.Models;
using Sentinel.Core.Native;

namespace Sentinel.Core.Scanning;

/// <summary>
/// Read-only memory analysis: walks the virtual address space of a process with
/// VirtualQueryEx, samples entropy of private executable regions, and enumerates
/// thread start addresses via NtQueryInformationThread. Never writes to or
/// modifies process memory. Dumping uses MiniDumpWriteDump (OS-provided, read-only).
/// </summary>
public sealed class MemoryScanner
{
    /// <summary>Maximum bytes of a region that are read for entropy sampling.</summary>
    public const int MaxEntropySampleBytes = 256 * 1024;

    /// <summary>Regions smaller than this are skipped for entropy sampling.</summary>
    private const int MinEntropySampleBytes = 4096;

    /// <summary>Maximum number of regions reported per process (bounds memory).</summary>
    public const int MaxRegionsPerProcess = 200_000;

    /// <summary>Maximum number of threads inspected per process.</summary>
    public const int MaxThreadsPerProcess = 4096;

    private readonly uint _processAccess;

    public MemoryScanner(bool includeEntropy = true)
    {
        IncludeEntropy = includeEntropy;
        _processAccess = NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ;
    }

    public bool IncludeEntropy { get; }

    /// <summary>
    /// Analyzes the memory of a process. Returns a result with AccessDenied=true
    /// when the process cannot be opened (elevated/PPL processes).
    /// </summary>
    public MemoryAnalysisResult Analyze(uint pid, string processName)
    {
        IntPtr hProcess = NativeMethods.OpenProcess(_processAccess, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            return new MemoryAnalysisResult
            {
                Pid = pid,
                ProcessName = processName,
                AccessDenied = true,
                Error = "Cannot open process for memory inspection (elevated or protected process).",
            };
        }

        try
        {
            var regions = new List<MemoryRegion>(1024);
            long totalPrivate = 0, totalExec = 0, totalPrivateExec = 0;

            nuint address = 0;
            while (true)
            {
                nuint result = NativeMethods.VirtualQueryEx(hProcess, (IntPtr)address, out NativeMethods.MEMORY_BASIC_INFORMATION mbi, (nuint)Marshal.SizeOf<NativeMethods.MEMORY_BASIC_INFORMATION>());
                if (result == 0)
                {
                    break; // end of address space or access denied
                }

                ulong regionSize = (ulong)mbi.RegionSize;
                if (regionSize == 0)
                {
                    break; // safety: avoid infinite loop
                }

                bool committed = mbi.State == NativeMethods.MEM_COMMIT;
                bool isPrivate = mbi.Type == NativeMethods.MEM_PRIVATE;
                bool isImage = mbi.Type == NativeMethods.MEM_IMAGE;
                bool isMapped = mbi.Type == NativeMethods.MEM_MAPPED;
                uint protect = mbi.Protect & 0xFF; // strip PAGE_GUARD/NOCACHE bits for classification
                bool isExec = (protect & (NativeMethods.PAGE_EXECUTE | NativeMethods.PAGE_EXECUTE_READ | NativeMethods.PAGE_EXECUTE_READWRITE | NativeMethods.PAGE_EXECUTE_WRITECOPY)) != 0;
                bool isWritable = (protect & (NativeMethods.PAGE_READWRITE | NativeMethods.PAGE_WRITECOPY | NativeMethods.PAGE_EXECUTE_READWRITE | NativeMethods.PAGE_EXECUTE_WRITECOPY)) != 0;
                bool isGuard = (mbi.Protect & NativeMethods.PAGE_GUARD) != 0;

                if (committed)
                {
                    if (isPrivate)
                    {
                        totalPrivate += (long)regionSize;
                    }
                    if (isExec)
                    {
                        totalExec += (long)regionSize;
                    }
                    if (isPrivate && isExec)
                    {
                        totalPrivateExec += (long)regionSize;
                    }
                }

                double? entropy = null;
                if (committed && isPrivate && IncludeEntropy && regionSize >= MinEntropySampleBytes)
                {
                    entropy = SampleEntropy(hProcess, (IntPtr)mbi.BaseAddress, regionSize);
                }

                regions.Add(new MemoryRegion
                {
                    BaseAddress = (ulong)mbi.BaseAddress,
                    RegionSize = regionSize,
                    State = StateName(mbi.State),
                    Type = TypeName(mbi.Type),
                    Protect = ProtectName(mbi.Protect),
                    ProtectRaw = mbi.Protect,
                    IsExecutable = isExec,
                    IsWritable = isWritable,
                    IsGuard = isGuard,
                    IsPrivate = isPrivate,
                    IsImage = isImage,
                    IsMapped = isMapped,
                    Entropy = entropy,
                });

                if (regions.Count >= MaxRegionsPerProcess)
                {
                    break;
                }

                // Advance to the next region.
                nuint next = address + (nuint)regionSize;
                if (next <= address)
                {
                    break; // overflow guard
                }
                address = next;
            }

            var suspiciousRegions = regions
                .Where(r => r.IsPrivate && r.IsExecutable && r.RegionSize >= 4096)
                .ToList();

            var threadStarts = EnumerateThreadStarts(hProcess, pid);
            var suspiciousThreads = threadStarts
                .Where(t => !t.IsInModule && t.StartAddress != 0)
                .ToList();

            return new MemoryAnalysisResult
            {
                Pid = pid,
                ProcessName = processName,
                Regions = regions,
                ThreadStarts = threadStarts,
                SuspiciousRegions = suspiciousRegions,
                SuspiciousThreads = suspiciousThreads,
                TotalPrivateBytes = totalPrivate,
                TotalExecutableBytes = totalExec,
                TotalPrivateExecutableBytes = totalPrivateExec,
                RegionCount = regions.Count,
            };
        }
        catch (Exception ex)
        {
            return new MemoryAnalysisResult
            {
                Pid = pid,
                ProcessName = processName,
                AccessDenied = true,
                Error = ex.Message,
            };
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Dumps a process to a minidump file using MiniDumpWriteDump (read-only).
    /// Protected processes (PPL) will fail with ERROR_ACCESS_DENIED — reported honestly.
    /// </summary>
    public MemoryDumpResult Dump(uint pid, string outputPath, bool fullMemory = false)
    {
        uint dumpType = NativeMethods.MiniDumpNormal
            | NativeMethods.MiniDumpWithDataSegs
            | NativeMethods.MiniDumpWithThreadInfo
            | NativeMethods.MiniDumpWithModuleHeaders
            | NativeMethods.MiniDumpWithProcessThreadData;
        if (fullMemory)
        {
            dumpType |= NativeMethods.MiniDumpWithFullMemory | NativeMethods.MiniDumpWithPrivateReadWriteMemory;
        }

        IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            return new MemoryDumpResult
            {
                Pid = pid,
                Success = false,
                Error = "Cannot open process (access denied — protected/elevated process).",
                IsProtectedProcess = true,
            };
        }

        try
        {
            using var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
            bool ok = NativeMethods.MiniDumpWriteDump(hProcess, pid, fs.SafeFileHandle.DangerousGetHandle(), dumpType, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                return new MemoryDumpResult
                {
                    Pid = pid,
                    Success = false,
                    Error = $"MiniDumpWriteDump failed (Win32 error {err}).",
                    IsProtectedProcess = err == 5, // ERROR_ACCESS_DENIED
                };
            }
            return new MemoryDumpResult
            {
                Pid = pid,
                Success = true,
                OutputPath = outputPath,
                BytesWritten = fs.Length,
            };
        }
        catch (Exception ex)
        {
            return new MemoryDumpResult
            {
                Pid = pid,
                Success = false,
                Error = ex.Message,
            };
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    // ---------------- helpers ----------------

    private static double? SampleEntropy(IntPtr hProcess, IntPtr baseAddress, ulong regionSize)
    {
        int sampleSize = (int)Math.Min(regionSize, MaxEntropySampleBytes);
        var buffer = new byte[sampleSize];
        if (!NativeMethods.ReadProcessMemory(hProcess, baseAddress, buffer, (nuint)sampleSize, out _))
        {
            return null;
        }
        return Entropy.ShannonBitsPerByte(buffer);
    }

    private static IReadOnlyList<ThreadStartInfo> EnumerateThreadStarts(IntPtr hProcess, uint pid)
    {
        var results = new List<ThreadStartInfo>(16);
        try
        {
            IntPtr snap = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPTHREAD, 0);
            if (snap == (IntPtr)NativeMethods.INVALID_HANDLE_VALUE)
            {
                return results;
            }
            try
            {
                var te = new NativeMethods.THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<NativeMethods.THREADENTRY32>() };
                if (!NativeMethods.Thread32First(snap, ref te))
                {
                    return results;
                }
                do
                {
                    if (te.th32OwnerProcessID != pid)
                    {
                        continue;
                    }
                    if (results.Count >= MaxThreadsPerProcess)
                    {
                        break;
                    }
                    IntPtr hThread = NativeMethods.OpenThread(NativeMethods.THREAD_QUERY_LIMITED_INFORMATION, false, te.th32ThreadID);
                    if (hThread == IntPtr.Zero)
                    {
                        continue;
                    }
                    try
                    {
                        int status = NativeMethods.NtQueryInformationThread(hThread, NativeMethods.ThreadQuerySetWin32StartAddress, out IntPtr startAddr, IntPtr.Size, out _);
                        if (status == 0)
                        {
                            results.Add(new ThreadStartInfo
                            {
                                ThreadId = te.th32ThreadID,
                                StartAddress = (ulong)startAddr,
                                ModuleName = null,
                                IsInModule = false,
                                IsInExecutableRegion = false,
                            });
                        }
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(hThread);
                    }
                }
                while (NativeMethods.Thread32Next(snap, ref te));
            }
            finally
            {
                NativeMethods.CloseHandle(snap);
            }
        }
        catch
        {
            // best-effort
        }
        return results;
    }

    private static string StateName(uint state) => state switch
    {
        NativeMethods.MEM_COMMIT => "Commit",
        NativeMethods.MEM_RESERVE => "Reserve",
        NativeMethods.MEM_FREE => "Free",
        _ => $"0x{state:X}",
    };

    private static string TypeName(uint type) => type switch
    {
        NativeMethods.MEM_PRIVATE => "Private",
        NativeMethods.MEM_IMAGE => "Image",
        NativeMethods.MEM_MAPPED => "Mapped",
        _ => "Unknown",
    };

    private static string ProtectName(uint protect)
    {
        uint p = protect & 0xFF;
        string s = p switch
        {
            NativeMethods.PAGE_NOACCESS => "---",
            NativeMethods.PAGE_READONLY => "R--",
            NativeMethods.PAGE_READWRITE => "RW-",
            NativeMethods.PAGE_WRITECOPY => "RWC",
            NativeMethods.PAGE_EXECUTE => "--X",
            NativeMethods.PAGE_EXECUTE_READ => "R-X",
            NativeMethods.PAGE_EXECUTE_READWRITE => "RWX",
            NativeMethods.PAGE_EXECUTE_WRITECOPY => "RXC",
            _ => "???",
        };
        if ((protect & NativeMethods.PAGE_GUARD) != 0)
        {
            s += "+G";
        }
        return s;
    }
}