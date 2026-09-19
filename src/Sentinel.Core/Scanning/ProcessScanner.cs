using System.Diagnostics;
using System.Runtime.InteropServices;
using Sentinel.Core.Hashing;
using Sentinel.Core.Models;
using Sentinel.Core.Native;
using Sentinel.Core.Signing;

namespace Sentinel.Core.Scanning;

/// <summary>
/// Enumerates running processes and gathers inspection data for each:
/// identity, parent, command line, user, session, memory counters,
/// loaded modules, and (optionally) main-executable hash + signature.
/// Read-only; never modifies processes or their memory.
/// </summary>
public sealed class ProcessScanner
{
    /// <summary>Maximum number of modules captured per process (bounds work for normal scanning).</summary>
    public const int MaxModulesPerProcess = 512;

    /// <summary>Processes with PIDs below this are kernel/system-owned.</summary>
    private const uint SystemPidThreshold = 8;

    private readonly int _maxHashSizeBytes;

    public ProcessScanner(int maxHashSizeBytes = 512 * 1024 * 1024)
    {
        _maxHashSizeBytes = maxHashSizeBytes;
    }

    /// <summary>
    /// Enumerates all processes. Use <see cref="ScanOneAsync"/> when a single PID is of interest.
    /// </summary>
    public IReadOnlyList<ProcessInfo> ScanAll()
    {
        var results = new List<ProcessInfo>(256);
        using var snap = CreateSnapshot();
        if (snap.IsInvalid)
        {
            return results;
        }

        var entry = new NativeMethods.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32W>() };
        if (!NativeMethods.Process32FirstW(snap.Handle, ref entry))
        {
            return results;
        }

        do
        {
            if (entry.th32ProcessID == 0)
            {
                continue;
            }
            results.Add(Inspect(entry));
        }
        while (NativeMethods.Process32NextW(snap.Handle, ref entry));

        return results;
    }

    /// <summary>
    /// Inspects a single process by PID; returns null if it no longer exists.
    /// </summary>
    public ProcessInfo? ScanOne(uint pid)
    {
        if (pid == 0)
        {
            return null;
        }
        using var snap = CreateSnapshot();
        if (snap.IsInvalid)
        {
            return null;
        }
        var entry = new NativeMethods.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32W>() };
        if (!NativeMethods.Process32FirstW(snap.Handle, ref entry))
        {
            return null;
        }
        do
        {
            if (entry.th32ProcessID == pid)
            {
                return Inspect(entry);
            }
        }
        while (NativeMethods.Process32NextW(snap.Handle, ref entry));
        return null;
    }

    /// <summary>
    /// Compares the Toolhelp32 view with the WMI (Win32_Process) view. PIDs
    /// present in only one view are returned — with SeDebug enabled this is a
    /// credible userland process-hiding check (an invasive program that hides
    /// from one enumeration surface may still be visible via the other).
    /// </summary>
    public Models.ProcessViewDiscrepancy CompareProcessViews()
    {
        var toolhelp = new HashSet<uint>();
        using (var snap = CreateSnapshot())
        {
            if (!snap.IsInvalid)
            {
                var entry = new NativeMethods.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32W>() };
                if (NativeMethods.Process32FirstW(snap.Handle, ref entry))
                {
                    do
                    {
                        if (entry.th32ProcessID != 0)
                        {
                            toolhelp.Add(entry.th32ProcessID);
                        }
                    }
                    while (NativeMethods.Process32NextW(snap.Handle, ref entry));
                }
            }
        }

        var wmi = new HashSet<uint>();
        bool wmiOk = false;
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"root\cimv2", "SELECT ProcessId FROM Win32_Process");
            foreach (var o in searcher.Get())
            {
                using (o)
                {
                    if (o["ProcessId"] is uint pid)
                    {
                        wmi.Add(pid);
                    }
                }
            }
            wmiOk = true;
        }
        catch (System.Management.ManagementException)
        {
        }

        var onlyTool = toolhelp.Except(wmi).OrderBy(p => p).ToList();
        var onlyWmi = wmi.Except(toolhelp).OrderBy(p => p).ToList();
        return new Models.ProcessViewDiscrepancy
        {
            ToolhelpSucceeded = true,
            WmiSucceeded = wmiOk,
            OnlyToolhelpPids = onlyTool,
            OnlyWmiPids = onlyWmi,
        };
    }

    /// <summary>Refreshes full process details for an already-listed process (e.g., after it changed).</summary>
    public async Task<ProcessInfo> AnalyzeAsync(ProcessInfo baseline, bool computeHash = true, CancellationToken ct = default)
    {
        var info = InspectByPid(baseline.Pid, baseline.Name);
        if (info is null)
        {
            return baseline;
        }

        if (computeHash && !string.IsNullOrEmpty(info.ExecutablePath) && File.Exists(info.ExecutablePath))
        {
            var fi = new FileInfo(info.ExecutablePath);
            if (fi.Length <= _maxHashSizeBytes)
            {
                try
                {
                    var hash = await HashService.ComputeFileAsync(info.ExecutablePath, HashAlgorithms.Sha256, cancellationToken: ct).ConfigureAwait(false);
                    info = info with { Sha256 = hash.Sha256 };
                }
                catch
                {
                    // hash failures (locked file, access denied) are informational only
                }
            }
        }
        return info;
    }

    private static SnapshotHandle CreateSnapshot()
    {
        // TH32CS_SNAPPROCESS only: TH32CS_SNAPMODULE requires a valid process id
        // (it fails with ERROR_BAD_LENGTH when pid == 0, which would make the
        // whole snapshot invalid). Modules are enumerated per-process in Inspect.
        IntPtr h = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPPROCESS, 0);
        return new SnapshotHandle(h);
    }

    private ProcessInfo Inspect(in NativeMethods.PROCESSENTRY32W entry)
    {
        uint pid = entry.th32ProcessID;
        string name = entry.szExeFile;

        var notes = new List<string>(4);
        bool elevated = false;
        bool is64Bit = true;
        bool isWow64 = false;
        bool protectedProcess = false;
        string? userName = null;
        string? path = null;
        uint? sessionId = null;
        DateTime? startUtc = null;
        long? ws = null, priv = null;
        int? basePriority = entry.pcPriClassBase;
        uint? threads = entry.cntThreads;
        uint? parentPid = entry.th32ParentProcessID;
        var modules = new List<ProcessModuleInfo>(16);

        IntPtr hProcess = IntPtr.Zero;
        if (pid >= SystemPidThreshold)
        {
            hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION | NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ, false, pid);
        }
        else
        {
            notes.Add("system process (PID < 8)");
        }

        if (hProcess != IntPtr.Zero)
        {
            try
            {
                path = QueryImagePath(hProcess);
                if (string.IsNullOrEmpty(path))
                {
                    path = ResolveFromModuleName(name, pid);
                }

                if (NativeMethods.GetProcessTimes(hProcess, out long creation, out _, out _, out _))
                {
                    try { startUtc = DateTime.FromFileTimeUtc(creation); } catch { startUtc = null; }
                }

                if (NativeMethods.ProcessIdToSessionId(pid, out uint sid))
                {
                    sessionId = sid;
                }

                if (NativeMethods.IsWow64Process2(hProcess, out ushort pMachine, out ushort nMachine))
                {
                    isWow64 = pMachine != 0 && nMachine != 0;
                    is64Bit = nMachine == 0; // native machine 0 means 32-bit OS/process
                }

                var pmc = new NativeMethods.PROCESS_MEMORY_COUNTERS { cb = (uint)Marshal.SizeOf<NativeMethods.PROCESS_MEMORY_COUNTERS>() };
                if (NativeMethods.GetProcessMemoryInfo(hProcess, ref pmc, pmc.cb))
                {
                    ws = (long)pmc.WorkingSetSize;
                    priv = (long)pmc.PrivateUsage;
                }

                var (isElev, tokenUser) = QueryToken(hProcess);
                elevated = isElev;
                if (tokenUser is not null)
                {
                    userName = ResolveUserName(tokenUser.Value);
                    if (userName is null)
                    {
                        notes.Add("token user lookup failed (elevated process)");
                    }
                }

                protectedProcess = IsProtectedProcess(path, name);
                if (protectedProcess)
                {
                    notes.Add("protected process (PPL) - limited visibility");
                }

                EnumerateModules(hProcess, pid, modules);
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }
        else
        {
            notes.Add("cannot open process (access denied or exited)");
        }

        // Command line via NtQueryInformationProcess - independent of the process handle.
        string? cmdline = QueryCommandLine(pid);

        return new ProcessInfo
        {
            Pid = pid,
            Name = name,
            ExecutablePath = path,
            ParentPid = parentPid,
            ParentName = null, // resolved by caller via lookup
            CommandLine = cmdline,
            UserName = userName,
            SessionId = sessionId,
            StartTimeUtc = startUtc,
            WorkingSetBytes = ws,
            PrivateBytes = priv,
            BasePriority = basePriority,
            ThreadCount = threads,
            IsElevated = elevated,
            Is64Bit = is64Bit,
            IsWow64 = isWow64,
            IsProtectedProcess = protectedProcess,
            IsSystemProcess = pid < SystemPidThreshold || string.Equals(name, "System", StringComparison.OrdinalIgnoreCase),
            SignatureStatus = SignatureStatus.Unknown,
            Modules = modules,
            Notes = notes,
        };
    }

    private ProcessInfo? InspectByPid(uint pid, string fallbackName)
    {
        IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION | NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            string? path = QueryImagePath(hProcess);
            var modules = new List<ProcessModuleInfo>(8);
            EnumerateModules(hProcess, pid, modules);
            var pmc = new NativeMethods.PROCESS_MEMORY_COUNTERS { cb = (uint)Marshal.SizeOf<NativeMethods.PROCESS_MEMORY_COUNTERS>() };
            bool memOk = NativeMethods.GetProcessMemoryInfo(hProcess, ref pmc, pmc.cb);
            var (isElev, tokenUser) = QueryToken(hProcess);

            return new ProcessInfo
            {
                Pid = pid,
                Name = fallbackName,
                ExecutablePath = path,
                CommandLine = QueryCommandLine(pid),
                UserName = tokenUser is null ? null : ResolveUserName(tokenUser.Value),
                IsElevated = isElev,
                IsProtectedProcess = IsProtectedProcess(path, fallbackName),
                IsSystemProcess = pid < SystemPidThreshold,
                WorkingSetBytes = memOk ? (long)pmc.WorkingSetSize : null,
                PrivateBytes = memOk ? (long)pmc.PrivateUsage : null,
                Modules = modules,
                Notes = [],
            };
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    // ---------------- helpers ----------------

    private static string? QueryImagePath(IntPtr hProcess)
    {
        var sb = new System.Text.StringBuilder(1024);
        uint size = (uint)sb.Capacity;
        if (NativeMethods.QueryFullProcessImageNameW(hProcess, 0, sb, ref size))
        {
            return sb.ToString();
        }
        return null;
    }

    private static string? ResolveFromModuleName(string name, uint pid)
    {
        // Fallback: find the module path from the snapshot (may fail for elevated processes).
        try
        {
            IntPtr h = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPMODULE | NativeMethods.TH32CS_SNAPMODULE32, pid);
            if (h == (IntPtr)NativeMethods.INVALID_HANDLE_VALUE)
            {
                return null;
            }
            try
            {
                var me = new NativeMethods.MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<NativeMethods.MODULEENTRY32W>() };
                if (NativeMethods.Module32FirstW(h, ref me))
                {
                    do
                    {
                        if (string.Equals(me.szModule, name, StringComparison.OrdinalIgnoreCase))
                        {
                            return me.szExePath;
                        }
                    }
                    while (NativeMethods.Module32NextW(h, ref me));
                }
            }
            finally
            {
                NativeMethods.CloseHandle(h);
            }
        }
        catch
        {
            // best-effort
        }
        return null;
    }

    private static void EnumerateModules(IntPtr hProcess, uint pid, List<ProcessModuleInfo> modules)
    {
        IntPtr h = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPMODULE | NativeMethods.TH32CS_SNAPMODULE32, pid);
        if (h == (IntPtr)NativeMethods.INVALID_HANDLE_VALUE)
        {
            return;
        }
        try
        {
            var me = new NativeMethods.MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<NativeMethods.MODULEENTRY32W>() };
            if (!NativeMethods.Module32FirstW(h, ref me))
            {
                return;
            }
            do
            {
                modules.Add(new ProcessModuleInfo
                {
                    Name = me.szModule,
                    Path = me.szExePath,
                    BaseAddress = (ulong)me.modBaseAddr,
                    Size = me.modBaseSize,
                });
                if (modules.Count >= MaxModulesPerProcess)
                {
                    break;
                }
            }
            while (NativeMethods.Module32NextW(h, ref me));
        }
        finally
        {
            NativeMethods.CloseHandle(h);
        }
    }

    private static string? QueryCommandLine(uint pid)
    {
        IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            // ProcessCommandLineInformation (class 59) is a UNICODE_STRING.
            int status = NativeMethods.NtQueryInformationProcess(hProcess, NativeMethods.ProcessCommandLineInformation, IntPtr.Zero, 0, out int needed);
            if (status != 0 && status != 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */)
            {
                return null;
            }
            int len = needed > 0 ? needed : 0x400;
            if (len <= 0 || len > 64 * 1024)
            {
                return null;
            }
            var buf = Marshal.AllocHGlobal(len);
            try
            {
                status = NativeMethods.NtQueryInformationProcess(hProcess, NativeMethods.ProcessCommandLineInformation, buf, len, out needed);
                if (status != 0)
                {
                    return null;
                }
                var us = Marshal.PtrToStructure<NativeMethods.UNICODE_STRING>(buf);
                if (us.Buffer == IntPtr.Zero || us.Length == 0)
                {
                    return null;
                }
                string cmd = Marshal.PtrToStringUni(us.Buffer, us.Length / 2) ?? string.Empty;
                return string.IsNullOrWhiteSpace(cmd) ? null : cmd.Trim();
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch
        {
            return null;
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    private static (bool Elevated, IntPtr? UserSid) QueryToken(IntPtr hProcess)
    {
        if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out IntPtr token))
        {
            return (false, null);
        }
        try
        {
            bool elevated = false;
            var el = new NativeMethods.TOKEN_ELEVATION();
            int elLen = Marshal.SizeOf<NativeMethods.TOKEN_ELEVATION>();
            IntPtr elBuf = Marshal.AllocHGlobal(elLen);
            try
            {
                if (NativeMethods.GetTokenInformation(token, NativeMethods.TokenElevation, elBuf, (uint)elLen, out _))
                {
                    el = Marshal.PtrToStructure<NativeMethods.TOKEN_ELEVATION>(elBuf);
                    elevated = el.TokenIsElevated != 0;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(elBuf);
            }

            IntPtr? userSid = null;
            int userLen = Marshal.SizeOf<NativeMethods.TOKEN_USER>() + 64;
            IntPtr userBuf = Marshal.AllocHGlobal(userLen);
            try
            {
                if (NativeMethods.GetTokenInformation(token, NativeMethods.TokenUser, userBuf, (uint)userLen, out uint retLen))
                {
                    if (retLen > (uint)userLen)
                    {
                        Marshal.FreeHGlobal(userBuf);
                        userBuf = Marshal.AllocHGlobal((int)retLen);
                        if (!NativeMethods.GetTokenInformation(token, NativeMethods.TokenUser, userBuf, retLen, out _))
                        {
                            return (elevated, null);
                        }
                    }
                    var tu = Marshal.PtrToStructure<NativeMethods.TOKEN_USER>(userBuf);
                    userSid = tu.User.Sid;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(userBuf);
            }
            return (elevated, userSid);
        }
        finally
        {
            NativeMethods.CloseHandle(token);
        }
    }

    private static string? ResolveUserName(IntPtr sid)
    {
        uint nameLen = 0, domLen = 0;
        NativeMethods.LookupAccountSidW(IntPtr.Zero, sid, null, ref nameLen, null, ref domLen, out _);
        if (nameLen == 0)
        {
            return null;
        }
        var name = new System.Text.StringBuilder((int)nameLen + 2);
        var domain = new System.Text.StringBuilder((int)domLen + 2);
        uint n2 = nameLen + 2, d2 = domLen + 2;
        if (!NativeMethods.LookupAccountSidW(IntPtr.Zero, sid, name, ref n2, domain, ref d2, out _))
        {
            return null;
        }
        string n = name.ToString();
        string d = domain.ToString();
        return string.IsNullOrEmpty(d) ? n : $"{d}\\{n}";
    }

    private static bool IsProtectedProcess(string? path, string name)
    {
        // PPL processes (csrss, wininit, services, lsass with RunAsPPL, etc.) fail
        // PROCESS_QUERY_INFORMATION; a handle with only QUERY_LIMITED_INFORMATION
        // usually opens but token query fails. We approximate by checking known
        // protected names and by the fact that token enumeration fails.
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }
        string fileName = Path.GetFileName(path);
        if (string.IsNullOrEmpty(fileName))
        {
            fileName = name;
        }
        return fileName.Equals("csrss.exe", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("wininit.exe", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("services.exe", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase);
    }

    private sealed class SnapshotHandle : IDisposable
    {
        public IntPtr Handle { get; }
        public bool IsInvalid => Handle == IntPtr.Zero || Handle == (IntPtr)NativeMethods.INVALID_HANDLE_VALUE;
        public SnapshotHandle(IntPtr handle) => Handle = handle;
        public void Dispose()
        {
            if (!IsInvalid)
            {
                NativeMethods.CloseHandle(Handle);
            }
        }
    }
}