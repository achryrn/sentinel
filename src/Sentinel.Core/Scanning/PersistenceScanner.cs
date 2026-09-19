using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Sentinel.Core.Models;
using Sentinel.Core.Native;

namespace Sentinel.Core.Scanning;

/// <summary>
/// Enumerates common persistence mechanisms (the "autoruns" set):
/// Run/RunOnce keys (both hives + Wow6432Node), startup folders, Winlogon
/// Userinit/Shell, IFEO Debugger, AppInit_DLLs, BootExecute, services,
/// scheduled tasks (schtasks), WMI event subscriptions, shell extensions,
/// browser extensions, RDP startup programs and logon scripts.
/// Read-only enumeration; no changes are made.
/// </summary>
public sealed class PersistenceScanner
{
    private static readonly string[] s_runKeyNames = ["Run", "RunOnce"];
    private static readonly string[] s_runKeyPaths =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    private static readonly string[] s_wow6432RunKeyPaths =
    [
        @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    private static readonly string[] s_startupFolders =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.Startup),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup"),
    ];

    private static readonly string[] s_winlogonPaths =
    [
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ];

    private static readonly string[] s_ifeoPaths =
    [
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    ];

    private static readonly string[] s_appInitPaths =
    [
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    ];

    private static readonly string[] s_bootExecutePaths =
    [
        @"SYSTEM\CurrentControlSet\Control\Session Manager",
    ];

    private static readonly string[] s_logonScriptPaths =
    [
        @"Environment",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ];

    private readonly bool _useWmi;

    public PersistenceScanner(bool useWmi = true)
    {
        _useWmi = useWmi;
    }

    /// <summary>Scans all persistence mechanisms and returns the full set.</summary>
    public PersistenceScanResult Scan()
    {
        var entries = new List<PersistenceEntry>(256);
        string? error = null;
        try
        {
            ScanRunKeys(entries);
            ScanStartupFolders(entries);
            ScanWinlogon(entries);
            ScanIfeo(entries);
            ScanAppInit(entries);
            ScanBootExecute(entries);
            ScanServices(entries);
            ScanScheduledTasks(entries);
            if (_useWmi)
            {
                ScanWmiSubscriptions(entries);
            }
            ScanShellExtensions(entries);
            ScanBrowserExtensions(entries);
            ScanRdpStartupPrograms(entries);
            ScanLogonScripts(entries);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }

        return new PersistenceScanResult
        {
            ScannedAtUtc = DateTime.UtcNow,
            Entries = entries,
            Error = error,
        };
    }

    // ---------------- Run keys ----------------

    private void ScanRunKeys(List<PersistenceEntry> entries)
    {
        foreach (string subKey in s_runKeyPaths)
        {
            AddRunKeyEntries(entries, NativeMethods.HKEY_LOCAL_MACHINE, subKey, "HKLM");
            AddRunKeyEntries(entries, NativeMethods.HKEY_CURRENT_USER, subKey, "HKCU");
        }
        // Wow6432Node under HKCU too
        foreach (string subKey in s_wow6432RunKeyPaths)
        {
            AddRunKeyEntries(entries, NativeMethods.HKEY_CURRENT_USER, subKey, "HKCU");
        }
    }

    private static void AddRunKeyEntries(List<PersistenceEntry> entries, IntPtr hive, string subKey, string scope)
    {
        foreach (string valueName in EnumValueNames(hive, subKey))
        {
            string? data = ReadStringValue(hive, subKey, valueName);
            if (string.IsNullOrEmpty(data))
            {
                continue;
            }
            (string command, string? args) = SplitCommand(data);
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.RunKey,
                Name = valueName,
                Location = $"{scope}\\{subKey}",
                Command = command,
                Arguments = args,
                TargetPath = ResolveTarget(command),
                TargetExists = TargetExists(ResolveTarget(command)),
                IsEnabled = true,
                User = scope,
            });
        }
    }

    // ---------------- Startup folders ----------------

    private void ScanStartupFolders(List<PersistenceEntry> entries)
    {
        foreach (string folder in s_startupFolders.Distinct())
        {
            if (!Directory.Exists(folder))
            {
                continue;
            }
            try
            {
                foreach (string file in Directory.EnumerateFiles(folder))
                {
                    string name = Path.GetFileName(file);
                    entries.Add(new PersistenceEntry
                    {
                        Category = PersistenceCategory.StartupFolder,
                        Name = name,
                        Location = folder,
                        Command = file,
                        TargetPath = file,
                        TargetExists = File.Exists(file),
                        IsEnabled = true,
                        User = "user",
                    });
                }
            }
            catch (UnauthorizedAccessException)
            {
                // not accessible (e.g. protected system dirs) - skip
            }
        }
    }

    // ---------------- Winlogon ----------------

    private void ScanWinlogon(List<PersistenceEntry> entries)
    {
        foreach (string subKey in s_winlogonPaths)
        {
            foreach (string valueName in new[] { "Userinit", "Shell" })
            {
                string? data = ReadStringValue(NativeMethods.HKEY_LOCAL_MACHINE, subKey, valueName);
                if (string.IsNullOrEmpty(data))
                {
                    continue;
                }
                foreach (string part in data.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    entries.Add(new PersistenceEntry
                    {
                        Category = PersistenceCategory.Winlogon,
                        Name = valueName,
                        Location = $"HKLM\\{subKey}",
                        Command = part,
                        TargetPath = ResolveTarget(part),
                        TargetExists = TargetExists(ResolveTarget(part)),
                        IsEnabled = true,
                        User = "SYSTEM",
                    });
                }
            }
        }
    }

    // ---------------- IFEO ----------------

    private void ScanIfeo(List<PersistenceEntry> entries)
    {
        foreach (string subKey in s_ifeoPaths)
        {
            foreach (string child in EnumKeyNames(NativeMethods.HKEY_LOCAL_MACHINE, subKey))
            {
                string debugger = ReadStringValue(NativeMethods.HKEY_LOCAL_MACHINE, $@"{subKey}\{child}", "Debugger");
                if (!string.IsNullOrEmpty(debugger))
                {
                    entries.Add(new PersistenceEntry
                    {
                        Category = PersistenceCategory.ImageFileExecutionOptions,
                        Name = child,
                        Location = $"HKLM\\{subKey}\\{child}",
                        Command = debugger,
                        TargetPath = ResolveTarget(debugger),
                        TargetExists = TargetExists(ResolveTarget(debugger)),
                        IsEnabled = true,
                        User = "SYSTEM",
                        Notes = ["IFEO Debugger is a classic malware persistence vector."],
                    });
                }
            }
        }
    }

    // ---------------- AppInit_DLLs ----------------

    private void ScanAppInit(List<PersistenceEntry> entries)
    {
        string? dlls = ReadStringValue(NativeMethods.HKEY_LOCAL_MACHINE, s_appInitPaths[0], "AppInit_DLLs");
        if (string.IsNullOrEmpty(dlls))
        {
            return;
        }
        foreach (string part in dlls.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string path = part.StartsWith("\\\\", StringComparison.Ordinal) ? part : part;
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.AppInitDll,
                Name = "AppInit_DLLs",
                Location = $"HKLM\\{s_appInitPaths[0]}",
                Command = path,
                TargetPath = path,
                TargetExists = TargetExists(path),
                IsEnabled = true,
                User = "SYSTEM",
                Notes = ["AppInit_DLLs loads DLLs into every GUI process."],
            });
        }
    }

    // ---------------- BootExecute ----------------

    private void ScanBootExecute(List<PersistenceEntry> entries)
    {
        string? data = ReadMultiStringValue(NativeMethods.HKEY_LOCAL_MACHINE, s_bootExecutePaths[0], "BootExecute");
        if (string.IsNullOrEmpty(data))
        {
            return;
        }
        foreach (string line in data.Split('\0', StringSplitOptions.RemoveEmptyEntries))
        {
            string trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.Equals("autocheck autochk *", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.BootExecute,
                Name = "BootExecute",
                Location = $"HKLM\\{s_bootExecutePaths[0]}",
                Command = trimmed,
                TargetPath = ResolveTarget(trimmed.Split(' ', 2)[0]),
                TargetExists = true,
                IsEnabled = true,
                User = "SYSTEM",
                Notes = ["Non-standard BootExecute entry."],
            });
        }
    }

    // ---------------- Services ----------------

    private void ScanServices(List<PersistenceEntry> entries)
    {
        const string servicesPath = @"SYSTEM\CurrentControlSet\Services";
        foreach (string serviceName in EnumKeyNames(NativeMethods.HKEY_LOCAL_MACHINE, servicesPath))
        {
            string keyPath = $@"{servicesPath}\{serviceName}";
            uint type = ReadDwordValue(NativeMethods.HKEY_LOCAL_MACHINE, keyPath, "Type");
            uint start = ReadDwordValue(NativeMethods.HKEY_LOCAL_MACHINE, keyPath, "Start");
            string? imagePath = ReadExpandStringValue(NativeMethods.HKEY_LOCAL_MACHINE, keyPath, "ImagePath");
            string? displayName = ReadStringValue(NativeMethods.HKEY_LOCAL_MACHINE, keyPath, "DisplayName");

            // Only kernel drivers (1) and file-system drivers (2) and
            // auto-start (2) / boot-start (0) / system-start (1) services.
            if (start > 2)
            {
                continue;
            }
            if (string.IsNullOrEmpty(imagePath))
            {
                continue;
            }
            string target = ExpandEnvironment(imagePath);
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.Service,
                Name = string.IsNullOrEmpty(displayName) ? serviceName : displayName,
                Location = $"HKLM\\{keyPath}",
                Command = target,
                TargetPath = target,
                TargetExists = TargetExists(target),
                IsEnabled = start == 2 || start == 0 || start == 1,
                User = "SYSTEM",
                Notes = [start == 0 ? "Boot-start service" : start == 1 ? "System-start service" : "Auto-start service"],
            });
        }
    }

    // ---------------- Scheduled tasks ----------------

    private void ScanScheduledTasks(List<PersistenceEntry> entries)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = "/query /fo csv /v",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                },
            };
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(15_000);

            // CSV: TaskName, Next Run Time, Status, Logon Mode, Last Run Time,
            //      Last Result, Author, Task To Run, ...
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (string line in lines.Skip(1))
            {
                string[] fields = SplitCsv(line);
                if (fields.Length < 8)
                {
                    continue;
                }
                string taskName = fields[0];
                string taskToRun = fields[7];
                if (string.IsNullOrEmpty(taskToRun) || taskToRun.Equals("N/A", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                entries.Add(new PersistenceEntry
                {
                    Category = PersistenceCategory.ScheduledTask,
                    Name = taskName,
                    Location = "Task Scheduler",
                    Command = taskToRun,
                    TargetPath = ResolveTarget(taskToRun),
                    TargetExists = TargetExists(ResolveTarget(taskToRun)),
                    IsEnabled = true,
                    User = fields[3] ?? "user",
                });
            }
        }
        catch
        {
            // schtasks not available or failed - best effort
        }
    }

    // ---------------- WMI subscriptions ----------------

    private void ScanWmiSubscriptions(List<PersistenceEntry> entries)
    {
        if (!_useWmi)
        {
            return;
        }
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT * FROM __EventConsumer WHERE __CLASS != 'ActiveScriptEventConsumer'");
            using var consumers = searcher.Get();
            foreach (System.Management.ManagementObject consumer in consumers)
            {
                try
                {
                    string? name = consumer["Name"]?.ToString();
                    string? script = consumer["ScriptText"]?.ToString() ?? consumer["CommandLineTemplate"]?.ToString();
                    entries.Add(new PersistenceEntry
                    {
                        Category = PersistenceCategory.WmiSubscription,
                        Name = name ?? "WMI consumer",
                        Location = "WMI __EventConsumer",
                        Command = script ?? "",
                        TargetPath = null,
                        TargetExists = true,
                        IsEnabled = true,
                        User = "SYSTEM",
                        Notes = ["WMI event subscription is a stealth persistence vector."],
                    });
                }
                catch
                {
                    // individual consumer may be inaccessible
                }
            }
        }
        catch
        {
            // WMI unavailable or access denied (common for elevated consumers)
        }
    }

    // ---------------- Shell extensions ----------------

    private void ScanShellExtensions(List<PersistenceEntry> entries)
    {
        // Context menu handlers and shellex (approved) - approximate:
        foreach (string subKey in new[]
        {
            @"SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
            @"SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
            @"SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers",
        })
        {
            foreach (string child in EnumKeyNames(NativeMethods.HKEY_LOCAL_MACHINE, subKey))
            {
                string clsid = ReadStringValue(NativeMethods.HKEY_LOCAL_MACHINE, $@"{subKey}\{child}", null);
                entries.Add(new PersistenceEntry
                {
                    Category = PersistenceCategory.ShellExtension,
                    Name = child,
                    Location = $"HKLM\\{subKey}\\{child}",
                    Command = clsid ?? "",
                    TargetPath = ResolveClsid(clsid),
                    TargetExists = true,
                    IsEnabled = true,
                    User = "SYSTEM",
                    Notes = ["Shell extension loaded by explorer.exe."],
                });
            }
        }
    }

    // ---------------- Browser extensions ----------------

    private void ScanBrowserExtensions(List<PersistenceEntry> entries)
    {
        // Chrome/Edge extensions are installed in user profile directories.
        string[] browsers =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\Default\Extensions"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data\Default\Extensions"),
        ];
        foreach (string dir in browsers)
        {
            if (!Directory.Exists(dir))
            {
                continue;
            }
            foreach (string ext in Directory.EnumerateDirectories(dir))
            {
                string id = Path.GetFileName(ext);
                entries.Add(new PersistenceEntry
                {
                    Category = PersistenceCategory.BrowserExtension,
                    Name = id,
                    Location = dir,
                    Command = ext,
                    TargetPath = ext,
                    TargetExists = true,
                    IsEnabled = true,
                    User = "user",
                    Notes = ["Browser extension (enabled state not read)."],
                });
            }
        }
    }

    // ---------------- RDP ----------------

    private void ScanRdpStartupPrograms(List<PersistenceEntry> entries)
    {
        string rdpPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup");
        string? startup = ReadStringValue(NativeMethods.HKEY_CURRENT_USER, @"Software\Microsoft\Windows NT\CurrentVersion\Terminal Server", "StartupPrograms");
        if (!string.IsNullOrEmpty(startup))
        {
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.Rdp,
                Name = "RDP StartupPrograms",
                Location = @"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server",
                Command = startup,
                TargetPath = ResolveTarget(startup),
                TargetExists = TargetExists(ResolveTarget(startup)),
                IsEnabled = true,
                User = "user",
                Notes = ["RDP session startup program."],
            });
        }
        _ = rdpPath; // folders covered by ScanStartupFolders
    }

    // ---------------- Logon scripts ----------------

    private void ScanLogonScripts(List<PersistenceEntry> entries)
    {
        string? userinit = ReadStringValue(NativeMethods.HKEY_LOCAL_MACHINE, s_logonScriptPaths[1], "Userinit");
        if (!string.IsNullOrEmpty(userinit))
        {
            foreach (string part in userinit.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                entries.Add(new PersistenceEntry
                {
                    Category = PersistenceCategory.LogonScript,
                    Name = "Userinit",
                    Location = $"HKLM\\{s_logonScriptPaths[1]}",
                    Command = part,
                    TargetPath = ResolveTarget(part),
                    TargetExists = TargetExists(ResolveTarget(part)),
                    IsEnabled = true,
                    User = "SYSTEM",
                });
            }
        }
        string? envUserinit = ReadStringValue(NativeMethods.HKEY_CURRENT_USER, s_logonScriptPaths[0], "UserInitMprLogonScript");
        if (!string.IsNullOrEmpty(envUserinit))
        {
            entries.Add(new PersistenceEntry
            {
                Category = PersistenceCategory.LogonScript,
                Name = "UserInitMprLogonScript",
                Location = @"HKCU\Environment",
                Command = envUserinit,
                TargetPath = ResolveTarget(envUserinit),
                TargetExists = TargetExists(ResolveTarget(envUserinit)),
                IsEnabled = true,
                User = "user",
            });
        }
    }

    // ---------------- registry helpers ----------------

    private static IEnumerable<string> EnumValueNames(IntPtr hive, string subKey)
    {
        if (NativeMethods.RegOpenKeyExW(hive, subKey, 0, NativeMethods.KEY_READ, out IntPtr hKey) != 0)
        {
            yield break;
        }
        try
        {
            uint index = 0;
            while (true)
            {
                var name = new System.Text.StringBuilder(512);
                uint nameLen = (uint)name.Capacity;
                int status = NativeMethods.RegEnumValueW(hKey, index, name, ref nameLen, IntPtr.Zero, out _, IntPtr.Zero, IntPtr.Zero);
                if (status != 0)
                {
                    yield break;
                }
                yield return name.ToString();
                index++;
            }
        }
        finally
        {
            NativeMethods.RegCloseKey(hKey);
        }
    }

    private static IEnumerable<string> EnumKeyNames(IntPtr hive, string subKey)
    {
        if (NativeMethods.RegOpenKeyExW(hive, subKey, 0, NativeMethods.KEY_READ, out IntPtr hKey) != 0)
        {
            yield break;
        }
        try
        {
            uint index = 0;
            while (true)
            {
                var name = new System.Text.StringBuilder(512);
                uint nameLen = (uint)name.Capacity;
                int status = NativeMethods.RegEnumKeyExW(hKey, index, name, ref nameLen, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out _);
                if (status != 0)
                {
                    yield break;
                }
                yield return name.ToString();
                index++;
            }
        }
        finally
        {
            NativeMethods.RegCloseKey(hKey);
        }
    }

    private static string? ReadStringValue(IntPtr hive, string subKey, string? valueName)
    {
        if (NativeMethods.RegOpenKeyExW(hive, subKey, 0, NativeMethods.KEY_READ, out IntPtr hKey) != 0)
        {
            return null;
        }
        try
        {
            uint type = 0;
            uint size = 0;
            if (NativeMethods.RegQueryValueExW(hKey, valueName, IntPtr.Zero, out type, IntPtr.Zero, ref size) != 0 || size == 0)
            {
                return null;
            }
            var buf = new byte[size + 2];
            unsafe
            {
                fixed (byte* p = buf)
                {
                    if (NativeMethods.RegQueryValueExW(hKey, valueName, IntPtr.Zero, out type, (IntPtr)p, ref size) != 0)
                    {
                        return null;
                    }
                }
            }
            if (type == 1 /* REG_SZ */ || type == 2 /* REG_EXPAND_SZ */)
            {
                string s = System.Text.Encoding.Unicode.GetString(buf, 0, (int)size).TrimEnd('\0');
                return s;
            }
            return null;
        }
        finally
        {
            NativeMethods.RegCloseKey(hKey);
        }
    }

    private static string? ReadMultiStringValue(IntPtr hive, string subKey, string? valueName)
    {
        if (NativeMethods.RegOpenKeyExW(hive, subKey, 0, NativeMethods.KEY_READ, out IntPtr hKey) != 0)
        {
            return null;
        }
        try
        {
            uint type = 0;
            uint size = 0;
            if (NativeMethods.RegQueryValueExW(hKey, valueName, IntPtr.Zero, out type, IntPtr.Zero, ref size) != 0 || size == 0)
            {
                return null;
            }
            var buf = new byte[size + 2];
            unsafe
            {
                fixed (byte* p = buf)
                {
                    if (NativeMethods.RegQueryValueExW(hKey, valueName, IntPtr.Zero, out type, (IntPtr)p, ref size) != 0)
                    {
                        return null;
                    }
                }
            }
            if (type == 7 /* REG_MULTI_SZ */)
            {
                return System.Text.Encoding.Unicode.GetString(buf, 0, (int)size);
            }
            return null;
        }
        finally
        {
            NativeMethods.RegCloseKey(hKey);
        }
    }

    private static string? ReadExpandStringValue(IntPtr hive, string subKey, string valueName)
    {
        string? s = ReadStringValue(hive, subKey, valueName);
        return s is null ? null : ExpandEnvironment(s);
    }

    private static uint ReadDwordValue(IntPtr hive, string subKey, string valueName)
    {
        if (NativeMethods.RegOpenKeyExW(hive, subKey, 0, NativeMethods.KEY_READ, out IntPtr hKey) != 0)
        {
            return 0;
        }
        try
        {
            uint type = 0;
            uint size = 4;
            var buf = new byte[4];
            unsafe
            {
                fixed (byte* p = buf)
                {
                    if (NativeMethods.RegQueryValueExW(hKey, valueName, IntPtr.Zero, out type, (IntPtr)p, ref size) != 0)
                    {
                        return 0;
                    }
                }
            }
            return BitConverter.ToUInt32(buf, 0);
        }
        finally
        {
            NativeMethods.RegCloseKey(hKey);
        }
    }

    // ---------------- command parsing ----------------

    private static string ExpandEnvironment(string s)
    {
        try
        {
            return Environment.ExpandEnvironmentVariables(s);
        }
        catch
        {
            return s;
        }
    }

    private static (string Command, string? Args) SplitCommand(string data)
    {
        data = data.Trim();
        if (data.StartsWith('"'))
        {
            int end = data.IndexOf('"', 1);
            if (end > 0)
            {
                string cmd = data[1..end];
                string rest = data[(end + 1)..].Trim();
                return (cmd, rest.Length == 0 ? null : rest);
            }
        }
        int space = data.IndexOf(' ');
        if (space > 0)
        {
            return (data[..space], data[(space + 1)..]);
        }
        return (data, null);
    }

    private static string? ResolveTarget(string? command)
    {
        if (string.IsNullOrEmpty(command))
        {
            return null;
        }
        string trimmed = command.Trim();
        if (trimmed.StartsWith('"'))
        {
            int end = trimmed.IndexOf('"', 1);
            if (end > 0)
            {
                return trimmed[1..end];
            }
        }
        int space = trimmed.IndexOf(' ');
        if (space > 0)
        {
            return trimmed[..space];
        }
        return trimmed;
    }

    private static bool TargetExists(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }
        try
        {
            return File.Exists(path) || Directory.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    private static string? ResolveClsid(string? clsid)
    {
        if (string.IsNullOrEmpty(clsid))
        {
            return null;
        }
        // CLSID → InprocServer32 path
        return ReadStringValue(NativeMethods.HKEY_CLASSES_ROOT, $@"CLSID\{clsid}\InprocServer32", null);
    }

    private static string[] SplitCsv(string line)
    {
        var result = new List<string>(16);
        var current = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (char c in line)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }
        result.Add(current.ToString());
        return result.ToArray();
    }
}