using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Sentinel.Core.Native;

namespace Sentinel.Setup;

/// <summary>
/// Production installer for Sentinel. Default (no args) installs the service
/// and components; self-elevates via UAC when needed. Supported switches:
///   --install            install (default)
///   --uninstall          stop/remove the service and all installed files
///   --install-dir <dir>  override target directory (testing)
///   --no-service         test mode: copy files only, no service/registry
///   --help               this text
/// </summary>
internal static class Program
{
    private const string ServiceName = "Sentinel";
    private const string ServiceDisplay = "Sentinel Endpoint Security Scanner";
    private const string Version = "1.0.0";
    private const uint ServiceControlStop = 0x00000001;
    private const int ServiceTypeWin32OwnProcess = 0x00000010;

    private static string DefaultInstallDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Sentinel");

    private static string UninstallKeyPath =>
        @"Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinel";

    private static int Main(string[] args)
    {
        try
        {
            bool help = args.Any(a => a is "--help" or "-h" or "/?");
            bool uninstall = args.Any(a => a is "--uninstall" or "-u");
            bool noService = args.Any(a => a == "--no-service");
            string installDir = Arg(args, "--install-dir") ?? DefaultInstallDir;

            if (help)
            {
                PrintUsage();
                return 0;
            }
            if (uninstall)
            {
                if (noService)
                {
                    throw new InvalidOperationException("--no-service cannot be combined with --uninstall.");
                }
                return RequireElevationAndRun(() => Uninstall(installDir));
            }
            return noService
                ? DoInstall(installDir, noService: true)
                : RequireElevationAndRun(() => DoInstall(installDir, noService: false));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAILED: " + ex.Message);
            return 1;
        }
    }

    private static int RequireElevationAndRun(Func<int> action)
    {
        if (IsElevated())
        {
            return action();
        }
        Console.WriteLine("Requesting administrator privileges (UAC)...");
        var psi = new ProcessStartInfo
        {
            FileName = Environment.ProcessPath!,
            UseShellExecute = true,
            Verb = "runas",
            Arguments = string.Join(' ', Environment.GetCommandLineArgs().Skip(1).Select(Escape)),
        };
        using var p = Process.Start(psi);
        if (p is null)
        {
            Console.Error.WriteLine("Elevation was declined or could not be started.");
            return 1;
        }
        p.WaitForExit();
        return p.ExitCode;
    }

    private static bool IsElevated()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static int DoInstall(string installDir, bool noService)
    {
        string selfDir = Path.GetDirectoryName(Environment.ProcessPath!)!;
        string root = Path.GetFullPath(Path.Combine(selfDir, ".."));
        string srcService = Path.Combine(root, "service");
        string srcCli = Path.Combine(root, "cli");
        string srcGui = Path.Combine(root, "gui");
        if (!Directory.Exists(srcService) || !Directory.Exists(srcCli) || !Directory.Exists(srcGui))
        {
            Console.Error.WriteLine("Source layout not found next to this exe:");
            Console.Error.WriteLine("  " + srcService);
            Console.Error.WriteLine("  " + srcCli);
            Console.Error.WriteLine("  " + srcGui);
            return 1;
        }
        if (string.Equals(Path.GetFullPath(installDir), root, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Refusing to install over the source tree.");
            return 1;
        }

        Console.WriteLine("Sentinel Setup " + Version);
        Console.WriteLine("  target: " + installDir);

        if (!noService)
        {
            StopServiceIfPresent();
        }

        CopyTree(srcService, Path.Combine(installDir, "service"));
        CopyTree(srcCli, Path.Combine(installDir, "cli"));
        CopyTree(srcGui, Path.Combine(installDir, "gui"));

        if (noService)
        {
            Console.WriteLine("Test mode: files copied, service NOT installed.");
            return 0;
        }

        InstallService(installDir);
        WriteUninstallEntry(installDir);
        CreateStartMenuShortcuts(installDir);

        string guiExe = Path.Combine(installDir, "gui", "Sentinel.Gui.exe");
        string cliExe = Path.Combine(installDir, "cli", "Sentinel.Cli.exe");
        string dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
        Console.WriteLine();
        Console.WriteLine("Install complete.");
        Console.WriteLine("  Files:   " + installDir);
        Console.WriteLine("  Service: " + ServiceName + " (auto start, LocalSystem)");
        Console.WriteLine("  GUI:     " + guiExe);
        Console.WriteLine("  CLI:     " + cliExe);
        Console.WriteLine("  Data:    " + dataDir + " (created on first scan)");
        return 0;
    }

    private static int Uninstall(string installDir)
    {
        Console.WriteLine("Sentinel Setup " + Version);
        Console.WriteLine("  uninstalling...");
        StopServiceIfPresent();
        DeleteStartMenuShortcuts();
        try
        {
            Registry.LocalMachine.DeleteSubKey(UninstallKeyPath, throwOnMissingSubKey: false);
        }
        catch (Exception ex)
        {
            Console.WriteLine("  (warn) uninstall registry entry: " + ex.Message);
        }
        TryDeleteDirectory(installDir);
        Console.WriteLine("Uninstall complete.");
        Console.WriteLine("  Database and quarantine were kept; delete the %ProgramData% Sentinel folder manually if you want them gone.");
        return 0;
    }

    // ---------------- service management ----------------

    private static void StopServiceIfPresent()
    {
        IntPtr scm = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero)
        {
            throw new InvalidOperationException("OpenSCManager failed (Win32 error " + Marshal.GetLastWin32Error() + "). Run as administrator.");
        }
        try
        {
            IntPtr svc = NativeMethods.OpenService(scm, ServiceName, NativeMethods.SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero)
            {
                return;
            }
            try
            {
                var status = new ServiceStatus();
                if (ControlService(svc, ServiceControlStop, ref status))
                {
                    Console.WriteLine("  stopping existing service...");
                    for (int i = 0; i < 30 && status.dwCurrentState != 1; i++)
                    {
                        Thread.Sleep(500);
                        QueryServiceStatus(svc, ref status);
                    }
                }
                if (!NativeMethods.DeleteService(svc))
                {
                    Console.WriteLine("  (warn) DeleteService failed: " + Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                NativeMethods.CloseServiceHandle(svc);
            }
        }
        finally
        {
            NativeMethods.CloseServiceHandle(scm);
        }
    }

    private static void InstallService(string installDir)
    {
        IntPtr scm = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero)
        {
            throw new InvalidOperationException("OpenSCManager failed (Win32 error " + Marshal.GetLastWin32Error() + ").");
        }
        try
        {
            string exe = Path.Combine(installDir, "service", "Sentinel.Service.exe");
            IntPtr svc = NativeMethods.CreateService(
                scm, ServiceName, ServiceDisplay,
                NativeMethods.SERVICE_ALL_ACCESS,
                ServiceTypeWin32OwnProcess,
                NativeMethods.SERVICE_AUTO_START,
                NativeMethods.SERVICE_ERROR_NORMAL,
                exe, null, null, null, null, null);
            if (svc == IntPtr.Zero)
            {
                throw new InvalidOperationException("CreateService failed (Win32 error " + Marshal.GetLastWin32Error() + ").");
            }
            try
            {
                if (!StartService(svc, 0, null))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err != 1053 && err != 1058 && err != 1072)
                    {
                        Console.WriteLine("  (warn) StartService failed: Win32 error " + err);
                    }
                }
                else
                {
                    Console.WriteLine("  service started.");
                }
            }
            finally
            {
                NativeMethods.CloseServiceHandle(svc);
            }
        }
        finally
        {
            NativeMethods.CloseServiceHandle(scm);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public int dwServiceType;
        public int dwCurrentState;
        public int dwControlsAccepted;
        public int dwWin32ExitCode;
        public int dwServiceSpecificExitCode;
        public int dwCheckPoint;
        public int dwWaitHint;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[]? lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr hService, uint dwControl, ref ServiceStatus lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr hService, ref ServiceStatus lpServiceStatus);

    // ---------------- registry / shortcuts ----------------

    private static void WriteUninstallEntry(string installDir)
    {
        using var key = Registry.LocalMachine.CreateSubKey(UninstallKeyPath);
        key.SetValue("DisplayName", ServiceDisplay);
        key.SetValue("DisplayVersion", Version);
        key.SetValue("Publisher", "Sentinel");
        key.SetValue("InstallLocation", installDir);
        string guiExe = Path.Combine(installDir, "gui", "Sentinel.Gui.exe");
        key.SetValue("DisplayIcon", guiExe);
        string q = char.ToString('"');
        key.SetValue("UninstallString", q + Path.Combine(installDir, "tools", "Sentinel.Setup.exe") + q + " --uninstall");
        key.SetValue("NoModify", 1);
        key.SetValue("NoRepair", 1);
        long size = Directory.Exists(installDir)
            ? Directory.EnumerateFiles(installDir, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length)
            : 0;
        key.SetValue("EstimatedSize", Math.Max(1, size / 1024));
    }

    private static void CreateStartMenuShortcuts(string installDir)
    {
        try
        {
            string menu = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs");
            Directory.CreateDirectory(menu);
            string guiExe = Path.Combine(installDir, "gui", "Sentinel.Gui.exe");
            CreateLnk(Path.Combine(menu, "Sentinel.lnk"), guiExe, installDir, ServiceDisplay, args: null);
            string setupExe = Path.Combine(installDir, "tools", "Sentinel.Setup.exe");
            CreateLnk(Path.Combine(menu, "Uninstall Sentinel.lnk"), setupExe, installDir, "Uninstall Sentinel", args: "--uninstall");
        }
        catch (Exception ex)
        {
            Console.WriteLine("  (warn) start menu shortcut: " + ex.Message);
        }
    }

    private static void CreateLnk(string lnkPath, string target, string workDir, string description, string? args)
    {
        dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
        try
        {
            dynamic lnk = shell.CreateShortcut(lnkPath);
            lnk.TargetPath = target;
            lnk.WorkingDirectory = workDir;
            lnk.Description = description;
            if (args is not null)
            {
                lnk.Arguments = args;
            }
            lnk.Save();
        }
        finally
        {
            Marshal.FinalReleaseComObject(shell);
        }
    }

    private static void DeleteStartMenuShortcuts()
    {
        try
        {
            string menu = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Programs");
            foreach (string f in new[] { Path.Combine(menu, "Sentinel.lnk"), Path.Combine(menu, "Uninstall Sentinel.lnk") })
            {
                if (File.Exists(f))
                {
                    File.Delete(f);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("  (warn) removing shortcuts: " + ex.Message);
        }
    }

    // ---------------- file helpers ----------------

    private static void CopyTree(string src, string dst)
    {
        Directory.CreateDirectory(dst);
        foreach (string f in Directory.EnumerateFiles(src))
        {
            string target = Path.Combine(dst, Path.GetFileName(f));
            try
            {
                File.Copy(f, target, overwrite: true);
            }
            catch (IOException)
            {
                Console.WriteLine("  (warn) file in use, skipped: " + Path.GetFileName(f));
            }
        }
        foreach (string d in Directory.EnumerateDirectories(src))
        {
            CopyTree(d, Path.Combine(dst, Path.GetFileName(d)));
        }
    }

    private static void TryDeleteDirectory(string dir)
    {
        if (!Directory.Exists(dir))
        {
            return;
        }
        for (int i = 0; i < 5; i++)
        {
            try
            {
                Directory.Delete(dir, recursive: true);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(500);
            }
            catch (UnauthorizedAccessException)
            {
                Thread.Sleep(500);
            }
        }
        Console.WriteLine("  (warn) some files in " + dir + " are locked; delete them once the service is stopped.");
    }

    private static string? Arg(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static string Escape(string s) => s.Contains(' ') ? char.ToString('"') + s + char.ToString('"') : s;

    private static void PrintUsage()
    {
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        Console.WriteLine("Sentinel Setup " + Version);
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  Sentinel.Setup.exe                install (elevates; service + files + shortcuts)");
        Console.WriteLine("  Sentinel.Setup.exe --uninstall    stop/remove the service and installed files");
        Console.WriteLine("  Sentinel.Setup.exe --install-dir <dir>        target directory (testing)");
        Console.WriteLine("  Sentinel.Setup.exe --no-service               copy files only, no service/registry");
        Console.WriteLine("  Sentinel.Setup.exe --help                     this text");
        Console.WriteLine();
        Console.WriteLine("Installed components:");
        Console.WriteLine("  " + Path.Combine(pf, "Sentinel") + " (service, cli, gui)");
        Console.WriteLine("  " + Path.Combine(pd, "Sentinel") + " - database / rules / quarantine");
    }
}
