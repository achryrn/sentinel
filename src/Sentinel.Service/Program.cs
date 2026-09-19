using System.Runtime.InteropServices;
using System.ServiceProcess;
using Sentinel.Core.Native;
using Sentinel.Service;

namespace Sentinel.Service;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] is "--install" or "-i")
        {
            return InstallService();
        }
        if (args.Length > 0 && args[0] is "--uninstall" or "-u")
        {
            return UninstallService();
        }
        if (args.Length > 0 && args[0] is "--run" or "-r")
        {
            // Run in console mode (debugging without SCM).
            var svc = new SentinelService();
            svc.StartCore();
            Console.WriteLine("Sentinel service running in console mode. Press Ctrl+C to stop.");
            var done = new ManualResetEventSlim(false);
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                done.Set();
            };
            done.Wait();
            svc.StopCore();
            return 0;
        }

        ServiceBase.Run(new ServiceBase[] { new SentinelService() });
        return 0;
    }

    private static int InstallService()
    {
        IntPtr scm = IntPtr.Zero;
        IntPtr svc = IntPtr.Zero;
        try
        {
            scm = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ALL_ACCESS);
            if (scm == IntPtr.Zero)
            {
                Console.Error.WriteLine("Failed to open SCM (run as administrator).");
                return 1;
            }
            string exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                ?? throw new InvalidOperationException("Cannot resolve service executable path.");
            svc = NativeMethods.CreateService(
                scm, "Sentinel", "Sentinel Endpoint Security Scanner",
                NativeMethods.SERVICE_ALL_ACCESS, NativeMethods.SERVICE_WIN32_OWN_PROCESS,
                NativeMethods.SERVICE_AUTO_START, NativeMethods.SERVICE_ERROR_NORMAL,
                exe, null, null, null, null, null);
            if (svc == IntPtr.Zero)
            {
                Console.Error.WriteLine($"Failed to create service (Win32 error {Marshal.GetLastWin32Error()}).");
                return 1;
            }
            Console.WriteLine("Service 'Sentinel' installed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Install failed: {ex.Message}");
            return 1;
        }
        finally
        {
            if (svc != IntPtr.Zero)
            {
                NativeMethods.CloseServiceHandle(svc);
            }
            if (scm != IntPtr.Zero)
            {
                NativeMethods.CloseServiceHandle(scm);
            }
        }
    }

    private static int UninstallService()
    {
        IntPtr scm = IntPtr.Zero;
        IntPtr svc = IntPtr.Zero;
        try
        {
            scm = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ALLOWRE);
            if (scm == IntPtr.Zero)
            {
                Console.Error.WriteLine("Failed to open SCM (run as administrator).");
                return 1;
            }
            svc = NativeMethods.OpenService(scm, "Sentinel", NativeMethods.SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero)
            {
                Console.Error.WriteLine("Service 'Sentinel' not found.");
                return 1;
            }
            if (!NativeMethods.DeleteService(svc))
            {
                Console.Error.WriteLine($"Failed to delete service (Win32 error {Marshal.GetLastWin32Error()}).");
                return 1;
            }
            Console.WriteLine("Service 'Sentinel' uninstalled.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Uninstall failed: {ex.Message}");
            return 1;
        }
        finally
        {
            if (svc != IntPtr.Zero)
            {
                NativeMethods.CloseServiceHandle(svc);
            }
            if (scm != IntPtr.Zero)
            {
                NativeMethods.CloseServiceHandle(scm);
            }
        }
    }
}