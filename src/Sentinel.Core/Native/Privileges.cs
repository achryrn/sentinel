using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Sentinel.Core.Native;

/// <summary>
/// Enables the Windows privileges an endpoint scanner needs for SYSTEM-WIDE
/// visibility (the same privileges real AVs hold):
///
///   SeDebugPrivilege       - open other processes (VM_READ / query / dump)
///   SeBackupPrivilege      - traverse/read files regardless of ACL
///   SeRestorePrivilege     - write/restore file data (quarantine restore under ACLs)
///   SeTakeOwnershipPrivilege - take ownership of files for inspection
///   SeSecurityPrivilege    - read security audit logs / SACL
///
/// Strictly read/inspection oriented: nothing here modifies processes or memory.
/// Requires elevation (Administrator) or LocalSystem; when unavailable the
/// scanners degrade gracefully (access-denied is reported, never bypassed).
/// </summary>
public static class Privileges
{
    private const uint SePrivilegeEnabled = 0x00000002;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;

    public const string SeDebug = "SeDebugPrivilege";
    public const string SeBackup = "SeBackupPrivilege";
    public const string SeRestore = "SeRestorePrivilege";
    public const string SeTakeOwnership = "SeTakeOwnershipPrivilege";
    public const string SeSecurity = "SeSecurityPrivilege";

    /// <summary>All privileges the scanner uses for deep inspection.</summary>
    public static readonly string[] ScannerPrivileges = [SeDebug, SeBackup, SeRestore, SeTakeOwnership, SeSecurity];

    /// <summary>True when the current process is elevated (Administrator token).</summary>
    public static bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    /// <summary>
    /// Attempts to enable each named privilege on the current process token.
    /// Returns the names that were successfully enabled. Callers log the result;
    /// a non-elevated process simply gets fewer privileges (and graceful degradation).
    /// </summary>
    public static IReadOnlyList<string> Enable(params string[] privilegeNames)
    {
        var enabled = new List<string>();
        IntPtr token = IntPtr.Zero;
        if (!NativeMethods.OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out token))
        {
            return enabled;
        }
        try
        {
            foreach (string name in privilegeNames)
            {
                if (!LookupPrivilegeValue(null, name, out long luid))
                {
                    continue;
                }
                var tp = new TokenPrivileges
                {
                    PrivilegeCount = 1,
                    Privileges = new LuidAndAttributes
                    {
                        Luid = new Luid { LowPart = (uint)(luid & 0xFFFFFFFFL), HighPart = (int)((ulong)luid >> 32) },
                        Attributes = SePrivilegeEnabled,
                    },
                };
                // AdjustTokenPrivileges sets last error even on success; ERROR_NOT_ALL_ASSIGNED (1300) must be checked.
                Marshal.SetLastPInvokeError(0);
                if (AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    int err = Marshal.GetLastPInvokeError();
                    if (err == 0)
                    {
                        enabled.Add(name);
                    }
                }
            }
        }
        finally
        {
            NativeMethods.CloseHandle(token);
        }
        return enabled;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
        ref TokenPrivileges newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);
}
