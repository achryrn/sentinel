using System.Runtime.InteropServices;

namespace Sentinel.Core.Native;

/// <summary>
/// Win32 interop declarations used by Sentinel. All declarations are written from
/// scratch for this project against the documented Win32 API surface.
/// </summary>
internal static partial class NativeMethods
{
    // ---------------- kernel32 / toolhelp ----------------

    internal const uint TH32CS_SNAPPROCESS = 0x00000002;
    internal const uint TH32CS_SNAPMODULE = 0x00000008;
    internal const uint TH32CS_SNAPMODULE32 = 0x00000010;
    internal const uint TH32CS_SNAPTHREAD = 0x00000004;
    internal const uint INVALID_HANDLE_VALUE = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    internal struct THREADENTRY32
    {
        internal uint dwSize;
        internal uint cntUsage;
        internal uint th32ThreadID;
        internal uint th32OwnerProcessID;
        internal int tpBasePri;
        internal int tpDeltaPri;
        internal uint dwFlags;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct PROCESSENTRY32W
    {
        internal uint dwSize;
        internal uint cntUsage;
        internal uint th32ProcessID;
        internal IntPtr th32DefaultHeapID;
        internal uint th32ModuleID;
        internal uint cntThreads;
        internal uint th32ParentProcessID;
        internal int pcPriClassBase;
        internal uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string szExeFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct MODULEENTRY32W
    {
        internal uint dwSize;
        internal uint th32ModuleID;
        internal uint th32ProcessID;
        internal uint GlblcntUsage;
        internal uint ProccntUsage;
        internal IntPtr modBaseAddr;
        internal uint modBaseSize;
        internal IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string szExePath;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Module32FirstW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeClientProcessId(IntPtr hNamedPipe, out uint lpClientProcessId);

    // ---------------- service control manager (advapi32) ----------------

    internal const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    internal const uint SC_MANAGER_ALLOWRE = 0x0002; // SC_MANAGER_CONNECT
    internal const uint SERVICE_ALL_ACCESS = 0xF01FF;
    internal const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    internal const uint SERVICE_AUTO_START = 0x00000002;
    internal const uint SERVICE_ERROR_NORMAL = 0x00000001;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr CreateService(
        IntPtr hSCManager, string lpServiceName, string lpDisplayName,
        uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
        string lpBinaryPathName, string? lpLoadOrderGroup, string? lpdwTagId,
        string? lpDependencies, string? lpServiceStartName, string? lpPassword);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseServiceHandle(IntPtr hSCObject);

    // ---------------- process access ----------------

    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    internal const uint PROCESS_QUERY_INFORMATION = 0x0400;
    internal const uint PROCESS_VM_READ = 0x0010;
    internal const uint PROCESS_VM_OPERATION = 0x0008;
    internal const uint PROCESS_VM_WRITE = 0x0020;
    internal const uint PROCESS_TERMINATE = 0x0001;
    internal const uint PROCESS_DUP_HANDLE = 0x0040;
    internal const uint PROCESS_CREATE_THREAD = 0x0002;
    internal const uint PROCESS_SUSPEND_RESUME = 0x0800;
    internal const uint SYNCHRONIZE = 0x00100000;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetProcessTimes(IntPtr hProcess, out long lpCreationTime, out long lpExitTime, out long lpKernelTime, out long lpUserTime);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsWow64Process2(IntPtr hProcess, out ushort pProcessMachine, out ushort pNativeMachine);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint GetProcessId(IntPtr hProcess);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    // ---------------- memory ----------------

    internal const uint MEM_COMMIT = 0x1000;
    internal const uint MEM_RESERVE = 0x2000;
    internal const uint MEM_FREE = 0x10000;
    internal const uint MEM_PRIVATE = 0x20000;
    internal const uint MEM_MAPPED = 0x40000;
    internal const uint MEM_IMAGE = 0x1000000;

    internal const uint PAGE_NOACCESS = 0x01;
    internal const uint PAGE_READONLY = 0x02;
    internal const uint PAGE_READWRITE = 0x04;
    internal const uint PAGE_WRITECOPY = 0x08;
    internal const uint PAGE_EXECUTE = 0x10;
    internal const uint PAGE_EXECUTE_READ = 0x20;
    internal const uint PAGE_EXECUTE_READWRITE = 0x40;
    internal const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    internal const uint PAGE_GUARD = 0x100;
    internal const uint PAGE_NOCACHE = 0x200;

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_BASIC_INFORMATION
    {
        internal IntPtr BaseAddress;
        internal IntPtr AllocationBase;
        internal uint AllocationProtect;
        internal IntPtr RegionSize;
        internal uint State;
        internal uint Protect;
        internal uint Type;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nuint VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesRead);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_INFO
    {
        internal ushort wProcessorArchitecture;
        internal ushort wReserved;
        internal uint dwPageSize;
        internal IntPtr lpMinimumApplicationAddress;
        internal IntPtr lpMaximumApplicationAddress;
        internal IntPtr dwActiveProcessorMask;
        internal uint dwNumberOfProcessors;
        internal uint dwProcessorType;
        internal uint dwAllocationGranularity;
        internal ushort wProcessorLevel;
        internal ushort wProcessorRevision;
    }

    // ---------------- psapi ----------------

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MEMORY_COUNTERS
    {
        internal uint cb;
        internal uint PageFaultCount;
        internal nuint PeakWorkingSetSize;
        internal nuint WorkingSetSize;
        internal nuint QuotaPeakPagedPoolUsage;
        internal nuint QuotaPagedPoolUsage;
        internal nuint QuotaPeakNonPagedPoolUsage;
        internal nuint QuotaNonPagedPoolUsage;
        internal nuint PagefileUsage;
        internal nuint PeakPagefileUsage;
        internal nuint PrivateUsage;
    }

    [LibraryImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetProcessMemoryInfo(IntPtr hProcess, ref PROCESS_MEMORY_COUNTERS ppsmemCounters, uint cb);

    // ---------------- ntdll (thread start address) ----------------

    internal const int ThreadQuerySetWin32StartAddress = 9;
    internal const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

    [LibraryImport("ntdll.dll", SetLastError = true)]
    internal static partial int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass, out IntPtr threadInformation, int threadInformationLength, out int returnLength);

    // ---------------- ntdll (process command line) ----------------

    internal const int ProcessCommandLineInformation = 59;

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        internal IntPtr Buffer;
    }

    [LibraryImport("ntdll.dll", SetLastError = true)]
    internal static partial int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, int processInformationLength, out int returnLength);

    // ---------------- dbghelp (minidump) ----------------

    internal const uint MiniDumpNormal = 0x00000000;
    internal const uint MiniDumpWithDataSegs = 0x00000001;
    internal const uint MiniDumpWithFullMemory = 0x00000002;
    internal const uint MiniDumpWithHandleData = 0x00000004;
    internal const uint MiniDumpWithThreadInfo = 0x00000010;
    internal const uint MiniDumpWithModuleHeaders = 0x00000020;
    internal const uint MiniDumpWithUnloadedModules = 0x00000040;
    internal const uint MiniDumpWithProcessThreadData = 0x00000100;
    internal const uint MiniDumpWithPrivateReadWriteMemory = 0x00000200;

    [LibraryImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool MiniDumpWriteDump(IntPtr hProcess, uint processId, IntPtr hFile, uint dumpType, IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);

    // ---------------- wintrust / crypt32 ----------------

    internal const uint WINTRUST_ACTION_GENERIC_VERIFY_V2 = 0x00AAC56B;
    internal const uint WTD_REVOKE_NONE = 0x00000000;
    internal const uint WTD_CHOICE_FILE = 1;
    internal const uint WTD_STATEACTION_VERIFY = 1;
    internal const uint WTD_STATEACTION_CLOSE = 2;
    internal const uint WTD_UI_NONE = 2;
    internal const uint WTD_PROVIDER_DEFAULT = 0;

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_FILE_INFO
    {
        internal uint cbStruct;
        internal IntPtr pcwszFilePath;
        internal IntPtr hFile;
        internal IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_DATA
    {
        internal uint cbStruct;
        internal IntPtr pPolicyCallbackData;
        internal IntPtr pSIPClientData;
        internal uint dwUIChoice;
        internal uint fdwRevocationChecks;
        internal uint dwUnionChoice;
        internal IntPtr pInfo;
        internal uint dwStateAction;
        internal IntPtr hWVTStateData;
        internal IntPtr pwszURLReference;
        internal uint dwProvFlags;
        internal uint dwUIContext;
    }

    [LibraryImport("wintrust.dll", SetLastError = true)]
    internal static partial int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    internal const uint CERT_QUERY_OBJECT_FILE = 1;
    internal const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10;
    internal const uint CERT_QUERY_FORMAT_FLAG_BINARY = 1;
    internal const uint CMSG_SIGNER_INFO_PARAM = 6;
    internal const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
    internal const uint X509_ASN_ENCODING = 0x00000001;
    internal const uint PKCS_7_ASN_ENCODING = 0x00010000;

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_DATA_BLOB
    {
        internal uint cbData;
        internal IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CMSG_SIGNER_INFO
    {
        internal uint dwVersion;
        internal CRYPT_DATA_BLOB Issuer;
        internal CRYPT_DATA_BLOB SerialNumber;
        internal CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        internal CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
        internal CRYPT_DATA_BLOB EncryptedHash;
        internal CRYPT_ATTRIBUTES AuthAttrs;
        internal CRYPT_ATTRIBUTES UnauthAttrs;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_ALGORITHM_IDENTIFIER
    {
        internal IntPtr pszObjId;
        internal CRYPT_DATA_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_ATTRIBUTES
    {
        internal uint cAttr;
        internal IntPtr rgAttr;
    }

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptQueryObject(uint dwObjectType, IntPtr pvObject, uint dwExpectedContentTypeFlags, uint dwExpectedFormatTypeFlags, uint dwFlags, out uint pdwMsgAndCertEncodingType, out uint pdwContentType, out uint pdwFormatType, out IntPtr phCertStore, out IntPtr phMsg, out IntPtr ppvContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptDecodeObjectEx(uint dwCertEncodingType, IntPtr lpszStructType, byte[] pbEncoded, uint cbEncoded, uint dwFlags, IntPtr pDecodePara, out IntPtr pvStructInfo, out uint pcbStructInfo);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptMsgGetParam(IntPtr hCryptMsg, uint dwParamType, uint dwIndex, byte[]? pvData, ref uint pcbData);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptMsgClose(IntPtr hCryptMsg);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CertFreeCertificateContext(IntPtr pCertContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    internal static partial uint CryptFormatObject(uint dwCertEncodingType, uint dwFormatType, IntPtr lpszStructType, byte[] pbEncoded, uint cbEncoded, byte[]? pbFormat, ref uint pcbFormat);

    [DllImport("crypt32.dll", SetLastError = true)]
    internal static extern uint CertNameToStrW(uint dwCertEncodingType, IntPtr pName, uint dwStrType, System.Text.StringBuilder psz, uint csz);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr LocalFree(IntPtr hMem);

    // ---------------- iphlpapi ----------------

    internal const uint AF_INET = 2;
    internal const uint AF_INET6 = 23;
    internal const uint TCP_TABLE_OWNER_PID_ALL = 5;
    internal const uint UDP_TABLE_OWNER_PID = 1;

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPROW_OWNER_PID
    {
        internal uint state;
        internal uint localAddr;
        internal uint localPort;
        internal uint remoteAddr;
        internal uint remotePort;
        internal uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPTABLE_OWNER_PID
    {
        internal uint dwNumEntries;
        internal MIB_TCPROW_OWNER_PID table;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDPROW_OWNER_PID
    {
        internal uint localAddr;
        internal uint localPort;
        internal uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDPTABLE_OWNER_PID
    {
        internal uint dwNumEntries;
        internal MIB_UDPROW_OWNER_PID table;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] localAddr;
        internal uint localScopeId;
        internal uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] remoteAddr;
        internal uint remoteScopeId;
        internal uint remotePort;
        internal uint state;
        internal uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCP6TABLE_OWNER_PID
    {
        internal uint dwNumEntries;
        internal MIB_TCP6ROW_OWNER_PID table;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] localAddr;
        internal uint localScopeId;
        internal uint localPort;
        internal uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_UDP6TABLE_OWNER_PID
    {
        internal uint dwNumEntries;
        internal MIB_UDP6ROW_OWNER_PID table;
    }

    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    internal static partial uint GetExtendedTcpTable(IntPtr pTcpTable, ref uint pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder, uint ulAf, uint TableClass, uint Reserved);

    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    internal static partial uint GetExtendedUdpTable(IntPtr pUdpTable, ref uint pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder, uint ulAf, uint TableClass, uint Reserved);

    // ---------------- advapi32 / security ----------------

    internal const uint TOKEN_QUERY = 0x0008;
    internal const uint TokenUser = 1;
    internal const uint TokenElevation = 20;
    internal const uint TokenIntegrityLevel = 25;
    internal const uint TokenElevationType = 18;
    internal const uint TokenElevationTypeFull = 1;
    internal const uint TokenElevationTypeLimited = 2;
    internal const uint TokenElevationTypeDefault = 3;

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_ELEVATION
    {
        internal uint TokenIsElevated;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        internal IntPtr Sid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        internal SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_USER
    {
        internal SID_AND_ATTRIBUTES User;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformation(IntPtr tokenHandle, uint tokenInformationClass, IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LookupAccountSidW(IntPtr lpSystemName, IntPtr sid, System.Text.StringBuilder? lpName, ref uint cchName, System.Text.StringBuilder? lpReferencedDomainName, ref uint cchReferencedDomainName, out uint peUse);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    internal static partial uint ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetUserNameW(System.Text.StringBuilder lpBuffer, ref uint pcbBuffer);

    // ---------------- registry notify ----------------

    internal const uint REG_NOTIFY_CHANGE_LAST_SET = 0x00000004;
    internal const uint REG_NOTIFY_CHANGE_NAME = 0x00000001;
    internal const uint REG_NOTIFY_THREAD_AGNOSTIC = 0x10000000;

    [LibraryImport("advapi32.dll", SetLastError = true)]
    internal static partial int RegNotifyChangeKeyValue(IntPtr hKey, [MarshalAs(UnmanagedType.Bool)] bool bWatchSubtree, uint dwNotifyFilter, IntPtr hEvent, [MarshalAs(UnmanagedType.Bool)] bool fAsynchronous);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    internal static partial int RegOpenKeyExW(IntPtr hKey, [MarshalAs(UnmanagedType.LPWStr)] string lpSubKey, uint ulOptions, uint samDesired, out IntPtr phkResult);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    internal static partial int RegCloseKey(IntPtr hKey);

    internal const uint KEY_READ = 0x20019;
    internal const uint KEY_NOTIFY = 0x0010;
    internal static readonly IntPtr HKEY_LOCAL_MACHINE = new(0x80000002);
    internal static readonly IntPtr HKEY_CURRENT_USER = new(0x80000001);
    internal static readonly IntPtr HKEY_CLASSES_ROOT = new(0x80000000);
    internal static readonly IntPtr HKEY_USERS = new(0x80000003);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int RegEnumKeyExW(IntPtr hKey, uint dwIndex, System.Text.StringBuilder lpName, ref uint lpcName, IntPtr lpReserved, IntPtr lpClass, IntPtr lpcClass, out long lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int RegEnumValueW(IntPtr hKey, uint dwIndex, System.Text.StringBuilder lpValueName, ref uint lpcchValueName, IntPtr lpReserved, out uint lpType, IntPtr lpData, IntPtr lpcbData);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    internal static partial int RegQueryValueExW(IntPtr hKey, [MarshalAs(UnmanagedType.LPWStr)] string? lpValueName, IntPtr lpReserved, out uint lpType, IntPtr lpData, ref uint lpcbData);

    // ---------------- file system ----------------

    internal const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    internal const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    internal const uint FILE_READ_ATTRIBUTES = 0x0080;
    internal const uint FILE_LIST_DIRECTORY = 0x0001;
    internal const uint FILE_SHARE_READ = 0x00000001;
    internal const uint FILE_SHARE_WRITE = 0x00000002;
    internal const uint FILE_SHARE_DELETE = 0x00000004;
    internal const uint OPEN_EXISTING = 3;
    internal const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;

    internal const uint FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
    internal const uint FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002;
    internal const uint FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004;
    internal const uint FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
    internal const uint FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010;
    internal const uint FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020;
    internal const uint FILE_NOTIFY_CHANGE_CREATION = 0x00000040;

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_NOTIFY_INFORMATION
    {
        internal uint NextEntryOffset;
        internal uint Action;
        internal uint FileNameLength;
        internal char FileName;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr CreateFileW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ReadDirectoryChangesW(IntPtr hDirectory, byte[] lpBuffer, uint nBufferLength, [MarshalAs(UnmanagedType.Bool)] bool bWatchSubtree, uint dwNotifyFilter, out uint lpBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr FindFirstStreamW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName, uint infoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool FindClose(IntPtr hFindFile);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WIN32_FIND_STREAM_DATA
    {
        internal long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        internal string cStreamName;
    }

    // ---------------- misc ----------------

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint GetCurrentProcessId();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)] string lpLibFileName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool FreeLibrary(IntPtr hLibModule);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint GetLastError();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial void SetLastError(uint dwErrCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string? lpModuleName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

    [StructLayout(LayoutKind.Sequential)]
    internal struct MODULEINFO
    {
        internal IntPtr lpBaseOfDll;
        internal uint SizeOfImage;
        internal IntPtr EntryPoint;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint GetTickCount64();
}