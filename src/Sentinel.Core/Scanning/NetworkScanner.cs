using System.Net;
using System.Runtime.InteropServices;
using Sentinel.Core.Models;
using Sentinel.Core.Native;

namespace Sentinel.Core.Scanning;

/// <summary>
/// Enumerates TCP/UDP connections (IPv4 + IPv6) with owning PIDs via
/// GetExtendedTcpTable / GetExtendedUdpTable, then resolves process names.
/// Read-only; requires no elevated privileges for one's own processes.
/// </summary>
public sealed class NetworkScanner
{
    /// <summary>Maps a PID to a process name; refreshed per scan.</summary>
    private Dictionary<uint, (string Name, string? Path)> _pidNames = [];

    /// <summary>
    /// Captures a full network snapshot. The PID→name map is resolved once
    /// per snapshot from the current process table.
    /// </summary>
    public NetworkSnapshot Capture()
    {
        RefreshPidNames();

        var connections = new List<NetworkConnection>(512);
        string? error = null;

        try
        {
            CaptureTcp4(connections);
            CaptureTcp6(connections);
            CaptureUdp4(connections);
            CaptureUdp6(connections);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }

        return new NetworkSnapshot
        {
            CapturedAtUtc = DateTime.UtcNow,
            Connections = connections,
            Error = error,
        };
    }

    private void RefreshPidNames()
    {
        var map = new Dictionary<uint, (string, string?)>(256);
        try
        {
            var procs = System.Diagnostics.Process.GetProcesses();
            try
            {
                foreach (var p in procs)
                {
                    try
                    {
                        map[(uint)p.Id] = (p.ProcessName, p.MainModule?.FileName);
                    }
                    catch
                    {
                        map[(uint)p.Id] = (p.ProcessName, null);
                    }
                }
            }
            finally
            {
                foreach (var p in procs)
                {
                    p.Dispose();
                }
            }
        }
        catch
        {
            // fall back to empty map
        }
        _pidNames = map;
    }

    private (string Name, string? Path) NameFor(uint pid) =>
        _pidNames.TryGetValue(pid, out var v) ? v : ($"PID {pid}", null);

    private void CaptureTcp4(List<NetworkConnection> list)
    {
        uint size = 0;
        NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0)
        {
            return;
        }
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try
        {
            uint status = NativeMethods.GetExtendedTcpTable(buf, ref size, false, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
            if (status != 0 /* NO_ERROR */)
            {
                return;
            }
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();
            uint count = (uint)Marshal.ReadInt32(buf);
            // Table layout: DWORD dwNumEntries followed by rows (no padding).
            IntPtr p = buf + 4;
            for (uint i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(p);
                var (name, path) = NameFor(row.owningPid);
                list.Add(new NetworkConnection
                {
                    Protocol = "TCP",
                    LocalAddress = new IPAddress(row.localAddr),
                    LocalPort = PortFromNbo(row.localPort),
                    RemoteAddress = new IPAddress(row.remoteAddr),
                    RemotePort = PortFromNbo(row.remotePort),
                    State = TcpStateName(row.state),
                    OwningPid = row.owningPid,
                    ProcessName = name,
                    ProcessPath = path,
                    IsListening = row.state == 2 /* MIB_TCP_STATE_LISTEN */,
                    IsLoopback = IPAddress.IsLoopback(new IPAddress(row.localAddr)),
                    IsEstablished = row.state == 5 /* MIB_TCP_STATE_ESTAB */,
                });
                p += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private void CaptureTcp6(List<NetworkConnection> list)
    {
        uint size = 0;
        NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0)
        {
            return;
        }
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try
        {
            uint status = NativeMethods.GetExtendedTcpTable(buf, ref size, false, NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
            if (status != 0)
            {
                return;
            }
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCP6ROW_OWNER_PID>();
            uint count = (uint)Marshal.ReadInt32(buf);
            // Table layout: DWORD dwNumEntries followed by the rows (no padding).
            IntPtr p = buf + 4;
            for (uint i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_TCP6ROW_OWNER_PID>(p);
                var (name, path) = NameFor(row.owningPid);
                var local = new IPAddress(row.localAddr!, (long)row.localScopeId);
                var remote = new IPAddress(row.remoteAddr!, (long)row.remoteScopeId);
                list.Add(new NetworkConnection
                {
                    Protocol = "TCP6",
                    LocalAddress = local,
                    LocalPort = PortFromNbo(row.localPort),
                    RemoteAddress = remote,
                    RemotePort = PortFromNbo(row.remotePort),
                    State = TcpStateName(row.state),
                    OwningPid = row.owningPid,
                    ProcessName = name,
                    ProcessPath = path,
                    IsListening = row.state == 2,
                    IsLoopback = IPAddress.IsLoopback(local),
                    IsEstablished = row.state == 5,
                });
                p += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private void CaptureUdp4(List<NetworkConnection> list)
    {
        uint size = 0;
        NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, false, NativeMethods.AF_INET, NativeMethods.UDP_TABLE_OWNER_PID, 0);
        if (size == 0)
        {
            return;
        }
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try
        {
            uint status = NativeMethods.GetExtendedUdpTable(buf, ref size, false, NativeMethods.AF_INET, NativeMethods.UDP_TABLE_OWNER_PID, 0);
            if (status != 0)
            {
                return;
            }
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_UDPROW_OWNER_PID>();
            uint count = (uint)Marshal.ReadInt32(buf);
            // Table layout: DWORD dwNumEntries followed by the rows (no padding).
            IntPtr p = buf + 4;
            for (uint i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_UDPROW_OWNER_PID>(p);
                var (name, path) = NameFor(row.owningPid);
                var local = new IPAddress(row.localAddr);
                list.Add(new NetworkConnection
                {
                    Protocol = "UDP",
                    LocalAddress = local,
                    LocalPort = PortFromNbo(row.localPort),
                    OwningPid = row.owningPid,
                    ProcessName = name,
                    ProcessPath = path,
                    IsListening = true, // UDP sockets are always "bound"
                    IsLoopback = IPAddress.IsLoopback(local),
                    IsEstablished = false,
                });
                p += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private void CaptureUdp6(List<NetworkConnection> list)
    {
        uint size = 0;
        NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, false, NativeMethods.AF_INET6, NativeMethods.UDP_TABLE_OWNER_PID, 0);
        if (size == 0)
        {
            return;
        }
        IntPtr buf = Marshal.AllocHGlobal((int)size);
        try
        {
            uint status = NativeMethods.GetExtendedUdpTable(buf, ref size, false, NativeMethods.AF_INET6, NativeMethods.UDP_TABLE_OWNER_PID, 0);
            if (status != 0)
            {
                return;
            }
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_UDP6ROW_OWNER_PID>();
            uint count = (uint)Marshal.ReadInt32(buf);
            // Table layout: DWORD dwNumEntries followed by the rows (no padding).
            IntPtr p = buf + 4;
            for (uint i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_UDP6ROW_OWNER_PID>(p);
                var (name, path) = NameFor(row.owningPid);
                var local = new IPAddress(row.localAddr!, (long)row.localScopeId);
                list.Add(new NetworkConnection
                {
                    Protocol = "UDP6",
                    LocalAddress = local,
                    LocalPort = PortFromNbo(row.localPort),
                    OwningPid = row.owningPid,
                    ProcessName = name,
                    ProcessPath = path,
                    IsListening = true,
                    IsLoopback = IPAddress.IsLoopback(local),
                    IsEstablished = false,
                });
                p += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>Ports are stored in network byte order (big-endian).</summary>
    private static int PortFromNbo(uint port)
    {
        ushort v = (ushort)port;
        return (v >> 8) | ((v & 0xFF) << 8);
    }

    private static string TcpStateName(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => state.ToString(),
    };
}