using System.Net;

namespace Sentinel.Core.Models;

/// <summary>A network connection or listening socket with its owning process.</summary>
public sealed record NetworkConnection
{
    public required string Protocol { get; init; }        // "TCP" | "UDP" | "TCP6" | "UDP6"
    public required IPAddress LocalAddress { get; init; }
    public required int LocalPort { get; init; }
    public IPAddress? RemoteAddress { get; init; }
    public int? RemotePort { get; init; }
    public string? State { get; init; }                   // TCP state; null for UDP
    public required uint OwningPid { get; init; }
    public string? ProcessName { get; init; }
    public string? ProcessPath { get; init; }
    public bool IsListening { get; init; }
    public bool IsLoopback { get; init; }
    public bool IsEstablished { get; init; }
}

/// <summary>Snapshot of all network activity at a point in time.</summary>
public sealed record NetworkSnapshot
{
    public required DateTime CapturedAtUtc { get; init; }
    public IReadOnlyList<NetworkConnection> Connections { get; init; } = [];
    public int TotalCount => Connections.Count;
    public int EstablishedCount => Connections.Count(c => c.IsEstablished);
    public int ListeningCount => Connections.Count(c => c.IsListening);
    public string? Error { get; init; }
}