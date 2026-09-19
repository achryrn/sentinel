using System.Text.Json;
using Sentinel.Core.Json;

namespace Sentinel.Core.Ipc;

/// <summary>IPC message kinds.</summary>
public enum IpcMessageKind
{
    Request,
    Response,
    Event,
}

/// <summary>IPC request commands.</summary>
public enum IpcCommand
{
    Ping,
    Status,
    ScanFile,
    ScanFolder,
    ScanQuick,
    ScanFull,
    ScanProcess,
    ScanNetwork,
    ScanPersistence,
    ScanMemory,
    AuditSystem,
    CancelScan,
    GetFindings,
    GetEvidence,
    UpdateFindingStatus,
    GetExclusions,
    AddExclusion,
    RemoveExclusion,
    GetQuarantine,
    QuarantineFile,
    RestoreQuarantine,
    DeleteQuarantine,
    GetEvents,
    GetScanJobs,
    GetRealtimeEvents,
    DumpProcessMemory,
    GetBlacklist,
    AddBlacklist,
    RemoveBlacklist,
    ReloadRules,
}

/// <summary>A message on the wire: JSON line, UTF-8.</summary>
public sealed record IpcMessage
{
    public required string Id { get; init; }              // request id (echoed); event id for events
    public required IpcMessageKind Kind { get; init; }
    public IpcCommand? Command { get; init; }
    public int? Code { get; init; }                       // response code: 0 = ok, non-zero = error
    public string? Error { get; init; }
    public string? PayloadJson { get; init; }
    public string? EventType { get; init; }               // for events: scan-progress, finding, realtime-event, ...
    public bool IsResponse => Kind == IpcMessageKind.Response;
}

/// <summary>
/// JSON-lines protocol over a named pipe. Each message is a single UTF-8 JSON
/// line terminated by \n. The server authenticates clients by process image.
/// </summary>
public static class IpcProtocol
{
    public const string PipeName = @"sentinel\ipc";
    public const string FullPipeName = @"\\.\pipe\sentinel\ipc";

    private static readonly JsonSerializerOptions s_options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new IpAddressConverter() },
    };

    /// <summary>Shared JSON options (camelCase, case-insensitive).</summary>
    public static JsonSerializerOptions JsonOptions => s_options;

    public static byte[] Encode(IpcMessage msg)
    {
        string json = JsonSerializer.Serialize(msg, s_options);
        return System.Text.Encoding.UTF8.GetBytes(json + "\n");
    }

    public static IpcMessage? Decode(ReadOnlySpan<byte> line)
    {
        try
        {
            return JsonSerializer.Deserialize<IpcMessage>(line, s_options);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Splits a stream buffer into complete JSON lines.</summary>
    public static List<string> SplitLines(byte[] buffer, int length, ref int carryStart, ref int carryEnd)
    {
        var lines = new List<string>();
        int start = 0;
        for (int i = 0; i < length; i++)
        {
            if (buffer[i] == (byte)'\n')
            {
                if (i > start)
                {
                    lines.Add(System.Text.Encoding.UTF8.GetString(buffer, start, i - start));
                }
                start = i + 1;
            }
        }
        // carry partial line
        carryStart = 0;
        carryEnd = length - start;
        if (carryEnd > 0 && start < length)
        {
            Buffer.BlockCopy(buffer, start, buffer, 0, carryEnd);
        }
        return lines;
    }
}

/// <summary>Helper to build request/response messages.</summary>
public static class IpcMessages
{
    public static IpcMessage Request(string id, IpcCommand command, object? payload = null) => new()
    {
        Id = id,
        Kind = IpcMessageKind.Request,
        Command = command,
        PayloadJson = payload is null ? null : JsonSerializer.Serialize(payload, IpcProtocol.JsonOptions),
    };

    public static IpcMessage Response(string id, object? payload = null, string? error = null) => new()
    {
        Id = id,
        Kind = IpcMessageKind.Response,
        Code = error is null ? 0 : 1,
        Error = error,
        PayloadJson = payload is null ? null : JsonSerializer.Serialize(payload, IpcProtocol.JsonOptions),
    };

    public static IpcMessage Event(string id, string eventType, object? payload = null) => new()
    {
        Id = id,
        Kind = IpcMessageKind.Event,
        EventType = eventType,
        PayloadJson = payload is null ? null : JsonSerializer.Serialize(payload, IpcProtocol.JsonOptions),
    };
}