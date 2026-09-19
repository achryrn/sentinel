using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Sentinel.Core.Ipc;

namespace Sentinel.Core.Ipc;

/// <summary>
/// Named-pipe client (GUI/CLI side). Connects to the service pipe, sends
/// JSON-line requests, awaits the matching response. Thread-safe via lock.
/// </summary>
public sealed class IpcClient : IDisposable
{
    private readonly object _lock = new();
    private NamedPipeClientStream? _pipe;
    private readonly MemoryStream _buffer = new();
    private int _nextId;

    public bool IsConnected => _pipe?.IsConnected == true;

    public bool Connect(int timeoutMs = 5000)
    {
        lock (_lock)
        {
            if (_pipe?.IsConnected == true)
            {
                return true;
            }
            var pipe = new NamedPipeClientStream(".", IpcProtocol.PipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough);
            try
            {
                pipe.Connect(timeoutMs);
                _pipe = pipe;
                _buffer.SetLength(0);
                return true;
            }
            catch (Exception)
            {
                pipe.Dispose();
                _pipe = null;
                return false;
            }
        }
    }

    /// <summary>Sends a request and waits for the response.</summary>
    public async Task<IpcMessage> RequestAsync(IpcCommand command, object? payload = null, CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (_pipe?.IsConnected != true)
            {
                throw new InvalidOperationException("Not connected to Sentinel service.");
            }
        }

        string id = Interlocked.Increment(ref _nextId).ToString();
        var request = IpcMessages.Request(id, command, payload);
        var bytes = IpcProtocol.Encode(request);

        NamedPipeClientStream pipe;
        lock (_lock)
        {
            pipe = _pipe!;
        }

        await pipe.WriteAsync(bytes, ct).ConfigureAwait(false);
        await pipe.FlushAsync(ct).ConfigureAwait(false);

        // Read until we find the matching response id.
        var pending = new System.Text.StringBuilder();
        var readBuf = new byte[64 * 1024];
        while (true)
        {
            int read = await pipe.ReadAsync(readBuf, ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("Pipe closed by server.");
            }
            pending.Append(System.Text.Encoding.UTF8.GetString(readBuf, 0, read));
            while (true)
            {
                int nl = pending.ToString().IndexOf('\n');
                if (nl < 0)
                {
                    break;
                }
                string line = pending.ToString(0, nl);
                pending.Remove(0, nl + 1);
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }
                var msg = IpcProtocol.Decode(System.Text.Encoding.UTF8.GetBytes(line));
                if (msg is null)
                {
                    continue;
                }
                if (msg.Kind == IpcMessageKind.Response && msg.Id == id)
                {
                    return msg;
                }
                // Events and other responses are ignored by the request/response path.
            }
        }
    }

    /// <summary>Convenience: request with typed payload deserialization.</summary>
    public async Task<T?> RequestAsync<T>(IpcCommand command, object? payload = null, CancellationToken ct = default)
    {
        var resp = await RequestAsync(command, payload, ct).ConfigureAwait(false);
        if (resp.Code != 0)
        {
            throw new InvalidOperationException(resp.Error ?? "IPC error");
        }
        if (resp.PayloadJson is null)
        {
            return default;
        }
        return JsonSerializer.Deserialize<T>(resp.PayloadJson, IpcProtocol.JsonOptions);
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _pipe?.Dispose();
            _pipe = null;
        }
    }
}