using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Sentinel.Core.Ipc;

/// <summary>
/// Full-duplex IPC session for the GUI: a background reader consumes the pipe
/// continuously, completing pending requests by id and dispatching Event
/// messages (scan progress, file reports, realtime events) to subscribers.
/// Thread-safe. Reconnectable.
/// </summary>
public sealed class IpcSession : IDisposable
{
    private readonly object _lock = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<IpcMessage>> _pending = new();
    private readonly CancellationTokenSource _cts = new();
    private NamedPipeClientStream? _pipe;
    private int _nextId;
    private bool _readerStarted;

    public event Action<IpcMessage>? EventReceived;
    public event Action<string>? Disconnected;

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
                if (!_readerStarted)
                {
                    _readerStarted = true;
                    _ = Task.Run(() => ReadLoopAsync(pipe));
                }
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

    private async Task ReadLoopAsync(NamedPipeClientStream pipe)
    {
        var buffer = new byte[64 * 1024];
        var pending = new StringBuilder();
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                int read = await pipe.ReadAsync(buffer, _cts.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                pending.Append(Encoding.UTF8.GetString(buffer, 0, read));
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
                    var msg = IpcProtocol.Decode(Encoding.UTF8.GetBytes(line));
                    if (msg is null)
                    {
                        continue;
                    }
                    if (msg.Kind == IpcMessageKind.Response)
                    {
                        if (_pending.TryRemove(msg.Id, out var tcs))
                        {
                            tcs.TrySetResult(msg);
                        }
                    }
                    else if (msg.Kind == IpcMessageKind.Event)
                    {
                        try
                        {
                            EventReceived?.Invoke(msg);
                        }
                        catch (Exception)
                        {
                            // subscriber errors never kill the reader
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
        }
        finally
        {
            foreach (var (_, tcs) in _pending)
            {
                tcs.TrySetException(new IOException("Pipe disconnected."));
            }
            _pending.Clear();
            Disconnected?.Invoke("Connection to Sentinel service lost.");
        }
    }

    public async Task<IpcMessage> RequestAsync(IpcCommand command, object? payload = null, CancellationToken ct = default)
    {
        NamedPipeClientStream pipe;
        string id;
        var tcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_lock)
        {
            if (_pipe?.IsConnected != true)
            {
                throw new InvalidOperationException("Not connected to Sentinel service.");
            }
            pipe = _pipe!;
            id = Interlocked.Increment(ref _nextId).ToString();
            _pending[id] = tcs;
        }

        var bytes = IpcProtocol.Encode(IpcMessages.Request(id, command, payload));
        try
        {
            await pipe.WriteAsync(bytes, ct).ConfigureAwait(false);
            await pipe.FlushAsync(ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            _pending.TryRemove(id, out _);
            throw;
        }

        using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
        return await tcs.Task.ConfigureAwait(false);
    }

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
        _cts.Cancel();
        lock (_lock)
        {
            _pipe?.Dispose();
            _pipe = null;
        }
    }
}