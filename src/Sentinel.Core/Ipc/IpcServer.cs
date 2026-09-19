using System.IO.Pipes;
using System.Text;
using Sentinel.Core.Ipc;

namespace Sentinel.Core.Ipc;

/// <summary>
/// Named-pipe server (runs in the service). Authenticates clients by process
/// image: only Sentinel.Gui.exe / Sentinel.Cli.exe (or same-session admin)
/// may connect. Handles one request at a time per connection; JSON lines.
/// </summary>
public sealed class IpcServer : IDisposable
{
    private readonly Func<IpcMessage, Task<IpcMessage>> _handler;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _connections = [];
    private readonly object _clientsLock = new();
    private readonly List<NamedPipeServerStream> _clients = [];
    private bool _started;

    public IpcServer(Func<IpcMessage, Task<IpcMessage>> handler)
    {
        _handler = handler;
    }

    /// <summary>
    /// Broadcasts an event message to all connected clients (best effort;
    /// failed pipes are dropped). Used for scan progress + realtime events.
    /// </summary>
    public void Broadcast(IpcMessage message)
    {
        byte[] bytes = IpcProtocol.Encode(message);
        NamedPipeServerStream[] clients;
        lock (_clientsLock)
        {
            clients = _clients.ToArray();
        }
        foreach (var pipe in clients)
        {
            try
            {
                pipe.Write(bytes, 0, bytes.Length);
                pipe.Flush();
            }
            catch (Exception)
            {
                RemoveClient(pipe);
            }
        }
    }

    private void AddClient(NamedPipeServerStream pipe)
    {
        lock (_clientsLock)
        {
            _clients.Add(pipe);
        }
    }

    private void RemoveClient(NamedPipeServerStream pipe)
    {
        lock (_clientsLock)
        {
            _clients.Remove(pipe);
        }
    }

    public void Start()
    {
        if (_started)
        {
            return;
        }
        _started = true;
        _ = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var pipe = new NamedPipeServerStream(
                    IpcProtocol.PipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 8,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough);
                await pipe.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);
                if (!IsClientAuthorized(pipe))
                {
                    pipe.Dispose();
                    continue;
                }
                AddClient(pipe);
                _connections.Add(Task.Run(() => HandleConnectionAsync(pipe, _cts.Token)));
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception)
            {
                await Task.Delay(500, _cts.Token).ConfigureAwait(false);
            }
        }
    }

    private static bool IsClientAuthorized(NamedPipeServerStream pipe)
    {
        try
        {
            string? image = GetClientProcessImage(pipe);
            if (image is null)
            {
                return false;
            }
            string name = Path.GetFileName(image);
            return name.Equals("Sentinel.Gui.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Sentinel.Cli.exe", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static string? GetClientProcessImage(NamedPipeServerStream pipe)
    {
        // Authenticate by process image: the pipe's server handle lets us query
        // the client's PID, which we resolve to an image name. Only our own
        // binaries pass.
        try
        {
            if (!Sentinel.Core.Native.NativeMethods.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid))
            {
                return null;
            }
            using var proc = System.Diagnostics.Process.GetProcessById((int)pid);
            return proc.MainModule?.FileName;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        var buffer = new byte[64 * 1024];
        var pending = new StringBuilder();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await pipe.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break; // client closed
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
                    if (msg is null || msg.Kind != IpcMessageKind.Request)
                    {
                        continue;
                    }
                    IpcMessage response;
                    try
                    {
                        response = await _handler(msg).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        response = IpcMessages.Response(msg.Id, error: ex.Message);
                    }
                    var bytes = IpcProtocol.Encode(response);
                    await pipe.WriteAsync(bytes, ct).ConfigureAwait(false);
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
            RemoveClient(pipe);
            pipe.Dispose();
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try
        {
            Task.WaitAll(_connections.ToArray(), TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
        }
        _cts.Dispose();
    }
}