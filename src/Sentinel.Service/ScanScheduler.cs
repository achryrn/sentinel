namespace Sentinel.Service;

/// <summary>
/// Bounded scan worker pool per ARCHITECTURE.md §9: a fixed number of worker
/// slots, one scan at a time per job, cancellation-aware. Real-time monitors
/// are NOT routed through this scheduler (they run on their own lightweight
/// loops). Uses a simple semaphore-based gate with a queue.
/// </summary>
public sealed class ScanScheduler : IDisposable
{
    private readonly int _maxConcurrent;
    private readonly SemaphoreSlim _gate;
    private readonly object _lock = new();
    private readonly LinkedList<Func<CancellationToken, Task>> _queue = [];
    private int _active;
    private bool _disposed;

    public ScanScheduler(int maxConcurrent = 1)
    {
        _maxConcurrent = Math.Max(1, maxConcurrent);
        _gate = new SemaphoreSlim(_maxConcurrent, _maxConcurrent);
    }

    public int ActiveCount { get { lock (_lock) { return _active; } } }

    public int QueuedCount { get { lock (_lock) { return _queue.Count; } } }

    /// <summary>
    /// Enqueues a scan job. The job delegate runs when a slot is free.
    /// </summary>
    public Task Enqueue(Func<CancellationToken, Task> job, CancellationToken ct = default)
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return Task.FromCanceled(ct);
            }
            var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _queue.AddLast(async token =>
            {
                try
                {
                    await job(token).ConfigureAwait(false);
                    tcs.TrySetResult();
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    tcs.TrySetCanceled(token);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            });
            _ = PumpAsync(ct);
            return tcs.Task;
        }
    }

    private async Task PumpAsync(CancellationToken ct)
    {
        while (true)
        {
            Func<CancellationToken, Task>? job;
            lock (_lock)
            {
                if (_queue.Count == 0 || _active >= _maxConcurrent || _disposed)
                {
                    return;
                }
                job = _queue.First!.Value;
                _queue.RemoveFirst();
                _active++;
            }

            try
            {
                await _gate.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                lock (_lock)
                {
                    _active--;
                }
                return;
            }

            try
            {
                await job(ct).ConfigureAwait(false);
            }
            finally
            {
                _gate.Release();
                lock (_lock)
                {
                    _active--;
                }
                // loop continues to pump any queued work
            }
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _disposed = true;
            _queue.Clear();
        }
        _gate.Dispose();
    }
}