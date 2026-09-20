using Sentinel.Core.Hashing;
using Sentinel.Core.Models;
using Sentinel.Core.Storage;

namespace Sentinel.Core.Quarantine;

/// <summary>
/// Quarantine manager: isolates files under %ProgramData%\Sentinel\Quarantine\&lt;id&gt;\
/// with metadata, read-only ACLs, hash-verified restore and verify-then-delete.
/// Never auto-deletes; every operation is audited via the event store.
/// </summary>
public sealed class QuarantineManager
{
    public const string QuarantineRoot = @"C:\ProgramData\Sentinel\Quarantine";

    private readonly SentinelStore _store;

    public QuarantineManager(SentinelStore store)
    {
        _store = store;
        Directory.CreateDirectory(QuarantineRoot);
    }

    /// <summary>
    /// Moves a file into quarantine. Returns the quarantine item, or null when
    /// the file does not exist / cannot be read.
    /// </summary>
    public QuarantineItem? Quarantine(string path, string reason, string? signerName = null, string? evidenceIdsJson = null)
    {
        var fi = new FileInfo(path);
        if (!fi.Exists)
        {
            return null;
        }

        string id = Guid.NewGuid().ToString("n");
        string dir = Path.Combine(QuarantineRoot, id);
        Directory.CreateDirectory(dir);
        string stored = Path.Combine(dir, "file");
        string meta = Path.Combine(dir, "original.json");

        // Compute hashes BEFORE moving (file still at original path).
        var hashes = HashService.ComputeFileAsync(path, HashAlgorithms.All).GetAwaiter().GetResult();
        if (hashes is null)
        {
            return null;
        }

        try
        {
            File.Move(path, stored);
        }
        catch (Exception ex)
        {
            _store.AppendEvent(new Models.SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "quarantine",
                Message = $"Quarantine failed for '{path}': {ex.Message}",
                Severity = Models.EventSeverity.Error,
                Entity = path,
            });
            return null;
        }

        // Read-only + hidden to reduce accidental tampering (ACL hardening is the service's job).
        File.SetAttributes(stored, FileAttributes.ReadOnly | FileAttributes.Hidden);

        var item = new Models.QuarantineItem
        {
            Id = id,
            OriginalPath = path,
            StoredPath = stored,
            Sha256 = hashes.Sha256 ?? "",
            Sha1 = hashes.Sha1 ?? "",
            Md5 = hashes.Md5 ?? "",
            Size = fi.Length,
            QuarantinedAtUtc = DateTime.UtcNow,
            Reason = reason,
            SignerName = signerName,
            EvidenceIdsJson = evidenceIdsJson,
            Status = Models.QuarantineStatus.Quarantined,
        };

        var metaObj = new
        {
            id = item.Id,
            originalPath = item.OriginalPath,
            storedPath = item.StoredPath,
            sha256 = item.Sha256,
            sha1 = item.Sha1,
            md5 = item.Md5,
            size = item.Size,
            quarantinedAtUtc = item.QuarantinedAtUtc,
            reason = item.Reason,
            signerName = item.SignerName,
            evidenceIds = item.EvidenceIdsJson,
        };
        File.WriteAllText(meta, System.Text.Json.JsonSerializer.Serialize(metaObj, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));

        _store.InsertQuarantine(item);
        _store.AppendEvent(new Models.SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "quarantine",
            Message = $"Quarantined '{path}' ({item.Sha256[..16]}…) - {reason}",
            Severity = Models.EventSeverity.Warning,
            Entity = path,
        });
        return item;
    }

    /// <summary>
    /// Restores a quarantined file to its original path. Verifies the stored
    /// file's hash against the recorded hash before and after the copy.
    /// </summary>
    public bool Restore(string id)
    {
        var item = _store.GetQuarantine().FirstOrDefault(q => q.Id == id);
        if (item is null || item.Status != Models.QuarantineStatus.Quarantined)
        {
            return false;
        }

        if (!File.Exists(item.StoredPath))
        {
            _store.AppendEvent(new Models.SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "quarantine",
                Message = $"Restore failed: stored file missing for '{item.OriginalPath}'",
                Severity = Models.EventSeverity.Error,
                Entity = item.OriginalPath,
            });
            return false;
        }

        // Verify stored file hash matches the record.
        var storedHash = HashService.ComputeFileAsync(item.StoredPath, HashAlgorithms.Sha256).GetAwaiter().GetResult();
        if (storedHash?.Sha256 is null || !string.Equals(storedHash.Sha256, item.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            _store.AppendEvent(new Models.SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "quarantine",
                Message = $"Restore refused: hash mismatch for '{item.OriginalPath}'",
                Severity = Models.EventSeverity.Error,
                Entity = item.OriginalPath,
            });
            return false;
        }

        // Refuse to overwrite an existing file at the original path.
        if (File.Exists(item.OriginalPath))
        {
            _store.AppendEvent(new Models.SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "quarantine",
                Message = $"Restore refused: original path already exists '{item.OriginalPath}'",
                Severity = Models.EventSeverity.Error,
                Entity = item.OriginalPath,
            });
            return false;
        }

        try
        {
            File.SetAttributes(item.StoredPath, FileAttributes.Normal);
            File.Copy(item.StoredPath, item.OriginalPath);

            // Verify the restored copy.
            var restoredHash = HashService.ComputeFileAsync(item.OriginalPath, HashAlgorithms.Sha256).GetAwaiter().GetResult();
            if (restoredHash?.Sha256 is null || !string.Equals(restoredHash.Sha256, item.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(item.OriginalPath);
                _store.AppendEvent(new Models.SentinelEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Category = "quarantine",
                    Message = $"Restore failed hash verification for '{item.OriginalPath}' - file removed",
                    Severity = Models.EventSeverity.Error,
                    Entity = item.OriginalPath,
                });
                return false;
            }

            _store.UpdateQuarantineStatus(id, Models.QuarantineStatus.Restored);
            _store.AppendEvent(new Models.SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "quarantine",
                Message = $"Restored '{item.OriginalPath}' (hash verified)",
                Severity = Models.EventSeverity.Info,
                Entity = item.OriginalPath,
            });
            return true;
        }
        catch (Exception ex)
        {
            _store.AppendEvent(new Models.SentinelEvent
            {
                TimestampUtc = DateTime.UtcNow,
                Category = "quarantine",
                Message = $"Restore failed for '{item.OriginalPath}': {ex.Message}",
                Severity = Models.EventSeverity.Error,
                Entity = item.OriginalPath,
            });
            return false;
        }
    }

    /// <summary>Verify-then-delete: hash-checked removal with audit row.</summary>
    public bool Delete(string id)
    {
        var item = _store.GetQuarantine().FirstOrDefault(q => q.Id == id);
        if (item is null || item.Status != Models.QuarantineStatus.Quarantined)
        {
            return false;
        }

        if (File.Exists(item.StoredPath))
        {
            var storedHash = HashService.ComputeFileAsync(item.StoredPath, HashAlgorithms.Sha256).GetAwaiter().GetResult();
            if (storedHash?.Sha256 is null || !string.Equals(storedHash.Sha256, item.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                _store.AppendEvent(new Models.SentinelEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Category = "quarantine",
                    Message = $"Delete refused: hash mismatch for '{item.OriginalPath}'",
                    Severity = Models.EventSeverity.Error,
                    Entity = item.OriginalPath,
                });
                return false;
            }
            try
            {
                File.SetAttributes(item.StoredPath, FileAttributes.Normal);
                File.Delete(item.StoredPath);
            }
            catch (Exception ex)
            {
                _store.AppendEvent(new Models.SentinelEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Category = "quarantine",
                    Message = $"Delete failed for '{item.OriginalPath}': {ex.Message}",
                    Severity = Models.EventSeverity.Error,
                    Entity = item.OriginalPath,
                });
                return false;
            }
        }

        _store.UpdateQuarantineStatus(id, Models.QuarantineStatus.Deleted);
        _store.AppendEvent(new Models.SentinelEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Category = "quarantine",
            Message = $"Deleted quarantined item '{item.OriginalPath}'",
            Severity = Models.EventSeverity.Info,
            Entity = item.OriginalPath,
        });
        return true;
    }
}