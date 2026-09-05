using System.Security.Cryptography;
using LiquidVault.Core.Crypto;
using LiquidVault.Core.Models;
using LiquidVault.Core.Storage;

namespace LiquidVault.Core.Services;

public sealed class VaultSession : IDisposable
{
    private readonly VaultFileStore _store;
    private VaultFileLease? _lease;
    private VaultKeys? _keys;
    private VaultContainer? _container;
    private KdfDescriptor? _kdf;
    private int _version;
    private bool _disposed;

    internal VaultSession(string path, VaultFileStore store, VaultFileLease lease, VaultKeys keys, KdfDescriptor kdf, VaultContainer container, int version = VaultEnvelope.CurrentVersion)
    {
        Path = System.IO.Path.GetFullPath(path);
        _store = store;
        _lease = lease;
        _keys = keys;
        _kdf = kdf;
        _container = container;
        _version = version;
    }

    public string Path { get; }
    public Guid VaultId => Container.VaultId;
    public long Revision => Container.Revision;
    public bool IsLocked => _disposed;

    public IReadOnlyList<VaultIndexItem> GetIndex()
    {
        EnsureOpen();
        var result = new List<VaultIndexItem>(Container.Entries.Count);
        foreach (var record in Container.Entries)
        {
            var meta = VaultCryptography.DecryptMetadata(Keys, record, _version);
            result.Add(new VaultIndexItem(meta.Id, meta.Type, meta.Title, meta.Username, meta.Url, meta.Note, meta.People, meta.PasswordStrength, meta.CreatedAt, meta.UpdatedAt));
        }
        return result;
    }

    public VaultEntry OpenEntry(Guid id)
    {
        EnsureOpen();
        var record = FindRecord(id);
            var meta = VaultCryptography.DecryptMetadata(Keys, record, _version);
            var secret = VaultCryptography.DecryptSecret(Keys, record, _version);
        return new VaultEntry
        {
            Id = meta.Id,
            Type = meta.Type,
            Title = meta.Title,
            Username = meta.Username,
            Password = secret.Password,
            Url = meta.Url,
            Note = meta.Note,
            People = meta.People,
            Content = secret.Content,
            Attachments = VaultCryptography.DecryptAttachments(Keys, record, _version).ToList(),
            CreatedAt = meta.CreatedAt,
            UpdatedAt = meta.UpdatedAt
        };
    }

    public string RevealPassword(Guid id)
    {
        EnsureOpen();
        var record = FindRecord(id);
        var meta = VaultCryptography.DecryptMetadata(Keys, record, _version);
        if (meta.Type != VaultEntryType.Password) throw new VaultFormatException("该条目不是密码类型。");
        return VaultCryptography.DecryptSecret(Keys, record, _version).Password;
    }

    public ISet<Guid> FindInTextContents(string query)
    {
        EnsureOpen();
        var matches = new HashSet<Guid>();
        if (string.IsNullOrWhiteSpace(query)) return matches;
        foreach (var record in Container.Entries)
        {
            var meta = VaultCryptography.DecryptMetadata(Keys, record, _version);
            if (meta.Type == VaultEntryType.Password) continue;
            var secret = VaultCryptography.DecryptSecret(Keys, record, _version);
            if (secret.Content.Contains(query, StringComparison.CurrentCultureIgnoreCase)) matches.Add(record.Id);
            secret = new VaultEntrySecret(string.Empty, string.Empty);
        }
        return matches;
    }

    public async Task UpsertAsync(VaultEntry entry, CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        entry.UpdatedAt = DateTimeOffset.UtcNow;
        var encrypted = VaultCryptography.EncryptEntry(Keys, entry);
        var index = Container.Entries.FindIndex(x => x.Id == entry.Id);
        var previousRevision = Container.Revision;
        var previousUpdatedAt = Container.UpdatedAt;
        var previous = index >= 0 ? Container.Entries[index] : null;
        if (index >= 0) Container.Entries[index] = encrypted;
        else Container.Entries.Add(encrypted);
        Touch();
        try { await SaveAsync(cancellationToken).ConfigureAwait(false); }
        catch
        {
            if (index >= 0) Container.Entries[index] = previous!;
            else Container.Entries.Remove(encrypted);
            Container.Revision = previousRevision;
            Container.UpdatedAt = previousUpdatedAt;
            throw;
        }
    }

    public async Task ImportBatchAsync(IEnumerable<VaultEntry> entries, CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        var incoming = entries.ToList();
        if (incoming.Count + Container.Entries.Count > 5000) throw new VaultFormatException("迁移后的条目数量超过 5000 条限制。");
        var existing = Container.Entries.Select(x => x.Id).ToHashSet();
        foreach (var entry in incoming)
        {
            entry.Validate();
            if (!existing.Add(entry.Id)) throw new VaultFormatException("迁移数据包含重复条目 ID。");
            Container.Entries.Add(VaultCryptography.EncryptEntry(Keys, entry));
        }
        Touch();
        await SaveAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        var entry = OpenEntry(id);
        var restoredPaths = new List<string>();
        try
        {
            if (entry.Type == VaultEntryType.File)
                restoredPaths = await RestoreAttachmentsAsync(entry.Attachments, cancellationToken).ConfigureAwait(false);
        }
        finally { entry.ClearSecrets(); }
        var index = Container.Entries.FindIndex(x => x.Id == id);
        if (index < 0) throw new VaultFormatException("未找到要删除的条目。");
        var previousRevision = Container.Revision;
        var previousUpdatedAt = Container.UpdatedAt;
        var removed = Container.Entries[index];
        Container.Entries.RemoveAt(index);
        Touch();
        try { await SaveAsync(cancellationToken).ConfigureAwait(false); }
        catch
        {
            Container.Entries.Insert(index, removed);
            Container.Revision = previousRevision;
            Container.UpdatedAt = previousUpdatedAt;
            DeleteRestoredFiles(restoredPaths);
            throw;
        }
    }

    public async Task ExportAttachmentAsync(Guid entryId, Guid attachmentId, string destinationPath, CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        var entry = OpenEntry(entryId);
        try
        {
            var attachment = entry.Attachments.FirstOrDefault(x => x.Id == attachmentId) ?? throw new VaultFormatException("未找到附件。");
            await File.WriteAllBytesAsync(destinationPath, attachment.Content, cancellationToken).ConfigureAwait(false);
        }
        finally { entry.ClearSecrets(); }
    }

    public async Task RemoveAttachmentAsync(Guid entryId, Guid attachmentId, CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        var entry = OpenEntry(entryId);
        var restoredPaths = new List<string>();
        var index = Container.Entries.FindIndex(x => x.Id == entryId);
        if (index < 0) throw new VaultFormatException("未找到要修改的条目。");
        var previousRecord = Container.Entries[index];
        var previousRevision = Container.Revision;
        var previousUpdatedAt = Container.UpdatedAt;
        try
        {
            var removed = entry.Attachments.FirstOrDefault(x => x.Id == attachmentId) ?? throw new VaultFormatException("未找到附件。");
            entry.Attachments.Remove(removed);
            if (!string.IsNullOrWhiteSpace(removed.OriginalPath)) restoredPaths = await RestoreAttachmentsAsync([removed], cancellationToken).ConfigureAwait(false);
            if (entry.Type == VaultEntryType.File && entry.Attachments.Count == 0)
            {
                Container.Entries.RemoveAll(x => x.Id == entryId);
                Touch();
                try { await SaveAsync(cancellationToken).ConfigureAwait(false); }
                catch
                {
                    Container.Entries.Insert(index, previousRecord);
                    Container.Revision = previousRevision;
                    Container.UpdatedAt = previousUpdatedAt;
                    DeleteRestoredFiles(restoredPaths);
                    throw;
                }
                return;
            }
            try { await UpsertAsync(entry, cancellationToken).ConfigureAwait(false); }
            catch
            {
                DeleteRestoredFiles(restoredPaths);
                throw;
            }
        }
        finally { entry.ClearSecrets(); }
    }

    private static async Task<List<string>> RestoreAttachmentsAsync(IEnumerable<VaultAttachment> attachments, CancellationToken cancellationToken)
    {
        var items = attachments.ToList();
        var destinations = items.Select(attachment =>
        {
            if (string.IsNullOrWhiteSpace(attachment.OriginalPath)) throw new VaultFormatException("文件缺少原始位置，无法安全恢复。");
            return System.IO.Path.GetFullPath(attachment.OriginalPath);
        }).ToList();
        var reserved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < destinations.Count; index++)
        {
            var destination = destinations[index];
            if (File.Exists(destination) || !reserved.Add(destination))
            {
                var directory = System.IO.Path.GetDirectoryName(destination)!;
                var name = System.IO.Path.GetFileNameWithoutExtension(destination);
                var extension = System.IO.Path.GetExtension(destination);
                var suffix = 1;
                string candidate;
                do candidate = System.IO.Path.Combine(directory, $"{name} ({suffix++}){extension}");
                while (File.Exists(candidate) || !reserved.Add(candidate));
                destinations[index] = candidate;
            }
        }
        var temporary = new List<string>(items.Count);
        var moved = new List<string>(items.Count);
        try
        {
            for (var index = 0; index < items.Count; index++)
            {
                var destination = destinations[index];
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(destination)!);
                var temp = destination + $".{Guid.NewGuid():N}.restore.tmp";
                temporary.Add(temp);
                await File.WriteAllBytesAsync(temp, items[index].Content, cancellationToken).ConfigureAwait(false);
            }
            for (var index = 0; index < temporary.Count; index++)
            {
                File.Move(temporary[index], destinations[index]);
                moved.Add(destinations[index]);
            }
        }
        catch
        {
            foreach (var destination in moved)
                try { if (File.Exists(destination)) File.Delete(destination); } catch (IOException) { }
            throw;
        }
        finally
        {
            foreach (var temp in temporary)
                try { if (File.Exists(temp)) File.Delete(temp); } catch (IOException) { }
        }
        return destinations;
    }

    private static void DeleteRestoredFiles(IEnumerable<string> paths)
    {
        foreach (var path in paths)
            try { if (File.Exists(path)) File.Delete(path); } catch (IOException) { }
    }

    public async Task ChangeMasterPasswordAsync(ReadOnlyMemory<char> newPassword, bool useArgon2id = true, CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        PasswordPolicy.ValidateMasterPassword(newPassword.Span);
        var entries = Container.Entries.Select(record => OpenEntry(record.Id)).ToList();
        var newKdf = useArgon2id ? KeyDerivation.CreateArgon2idDescriptor() : KeyDerivation.CreatePbkdf2Descriptor();
        using var master = await KeyDerivation.DeriveMasterKeyAsync(newPassword, newKdf, cancellationToken).ConfigureAwait(false);
        using var newKeys = VaultKeys.FromMasterKey(master.Span);
        try
        {
            var newRecords = entries.Select(entry => VaultCryptography.EncryptEntry(newKeys, entry)).ToList();
            var newContainer = new VaultContainer
            {
                VaultId = Container.VaultId,
                Revision = Container.Revision + 1,
                CreatedAt = Container.CreatedAt,
                UpdatedAt = DateTimeOffset.UtcNow,
                Entries = newRecords
            };
            await WriteAndVerifyAsync(newKdf, newKeys, newContainer, cancellationToken).ConfigureAwait(false);
            _keys?.Dispose();
            _keys = VaultKeys.FromMasterKey(master.Span);
            _kdf = newKdf;
            _container = newContainer;
            _version = VaultEnvelope.CurrentVersion;
        }
        finally
        {
            foreach (var entry in entries) entry.ClearSecrets();
            entries.Clear();
        }
    }

    public async Task ExportVerifiedBackupAsync(string destinationPath, ReadOnlyMemory<char> password, CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        var service = new VaultService(_store);
        await service.VerifyPasswordAsync(Path, password, cancellationToken).ConfigureAwait(false);
        await _store.CopyVerifiedAsync(Path, destinationPath, async (candidate, ct) =>
        {
            await service.VerifyPasswordAsync(candidate, password, ct).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task SaveAsync(CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        if (_version < VaultEnvelope.CurrentVersion) UpgradeRecordsToCurrentVersion();
        await WriteAndVerifyAsync(Kdf, Keys, Container, cancellationToken).ConfigureAwait(false);
        _version = VaultEnvelope.CurrentVersion;
    }

    private void UpgradeRecordsToCurrentVersion()
    {
        var entries = Container.Entries.Select(record => OpenEntry(record.Id)).ToList();
        try
        {
            Container.Entries.Clear();
            Container.Entries.AddRange(entries.Select(entry => VaultCryptography.EncryptEntry(Keys, entry)));
        }
        finally
        {
            foreach (var entry in entries) entry.ClearSecrets();
        }
    }

    private async Task WriteAndVerifyAsync(KdfDescriptor kdf, VaultKeys keys, VaultContainer container, CancellationToken cancellationToken)
    {
        var envelope = new VaultEnvelope { Kdf = kdf, Cipher = VaultCryptography.EncryptContainer(keys, kdf, container) };
        await _store.WriteAtomicallyAsync(Path, envelope, async (candidate, ct) =>
        {
            var read = await _store.ReadEnvelopeAsync(candidate, ct).ConfigureAwait(false);
            var verified = VaultCryptography.DecryptContainer(keys, read);
            if (verified.VaultId != container.VaultId || verified.Revision != container.Revision || verified.Entries.Count != container.Entries.Count)
                throw new VaultFormatException("写入后的保险库自检失败。");
        }, cancellationToken).ConfigureAwait(false);
    }

    private EncryptedEntryRecord FindRecord(Guid id) => Container.Entries.FirstOrDefault(x => x.Id == id) ?? throw new VaultFormatException("未找到条目。");
    private VaultContainer Container => _container ?? throw new ObjectDisposedException(nameof(VaultSession));
    private VaultKeys Keys => _keys ?? throw new ObjectDisposedException(nameof(VaultSession));
    private KdfDescriptor Kdf => _kdf ?? throw new ObjectDisposedException(nameof(VaultSession));
    private void Touch() { Container.Revision++; Container.UpdatedAt = DateTimeOffset.UtcNow; }
    private void EnsureOpen() { if (_disposed) throw new ObjectDisposedException(nameof(VaultSession)); }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _container = null;
        _kdf = null;
        _keys?.Dispose();
        _keys = null;
        _lease?.Dispose();
        _lease = null;
    }
}
