using LiquidVault.Core.Crypto;
using LiquidVault.Core.Models;
using LiquidVault.Core.Storage;

namespace LiquidVault.Core.Services;

public sealed class VaultService
{
    private readonly VaultFileStore _store;
    public VaultService(VaultFileStore? store = null) => _store = store ?? new VaultFileStore();

    public async Task<VaultSession> CreateAsync(string path, ReadOnlyMemory<char> password, bool useArgon2id = true, CancellationToken cancellationToken = default)
    {
        PasswordPolicy.ValidateMasterPassword(password.Span);
        if (File.Exists(path)) throw new IOException("目标位置已经存在保险库文件。");
        var lease = VaultFileLease.Acquire(path);
        try
        {
            var kdf = useArgon2id ? KeyDerivation.CreateArgon2idDescriptor() : KeyDerivation.CreatePbkdf2Descriptor();
            using var master = await KeyDerivation.DeriveMasterKeyAsync(password, kdf, cancellationToken).ConfigureAwait(false);
            var keys = VaultKeys.FromMasterKey(master.Span);
            var container = new VaultContainer();
            var session = new VaultSession(path, _store, lease, keys, kdf, container);
            try
            {
                await session.SaveAsync(cancellationToken).ConfigureAwait(false);
                return session;
            }
            catch { session.Dispose(); throw; }
        }
        catch { lease.Dispose(); throw; }
    }

    public async Task<VaultSession> OpenAsync(string path, ReadOnlyMemory<char> password, CancellationToken cancellationToken = default)
    {
        var lease = VaultFileLease.Acquire(path);
        try
        {
            var envelope = await _store.ReadEnvelopeAsync(path, cancellationToken).ConfigureAwait(false);
            VaultCryptography.ValidateEnvelope(envelope);
            using var master = await KeyDerivation.DeriveMasterKeyAsync(password, envelope.Kdf, cancellationToken).ConfigureAwait(false);
            var keys = VaultKeys.FromMasterKey(master.Span);
            try
            {
                var container = VaultCryptography.DecryptContainer(keys, envelope);
                return new VaultSession(path, _store, lease, keys, envelope.Kdf, container, envelope.Version);
            }
            catch { keys.Dispose(); throw; }
        }
        catch { lease.Dispose(); throw; }
    }

    public async Task VerifyPasswordAsync(string path, ReadOnlyMemory<char> password, CancellationToken cancellationToken = default)
    {
        var envelope = await _store.ReadEnvelopeAsync(path, cancellationToken).ConfigureAwait(false);
        using var master = await KeyDerivation.DeriveMasterKeyAsync(password, envelope.Kdf, cancellationToken).ConfigureAwait(false);
        using var keys = VaultKeys.FromMasterKey(master.Span);
        _ = VaultCryptography.DecryptContainer(keys, envelope);
    }

    public async Task DestroyAsync(string path, ReadOnlyMemory<char> password, bool deleteManagedBackups, CancellationToken cancellationToken = default)
    {
        await VerifyPasswordAsync(path, password, cancellationToken).ConfigureAwait(false);
        File.Delete(path);
        var lockPath = Path.GetFullPath(path) + ".lock";
        try { if (File.Exists(lockPath)) File.Delete(lockPath); } catch (IOException) { }
        if (!deleteManagedBackups) return;
        var directory = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path))!, "Backups");
        if (!Directory.Exists(directory)) return;
        var pattern = Path.GetFileNameWithoutExtension(path) + "-*.lvault.bak";
        foreach (var backup in Directory.EnumerateFiles(directory, pattern)) File.Delete(backup);
    }
}
