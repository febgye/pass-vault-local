using System.Security.Cryptography;

namespace LiquidVault.Core.Crypto;

public sealed class VaultKeys : IDisposable
{
    private byte[]? _containerKey;
    private byte[]? _entryKey;
    private byte[]? _backupAuthKey;

    private VaultKeys(byte[] containerKey, byte[] entryKey, byte[] backupAuthKey)
    {
        _containerKey = containerKey;
        _entryKey = entryKey;
        _backupAuthKey = backupAuthKey;
    }

    public ReadOnlySpan<byte> ContainerKey => _containerKey ?? throw new ObjectDisposedException(nameof(VaultKeys));
    public ReadOnlySpan<byte> EntryKey => _entryKey ?? throw new ObjectDisposedException(nameof(VaultKeys));
    public ReadOnlySpan<byte> BackupAuthKey => _backupAuthKey ?? throw new ObjectDisposedException(nameof(VaultKeys));

    public static VaultKeys FromMasterKey(ReadOnlySpan<byte> masterKey) => new(
        HkdfSha256.DeriveKey(masterKey, "liquid-vault-native-container-v1"),
        HkdfSha256.DeriveKey(masterKey, "liquid-vault-native-entry-v1"),
        HkdfSha256.DeriveKey(masterKey, "liquid-vault-native-backup-auth-v1"));

    public void Dispose()
    {
        Zero(ref _containerKey);
        Zero(ref _entryKey);
        Zero(ref _backupAuthKey);
    }

    private static void Zero(ref byte[]? value)
    {
        var bytes = Interlocked.Exchange(ref value, null);
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
    }
}
