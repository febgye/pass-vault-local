using System.Security.Cryptography;

namespace LiquidVault.Core.Crypto;

public sealed class SensitiveBuffer : IDisposable
{
    private byte[]? _bytes;
    public SensitiveBuffer(byte[] bytes) => _bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
    public ReadOnlySpan<byte> Span => _bytes ?? throw new ObjectDisposedException(nameof(SensitiveBuffer));
    public byte[] DangerousCopy() => (_bytes ?? throw new ObjectDisposedException(nameof(SensitiveBuffer))).ToArray();

    public void Dispose()
    {
        var bytes = Interlocked.Exchange(ref _bytes, null);
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
    }
}
