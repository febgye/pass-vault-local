using System.Security.Cryptography;
using System.Text;

namespace LiquidVault.Core.Crypto;

public static class HkdfSha256
{
    private const int HashLength = 32;

    public static byte[] DeriveKey(ReadOnlySpan<byte> inputKeyMaterial, string info, int length = HashLength)
    {
        if (length is < 1 or > 255 * HashLength) throw new ArgumentOutOfRangeException(nameof(length));
        Span<byte> zeroSalt = stackalloc byte[HashLength];
        var prk = HMACSHA256.HashData(zeroSalt, inputKeyMaterial);
        try
        {
            var infoBytes = Encoding.UTF8.GetBytes(info);
            var result = new byte[length];
            var previous = Array.Empty<byte>();
            var offset = 0;
            byte counter = 1;
            while (offset < length)
            {
                var input = new byte[previous.Length + infoBytes.Length + 1];
                previous.CopyTo(input, 0);
                infoBytes.CopyTo(input, previous.Length);
                input[^1] = counter++;
                var block = HMACSHA256.HashData(prk, input);
                CryptographicOperations.ZeroMemory(input);
                if (previous.Length > 0) CryptographicOperations.ZeroMemory(previous);
                previous = block;
                var count = Math.Min(block.Length, length - offset);
                block.AsSpan(0, count).CopyTo(result.AsSpan(offset));
                offset += count;
            }
            if (previous.Length > 0) CryptographicOperations.ZeroMemory(previous);
            CryptographicOperations.ZeroMemory(infoBytes);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
        }
    }
}
