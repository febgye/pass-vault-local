using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using LiquidVault.Core.Models;

namespace LiquidVault.Core.Crypto;

public static class KeyDerivation
{
    public const int SaltSize = 16;
    public const int KeySize = 32;

    public static KdfDescriptor CreateArgon2idDescriptor() => new()
    {
        Algorithm = "argon2id",
        Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(SaltSize)),
        MemoryKiB = 65536,
        Iterations = 3,
        Parallelism = Math.Clamp(Environment.ProcessorCount / 2, 1, 4)
    };

    public static KdfDescriptor CreatePbkdf2Descriptor(int iterations = 600_000) => new()
    {
        Algorithm = "pbkdf2-sha256",
        Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(SaltSize)),
        MemoryKiB = 0,
        Iterations = Math.Clamp(iterations, 100_000, 2_000_000),
        Parallelism = 1
    };

    public static async Task<SensitiveBuffer> DeriveMasterKeyAsync(ReadOnlyMemory<char> password, KdfDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ValidateDescriptor(descriptor);
        var passwordBytes = new byte[Encoding.UTF8.GetByteCount(password.Span)];
        Encoding.UTF8.GetBytes(password.Span, passwordBytes);
        var salt = Convert.FromBase64String(descriptor.Salt);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] key;
            if (descriptor.Algorithm == "argon2id")
            {
                using var argon = new Argon2id(passwordBytes)
                {
                    Salt = salt,
                    MemorySize = descriptor.MemoryKiB,
                    Iterations = descriptor.Iterations,
                    DegreeOfParallelism = descriptor.Parallelism
                };
                key = await argon.GetBytesAsync(KeySize).WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                key = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, descriptor.Iterations, HashAlgorithmName.SHA256, KeySize);
            }
            return new SensitiveBuffer(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    public static void ValidateDescriptor(KdfDescriptor descriptor)
    {
        byte[] salt;
        try { salt = Convert.FromBase64String(descriptor.Salt); }
        catch (FormatException ex) { throw new VaultFormatException("KDF 盐格式无效。", ex); }
        try
        {
            if (salt.Length != SaltSize) throw new VaultFormatException("KDF 盐长度无效。");
        }
        finally { CryptographicOperations.ZeroMemory(salt); }

        switch (descriptor.Algorithm)
        {
            case "argon2id" when descriptor.MemoryKiB is >= 32768 and <= 262144 && descriptor.Iterations is >= 2 and <= 10 && descriptor.Parallelism is >= 1 and <= 8:
            case "pbkdf2-sha256" when descriptor.MemoryKiB == 0 && descriptor.Iterations is >= 100_000 and <= 2_000_000 && descriptor.Parallelism == 1:
                return;
            default:
                throw new VaultFormatException("KDF 参数不受支持或超出安全边界。");
        }
    }
}
