using System.Security.Cryptography;
using System.Text.Json;
using LiquidVault.Core.Models;

namespace LiquidVault.Core.Crypto;

public static class AesGcmCipher
{
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int MaxPlaintextBytes = 32 * 1024 * 1024;

    public static CipherBlob EncryptJson<T>(ReadOnlySpan<byte> key, T value, ReadOnlySpan<byte> associatedData)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(value, JsonDefaults.Options);
        try { return Encrypt(key, plaintext, associatedData); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static T DecryptJson<T>(ReadOnlySpan<byte> key, CipherBlob blob, ReadOnlySpan<byte> associatedData)
    {
        var plaintext = Decrypt(key, blob, associatedData);
        try { return JsonSerializer.Deserialize<T>(plaintext, JsonDefaults.Options) ?? throw new VaultFormatException("解密后的 JSON 为空。"); }
        catch (JsonException ex) { throw new VaultFormatException("解密后的 JSON 结构无效。", ex); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static CipherBlob Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        if (key.Length != 32) throw new ArgumentException("AES-256 密钥必须是 32 字节。", nameof(key));
        if (plaintext.Length > MaxPlaintextBytes) throw new VaultFormatException("保险库内容超过大小限制。");
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            return new CipherBlob { Nonce = Convert.ToBase64String(nonce), Ciphertext = Convert.ToBase64String(ciphertext), Tag = Convert.ToBase64String(tag) };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static byte[] Decrypt(ReadOnlySpan<byte> key, CipherBlob blob, ReadOnlySpan<byte> associatedData)
    {
        byte[] nonce, ciphertext, tag;
        try
        {
            nonce = Convert.FromBase64String(blob.Nonce);
            ciphertext = Convert.FromBase64String(blob.Ciphertext);
            tag = Convert.FromBase64String(blob.Tag);
        }
        catch (FormatException ex) { throw new VaultFormatException("密文字段不是有效的 Base64。", ex); }
        if (nonce.Length != NonceSize || tag.Length != TagSize || ciphertext.Length > MaxPlaintextBytes)
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            throw new VaultFormatException("密文长度无效。");
        }

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new VaultAuthenticationException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }
}
