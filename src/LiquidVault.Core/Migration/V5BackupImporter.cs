using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using LiquidVault.Core.Crypto;
using LiquidVault.Core.Models;
using LiquidVault.Core.Services;

namespace LiquidVault.Core.Migration;

public sealed class V5BackupImporter
{
    private const long MaxBackupBytes = 2L * 1024 * 1024;
    private static readonly JsonSerializerOptions StringOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public async Task<IReadOnlyList<VaultEntry>> ReadAndVerifyAsync(string backupPath, ReadOnlyMemory<char> password, CancellationToken cancellationToken = default)
    {
        var info = new FileInfo(backupPath);
        if (!info.Exists || info.Length is < 100 or > MaxBackupBytes) throw new VaultFormatException("v5 备份文件大小无效。");
        var bytes = await File.ReadAllBytesAsync(backupPath, cancellationToken).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false });
            var root = document.RootElement;
            ValidateTopLevel(root);
            var meta = root.GetProperty("meta");
            var iterations = meta.GetProperty("iterations").GetInt32();
            if (iterations is < 100_000 or > 2_000_000) throw new VaultFormatException("v5 PBKDF2 参数越界。");
            var salt = DecodeBase64(meta.GetProperty("salt").GetString(), 16, "v5 盐");
            var passwordBytes = new byte[Encoding.UTF8.GetByteCount(password.Span)];
            Encoding.UTF8.GetBytes(password.Span, passwordBytes);
            var master = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA256, 32);
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(salt);
            try
            {
                var verifier = HkdfSha256.DeriveKey(master, "liquid-vault-verifier-v2");
                var expectedVerifier = DecodeBase64(meta.GetProperty("verifier").GetString(), 32, "v5 verifier");
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(verifier, expectedVerifier)) throw new VaultAuthenticationException();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(verifier);
                    CryptographicOperations.ZeroMemory(expectedVerifier);
                }

                var authKey = HkdfSha256.DeriveKey(master, "liquid-vault-auth-v2");
                try { VerifyHmac(root, authKey); }
                finally { CryptographicOperations.ZeroMemory(authKey); }

                var encKey = HkdfSha256.DeriveKey(master, "liquid-vault-enc-v1");
                try { return DecryptEntries(root.GetProperty("encItems"), encKey); }
                finally { CryptographicOperations.ZeroMemory(encKey); }
            }
            finally { CryptographicOperations.ZeroMemory(master); }
        }
        catch (JsonException ex) { throw new VaultFormatException("v5 备份 JSON 结构无效。", ex); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public async Task<VaultSession> MigrateAsync(string backupPath, ReadOnlyMemory<char> backupPassword, string destinationPath, ReadOnlyMemory<char> newPassword, CancellationToken cancellationToken = default)
    {
        var entries = (await ReadAndVerifyAsync(backupPath, backupPassword, cancellationToken).ConfigureAwait(false)).ToList();
        var service = new VaultService();
        var session = await service.CreateAsync(destinationPath, newPassword, true, cancellationToken).ConfigureAwait(false);
        try
        {
            await session.ImportBatchAsync(entries, cancellationToken).ConfigureAwait(false);
            return session;
        }
        catch
        {
            session.Dispose();
            try { if (File.Exists(destinationPath)) File.Delete(destinationPath); } catch (IOException) { }
            throw;
        }
        finally
        {
            foreach (var entry in entries) entry.ClearSecrets();
            entries.Clear();
        }
    }

    private static void ValidateTopLevel(JsonElement root)
    {
        EnsureKeys(root, "magic", "version", "exportedAt", "algorithm", "meta", "encItems", "integrity");
        if (root.ValueKind != JsonValueKind.Object || root.GetProperty("magic").GetString() != "LIQUID_VAULT_BACKUP" || root.GetProperty("version").GetInt32() != 5)
            throw new VaultFormatException("只支持液态保险库 v5 备份。");
        var exportedAt = root.GetProperty("exportedAt").GetInt64();
        if (exportedAt < 0 || exportedAt > DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeMilliseconds()) throw new VaultFormatException("v5 导出时间无效。");
        var algorithm = root.GetProperty("algorithm");
        EnsureKeys(algorithm, "kdf", "keyScheme", "auth", "cipher", "storageMode", "entryVersion", "ivBytes", "aad");
        if (algorithm.GetProperty("kdf").GetString() != "PBKDF2-SHA-256" ||
            algorithm.GetProperty("keyScheme").GetString() != "hkdf-sha256-v2" ||
            algorithm.GetProperty("auth").GetString() != "HMAC-SHA-256" ||
            algorithm.GetProperty("cipher").GetString() != "AES-GCM-256" ||
            algorithm.GetProperty("storageMode").GetString() != "per-item-v4" ||
            algorithm.GetProperty("entryVersion").GetInt32() != 4 ||
            algorithm.GetProperty("ivBytes").GetInt32() != 12 ||
            algorithm.GetProperty("aad").GetString() != "version|entryId|dataType")
            throw new VaultFormatException("v5 备份算法声明不受支持。");
        var meta = root.GetProperty("meta");
        EnsureKeys(meta, "version", "kdf", "keyScheme", "verifierKdf", "cipher", "storageMode", "salt", "verifier", "iterations", "calibratedAt", "calibrationTargetMs", "rev", "createdAt", "updatedAt");
        if (meta.GetProperty("version").GetInt32() != 4 || meta.GetProperty("kdf").GetString() != "PBKDF2-SHA-256" ||
            meta.GetProperty("keyScheme").GetString() != "hkdf-sha256-v2" || meta.GetProperty("verifierKdf").GetString() != "PBKDF2-HKDF-v2" ||
            meta.GetProperty("cipher").GetString() != "AES-GCM-256" || meta.GetProperty("storageMode").GetString() != "per-item-v4")
            throw new VaultFormatException("v5 元数据算法声明无效。");
        _ = DecodeBase64(meta.GetProperty("salt").GetString(), 16, "v5 盐");
        _ = DecodeBase64(meta.GetProperty("verifier").GetString(), 32, "v5 verifier");
        var integrity = root.GetProperty("integrity");
        EnsureKeys(integrity, "algorithm", "value");
        if (integrity.GetProperty("algorithm").GetString() != "HMAC-SHA-256") throw new VaultFormatException("v5 HMAC 算法无效。");
        _ = DecodeBase64(integrity.GetProperty("value").GetString(), 32, "v5 HMAC");
        if (root.GetProperty("encItems").ValueKind != JsonValueKind.Array || root.GetProperty("encItems").GetArrayLength() > 5000)
            throw new VaultFormatException("v5 条目数量无效。");
    }

    private static void VerifyHmac(JsonElement root, ReadOnlySpan<byte> authKey)
    {
        var integrity = root.GetProperty("integrity");
        if (integrity.GetProperty("algorithm").GetString() != "HMAC-SHA-256") throw new VaultFormatException("v5 HMAC 算法无效。");
        var expected = DecodeBase64(integrity.GetProperty("value").GetString(), 32, "v5 HMAC");
        var canonical = Encoding.UTF8.GetBytes(Canonicalize(root, skipTopLevelIntegrity: true));
        var actual = HMACSHA256.HashData(authKey, canonical);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, actual)) throw new VaultFormatException("v5 备份 HMAC 验证失败，拒绝迁移。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private static IReadOnlyList<VaultEntry> DecryptEntries(JsonElement items, ReadOnlySpan<byte> encKey)
    {
        var result = new List<VaultEntry>(items.GetArrayLength());
        var ids = new HashSet<Guid>();
        foreach (var row in items.EnumerateArray())
        {
            EnsureKeys(row, "id", "meta", "secret", "createdAt", "updatedAt");
            var legacyId = row.GetProperty("id").GetString() ?? throw new VaultFormatException("v5 条目 ID 缺失。");
            if (!legacyId.StartsWith("e_", StringComparison.Ordinal) || legacyId.Length != 34 || !Guid.TryParseExact(legacyId[2..], "N", out var id) || !ids.Add(id))
                throw new VaultFormatException("v5 条目 ID 无效或重复。");
            using var meta = DecryptLegacyJson(row.GetProperty("meta"), encKey, $"v4|{legacyId}|meta");
            using var secret = DecryptLegacyJson(row.GetProperty("secret"), encKey, $"v4|{legacyId}|secret");
            var m = meta.RootElement;
            var s = secret.RootElement;
            var type = ParseType(GetString(m, "type", "password"));
            var entry = new VaultEntry
            {
                Id = id,
                Type = type,
                Title = GetString(m, "title"),
                Username = GetString(m, "username"),
                Password = GetString(s, "password"),
                Url = GetString(m, "url"),
                Note = GetString(m, "note"),
                People = GetString(m, "people"),
                Content = GetString(s, "content"),
                CreatedAt = FromUnixMilliseconds(GetInt64(m, "createdAt", row.GetProperty("createdAt").GetInt64())),
                UpdatedAt = FromUnixMilliseconds(GetInt64(m, "updatedAt", row.GetProperty("updatedAt").GetInt64()))
            };
            entry.Validate();
            result.Add(entry);
        }
        return result;
    }

    private static JsonDocument DecryptLegacyJson(JsonElement blob, ReadOnlySpan<byte> key, string aadText)
    {
        var nonce = DecodeBase64(blob.GetProperty("iv").GetString(), 12, "v5 IV");
        var combined = DecodeBase64(blob.GetProperty("ct").GetString(), null, "v5 密文");
        if (combined.Length is < 16 or > 65536) throw new VaultFormatException("v5 密文长度无效。");
        var cipherLength = combined.Length - 16;
        var plaintext = new byte[cipherLength];
        var aad = Encoding.UTF8.GetBytes(aadText);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, combined.AsSpan(0, cipherLength), combined.AsSpan(cipherLength, 16), plaintext, aad);
            using var stream = new MemoryStream(plaintext, writable: false);
            return JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 16 });
        }
        catch (AuthenticationTagMismatchException) { throw new VaultAuthenticationException(); }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(combined);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] DecodeBase64(string? value, int? exactLength, string name)
    {
        byte[] bytes;
        try { bytes = Convert.FromBase64String(value ?? string.Empty); }
        catch (FormatException ex) { throw new VaultFormatException($"{name} 不是有效 Base64。", ex); }
        if (exactLength is not null && bytes.Length != exactLength) { CryptographicOperations.ZeroMemory(bytes); throw new VaultFormatException($"{name} 长度无效。"); }
        return bytes;
    }

    private static string Canonicalize(JsonElement value, bool skipTopLevelIntegrity = false)
    {
        return value.ValueKind switch
        {
            JsonValueKind.Object => "{" + string.Join(',', value.EnumerateObject()
                .Where(p => !(skipTopLevelIntegrity && p.NameEquals("integrity")))
                .OrderBy(p => p.Name, StringComparer.Ordinal)
                .Select(p => JsonSerializer.Serialize(p.Name, StringOptions) + ":" + Canonicalize(p.Value))) + "}",
            JsonValueKind.Array => "[" + string.Join(',', value.EnumerateArray().Select(x => Canonicalize(x))) + "]",
            JsonValueKind.String => JsonSerializer.Serialize(value.GetString(), StringOptions),
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null => value.GetRawText(),
            _ => throw new VaultFormatException("v5 备份包含不支持的 JSON 值。")
        };
    }

    private static VaultEntryType ParseType(string value) => value switch { "password" => VaultEntryType.Password, "note" => VaultEntryType.Note, "chat" => VaultEntryType.Chat, "text" => VaultEntryType.Text, _ => throw new VaultFormatException("v5 条目类型无效。") };
    private static string GetString(JsonElement obj, string name, string fallback = "") => obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : fallback;
    private static long GetInt64(JsonElement obj, string name, long fallback) => obj.TryGetProperty(name, out var value) && value.TryGetInt64(out var result) ? result : fallback;
    private static DateTimeOffset FromUnixMilliseconds(long value) => value is >= 0 and <= 253402300799999 ? DateTimeOffset.FromUnixTimeMilliseconds(value) : throw new VaultFormatException("v5 时间戳无效。");

    private static void EnsureKeys(JsonElement obj, params string[] expected)
    {
        if (obj.ValueKind != JsonValueKind.Object) throw new VaultFormatException("v5 对象结构无效。");
        var allowed = expected.ToHashSet(StringComparer.Ordinal);
        foreach (var property in obj.EnumerateObject()) if (!allowed.Remove(property.Name)) throw new VaultFormatException($"v5 对象包含未知字段 {property.Name}。");
        if (allowed.Count != 0) throw new VaultFormatException($"v5 对象缺少字段 {string.Join(',', allowed)}。");
    }
}
