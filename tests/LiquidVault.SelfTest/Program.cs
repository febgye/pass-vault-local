using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using LiquidVault.Core.Crypto;
using LiquidVault.Core.Migration;
using LiquidVault.Core.Models;
using LiquidVault.Core.Services;

namespace LiquidVault.SelfTest;

internal static class Program
{
    private static int _passed;

    private static async Task<int> Main()
    {
        var root = Path.Combine(Path.GetTempPath(), "LiquidVaultSelfTest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await RoundTripAndAtomicBackupAsync(root);
            await WrongPasswordAndTamperAsync(root);
            await ChangePasswordAsync(root);
            await AttachmentRoundTripAsync(root);
            await AttachmentTamperAsync(root);
            await OversizedAttachmentRollsBackAsync(root);
            await DeleteFileEntryRestoresOriginalAsync(root);
            await RemovingAttachmentRestoresOriginalAsync(root);
            PreviewEligibility();
            PreviewPreservesMultilineText();
            PathValidation();
            await V5MigrationAsync(root);
            PasswordGeneration();
            Console.WriteLine($"PASS: {_passed} tests");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAIL after {_passed} tests: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
        finally
        {
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    private static void PreviewPreservesMultilineText()
    {
        var text = "第一行\r\n第二行\n第三行";
        var decoded = AttachmentPreviewService.DecodeText("多行.txt", Encoding.UTF8.GetBytes(text));
        Equal(text, decoded, "multiline text preview preserves all lines");
        _passed++;
    }

    private static async Task RoundTripAndAtomicBackupAsync(string root)
    {
        var path = Path.Combine(root, "roundtrip.lvault");
        var password = "正确的主密码-Alpha-2026!".ToCharArray();
        var service = new VaultService();
        using (var session = await service.CreateAsync(path, password, useArgon2id: false))
        {
            await session.UpsertAsync(new VaultEntry { Type = VaultEntryType.Password, Title = "邮箱", Username = "user@example.com", Password = "S3cret!", Url = "https://example.com" });
            await session.UpsertAsync(new VaultEntry { Type = VaultEntryType.Note, Title = "私密笔记", Content = "只有打开时才解密", Note = "测试" });
            Equal(2, session.GetIndex().Count, "index count");
            True(session.FindInTextContents("打开").SetEquals([session.GetIndex().Single(x => x.Type == VaultEntryType.Note).Id]), "explicit content search");
            var raw = await File.ReadAllTextAsync(path);
            True(!raw.Contains("邮箱", StringComparison.Ordinal) && !raw.Contains("user@example.com", StringComparison.Ordinal) && !raw.Contains("S3cret!", StringComparison.Ordinal) && !raw.Contains("只有打开时才解密", StringComparison.Ordinal), "no plaintext at rest");
            await ThrowsAsync<VaultBusyException>(async () =>
            {
                using var ignored = await service.OpenAsync(path, password);
            }, "exclusive cross-process lease");
            var backup = Path.Combine(root, "verified-backup.lvault");
            await session.ExportVerifiedBackupAsync(backup, password);
            True(File.Exists(backup), "verified backup exists");
        }
        using (var reopened = await service.OpenAsync(path, password))
        {
            Equal(2, reopened.GetIndex().Count, "reopen count");
            var id = reopened.GetIndex().Single(x => x.Type == VaultEntryType.Password).Id;
            Equal("S3cret!", reopened.RevealPassword(id), "on-demand password");
        }
        Array.Clear(password);
        _passed++;
    }

    private static async Task WrongPasswordAndTamperAsync(string root)
    {
        var source = Path.Combine(root, "roundtrip.lvault");
        var service = new VaultService();
        await ThrowsAsync<VaultAuthenticationException>(async () =>
        {
            using var ignored = await service.OpenAsync(source, "完全错误的主密码-2026!".ToCharArray());
        }, "wrong password");

        var tampered = Path.Combine(root, "tampered.lvault");
        var node = JsonNode.Parse(await File.ReadAllTextAsync(source))!.AsObject();
        var cipher = node["cipher"]!["ciphertext"]!.GetValue<string>();
        node["cipher"]!["ciphertext"] = (cipher[0] == 'A' ? 'B' : 'A') + cipher[1..];
        await File.WriteAllTextAsync(tampered, node.ToJsonString(JsonDefaults.Options));
        await ThrowsAsync<VaultAuthenticationException>(async () =>
        {
            using var ignored = await service.OpenAsync(tampered, "正确的主密码-Alpha-2026!".ToCharArray());
        }, "tamper detection");
        _passed++;
    }

    private static async Task ChangePasswordAsync(string root)
    {
        var path = Path.Combine(root, "roundtrip.lvault");
        var service = new VaultService();
        var oldPassword = "正确的主密码-Alpha-2026!".ToCharArray();
        var newPassword = "新的主密码-Bravo-2026!".ToCharArray();
        using (var session = await service.OpenAsync(path, oldPassword)) await session.ChangeMasterPasswordAsync(newPassword, useArgon2id: false);
        await ThrowsAsync<VaultAuthenticationException>(async () =>
        {
            using var ignored = await service.OpenAsync(path, oldPassword);
        }, "old password rejected");
        using (var reopened = await service.OpenAsync(path, newPassword)) Equal(2, reopened.GetIndex().Count, "new password works");
        Array.Clear(oldPassword); Array.Clear(newPassword);
        _passed++;
    }

    private static async Task AttachmentRoundTripAsync(string root)
    {
        var path = Path.Combine(root, "attachments.lvault");
        var password = "附件测试主密码-Echo-2026!".ToCharArray();
        var first = Encoding.UTF8.GetBytes("first attachment content");
        var second = RandomNumberGenerator.GetBytes(4096);
        var service = new VaultService();
        Guid entryId;
        using (var session = await service.CreateAsync(path, password, useArgon2id: false))
        {
            var entry = new VaultEntry
            {
                Type = VaultEntryType.File,
                Title = "附件资料",
                Attachments =
                [
                    VaultAttachment.Create("first.txt", "text/plain", first),
                    VaultAttachment.Create("second.bin", "application/octet-stream", second)
                ]
            };
            entryId = entry.Id;
            await session.UpsertAsync(entry);
        }

        using (var reopened = await service.OpenAsync(path, password))
        {
            var entry = reopened.OpenEntry(entryId);
            Equal(2, entry.Attachments.Count, "multiple attachment count");
            True(first.SequenceEqual(entry.Attachments[0].Content), "first attachment bytes");
            True(second.SequenceEqual(entry.Attachments[1].Content), "second attachment bytes");
            entry.ClearSecrets();
        }
        Array.Clear(password);
        CryptographicOperations.ZeroMemory(first);
        CryptographicOperations.ZeroMemory(second);
        _passed++;
    }

    private static async Task AttachmentTamperAsync(string root)
    {
        var path = Path.Combine(root, "attachments.lvault");
        var password = "附件测试主密码-Echo-2026!".ToCharArray();
        var service = new VaultService();
        var node = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        var envelope = JsonSerializer.Deserialize<VaultEnvelope>(node, JsonDefaults.Options)!;
        using var master = await KeyDerivation.DeriveMasterKeyAsync(password, envelope.Kdf);
        using var keys = VaultKeys.FromMasterKey(master.Span);
        var container = VaultCryptography.DecryptContainer(keys, envelope);
        var record = container.Entries.Single();
        var attachment = record.Attachments[0];
        var attachmentCipher = attachment.Content.Ciphertext;
        var tamperedAttachment = new EncryptedAttachmentRecord
        {
            Id = attachment.Id,
            FileName = attachment.FileName,
            ContentType = attachment.ContentType,
            Size = attachment.Size,
            CreatedAt = attachment.CreatedAt,
            Content = new CipherBlob
            {
                Nonce = attachment.Content.Nonce,
                Ciphertext = (attachmentCipher[0] == 'A' ? 'B' : 'A') + attachmentCipher[1..],
                Tag = attachment.Content.Tag
            }
        };
        record.Attachments[0] = tamperedAttachment;
        var tamperedEnvelope = new VaultEnvelope
        {
            Kdf = envelope.Kdf,
            Cipher = VaultCryptography.EncryptContainer(keys, envelope.Kdf, container)
        };
        var tamperedPath = Path.Combine(root, "attachment-tampered.lvault");
        await File.WriteAllTextAsync(tamperedPath, JsonSerializer.Serialize(tamperedEnvelope, JsonDefaults.Options));
        await ThrowsAsync<VaultAuthenticationException>(async () =>
        {
            using var session = await service.OpenAsync(tamperedPath, password);
            _ = session.OpenEntry(session.GetIndex().Single().Id);
        }, "attachment tamper detection");
        Array.Clear(password);
        _passed++;
    }

    private static async Task OversizedAttachmentRollsBackAsync(string root)
    {
        var path = Path.Combine(root, "oversized.lvault");
        var password = "超限测试主密码-Foxtrot-2026!".ToCharArray();
        var service = new VaultService();
        using var session = await service.CreateAsync(path, password, useArgon2id: false);
        var content = RandomNumberGenerator.GetBytes(12 * 1024 * 1024);
        var entry = new VaultEntry
        {
            Type = VaultEntryType.File,
            Title = "超限附件",
            Attachments = Enumerable.Range(1, 4)
                .Select(index => VaultAttachment.Create($"part-{index}.bin", "application/octet-stream", content))
                .ToList()
        };
        await ThrowsAsync<VaultFormatException>(() => session.UpsertAsync(entry), "oversized vault rejected");
        Equal(0, session.GetIndex().Count, "oversized upsert rolls back session state");
        Array.Clear(password);
        CryptographicOperations.ZeroMemory(content);
        entry.ClearSecrets();
        _passed++;
    }

    private static async Task DeleteFileEntryRestoresOriginalAsync(string root)
    {
        var path = Path.Combine(root, "restore.lvault");
        var originalPath = Path.Combine(root, "documents", "恢复测试.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(originalPath)!);
        var original = Encoding.UTF8.GetBytes("恢复后的文件内容");
        await File.WriteAllBytesAsync(originalPath, original);
        var password = "恢复测试主密码-Golf-2026!".ToCharArray();
        var service = new VaultService();
        Guid entryId;
        using (var session = await service.CreateAsync(path, password, useArgon2id: false))
        {
            var entry = new VaultEntry
            {
                Type = VaultEntryType.File,
                Title = "恢复测试",
                Attachments = [VaultAttachment.Create("恢复测试.txt", "text/plain", original, originalPath)]
            };
            entryId = entry.Id;
            await session.UpsertAsync(entry);
            File.Delete(originalPath);
            await session.DeleteAsync(entryId);
            True(File.Exists(originalPath), "delete restores original file");
            var restored = await File.ReadAllBytesAsync(originalPath);
            True(original.SequenceEqual(restored), "restored bytes");
            CryptographicOperations.ZeroMemory(restored);
            Equal(0, session.GetIndex().Count, "restored file entry deleted");
        }
        Array.Clear(password);
        CryptographicOperations.ZeroMemory(original);
        _passed++;
    }

    private static async Task RemovingAttachmentRestoresOriginalAsync(string root)
    {
        var path = Path.Combine(root, "remove-attachment.lvault");
        var originalPath = Path.Combine(root, "documents", "移除附件.txt");
        var original = Encoding.UTF8.GetBytes("移除附件后的恢复内容");
        var password = "移除附件主密码-Hotel-2026!".ToCharArray();
        var service = new VaultService();
        Guid entryId;
        Guid attachmentId;
        Directory.CreateDirectory(Path.GetDirectoryName(originalPath)!);
        await File.WriteAllBytesAsync(originalPath, original);
        using (var session = await service.CreateAsync(path, password, useArgon2id: false))
        {
            var attachment = VaultAttachment.Create("移除附件.txt", "text/plain", original, originalPath);
            var entry = new VaultEntry { Type = VaultEntryType.File, Title = "移除附件", Attachments = [attachment] };
            entryId = entry.Id;
            attachmentId = attachment.Id;
            await session.UpsertAsync(entry);
            File.Delete(originalPath);
            await session.RemoveAttachmentAsync(entryId, attachmentId);
            True(File.Exists(originalPath), "remove attachment restores original file");
            Equal(0, session.GetIndex().Count, "empty file entry is removed after attachment removal");
        }
        Array.Clear(password);
        CryptographicOperations.ZeroMemory(original);
        _passed++;
    }

    private static void PreviewEligibility()
    {
        True(AttachmentPreviewService.IsPreviewable("photo.PNG"), "image preview supported");
        True(AttachmentPreviewService.IsPreviewable("notes.json"), "text preview supported");
        True(!AttachmentPreviewService.IsPreviewable("document.pdf"), "pdf preview rejected");
        True(!AttachmentPreviewService.IsPreviewable("program.exe"), "executable preview rejected");
        True(AttachmentPreviewService.IsTextPreview("notes.md"), "markdown is text preview");
        True(!AttachmentPreviewService.IsTextPreview("photo.jpg"), "image is not text preview");
        _passed++;
    }

    private static void PathValidation()
    {
        True(VaultAttachment.IsSafeOriginalPath(Path.Combine(Path.GetTempPath(), "safe.txt")), "absolute original path accepted");
        True(!VaultAttachment.IsSafeOriginalPath("relative.txt"), "relative original path rejected");
        True(!VaultAttachment.IsSafeOriginalPath("\\\\server\\share\\file.txt"), "UNC original path rejected");
        True(!VaultAttachment.IsSafeOriginalPath("C:\\"), "root original path rejected");
        _passed++;
    }

    private static async Task V5MigrationAsync(string root)
    {
        var backupPassword = "旧版主密码-Charlie-2026!";
        var backupPath = Path.Combine(root, "legacy-v5.json");
        await File.WriteAllTextAsync(backupPath, BuildV5Backup(backupPassword));
        var destination = Path.Combine(root, "migrated.lvault");
        var newPassword = "原生版主密码-Delta-2026!".ToCharArray();
        var importer = new V5BackupImporter();
        using var session = await importer.MigrateAsync(backupPath, backupPassword.ToCharArray(), destination, newPassword);
        Equal(1, session.GetIndex().Count, "v5 migrated count");
        var id = session.GetIndex().Single().Id;
        Equal("legacy-secret", session.RevealPassword(id), "v5 migrated secret");
        Array.Clear(newPassword);
        _passed++;
    }

    private static void PasswordGeneration()
    {
        var password = PasswordPolicy.Generate(24);
        Equal(24, password.Length, "generated length");
        True(password.Any(char.IsLower) && password.Any(char.IsUpper) && password.Any(char.IsDigit) && password.Any(c => !char.IsLetterOrDigit(c)), "generated groups");
        _passed++;
    }

    private static string BuildV5Backup(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var iterations = 100_000;
        var master = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, 32);
        var encKey = HkdfSha256.DeriveKey(master, "liquid-vault-enc-v1");
        var authKey = HkdfSha256.DeriveKey(master, "liquid-vault-auth-v2");
        var verifier = HkdfSha256.DeriveKey(master, "liquid-vault-verifier-v2");
        var id = "e_" + Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var metaPlain = new JsonObject { ["type"] = "password", ["title"] = "旧版邮箱", ["username"] = "legacy-user", ["url"] = "https://example.com", ["note"] = "迁移测试", ["people"] = "", ["strength"] = 3, ["hasUrl"] = true, ["hasNote"] = true, ["createdAt"] = now, ["updatedAt"] = now };
        var secretPlain = new JsonObject { ["password"] = "legacy-secret" };
        var root = new JsonObject
        {
            ["magic"] = "LIQUID_VAULT_BACKUP", ["version"] = 5, ["exportedAt"] = now,
            ["algorithm"] = new JsonObject { ["kdf"] = "PBKDF2-SHA-256", ["keyScheme"] = "hkdf-sha256-v2", ["auth"] = "HMAC-SHA-256", ["cipher"] = "AES-GCM-256", ["storageMode"] = "per-item-v4", ["entryVersion"] = 4, ["ivBytes"] = 12, ["aad"] = "version|entryId|dataType" },
            ["meta"] = new JsonObject { ["version"] = 4, ["kdf"] = "PBKDF2-SHA-256", ["keyScheme"] = "hkdf-sha256-v2", ["verifierKdf"] = "PBKDF2-HKDF-v2", ["cipher"] = "AES-GCM-256", ["storageMode"] = "per-item-v4", ["salt"] = Convert.ToBase64String(salt), ["verifier"] = Convert.ToBase64String(verifier), ["iterations"] = iterations, ["calibratedAt"] = now, ["calibrationTargetMs"] = 750, ["rev"] = 1, ["createdAt"] = now, ["updatedAt"] = now },
            ["encItems"] = new JsonArray(new JsonObject { ["id"] = id, ["meta"] = EncryptLegacy(encKey, id, "meta", metaPlain), ["secret"] = EncryptLegacy(encKey, id, "secret", secretPlain), ["createdAt"] = now, ["updatedAt"] = now })
        };
        var canonical = Encoding.UTF8.GetBytes(Canonicalize(root));
        root["integrity"] = new JsonObject { ["algorithm"] = "HMAC-SHA-256", ["value"] = Convert.ToBase64String(HMACSHA256.HashData(authKey, canonical)) };
        CryptographicOperations.ZeroMemory(salt); CryptographicOperations.ZeroMemory(master); CryptographicOperations.ZeroMemory(encKey); CryptographicOperations.ZeroMemory(authKey); CryptographicOperations.ZeroMemory(verifier); CryptographicOperations.ZeroMemory(canonical);
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    private static JsonObject EncryptLegacy(ReadOnlySpan<byte> key, string id, string kind, JsonObject value)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.UTF8.GetBytes(value.ToJsonString(new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes($"v4|{id}|{kind}"));
        var combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined, 0); tag.CopyTo(combined, ciphertext.Length);
        var result = new JsonObject { ["iv"] = Convert.ToBase64String(nonce), ["ct"] = Convert.ToBase64String(combined) };
        CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(plaintext); CryptographicOperations.ZeroMemory(ciphertext); CryptographicOperations.ZeroMemory(tag); CryptographicOperations.ZeroMemory(combined);
        return result;
    }

    private static string Canonicalize(JsonNode? node) => node switch
    {
        JsonObject obj => "{" + string.Join(',', obj.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => JsonSerializer.Serialize(x.Key) + ":" + Canonicalize(x.Value))) + "}",
        JsonArray array => "[" + string.Join(',', array.Select(Canonicalize)) + "]",
        JsonValue value => value.ToJsonString(new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }),
        null => "null",
        _ => throw new InvalidOperationException()
    };

    private static async Task ThrowsAsync<T>(Func<Task> action, string name) where T : Exception
    {
        try { await action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}: {name}");
    }

    private static void Equal<T>(T expected, T actual, string name) where T : notnull
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException($"{name}: expected {expected}, actual {actual}");
    }

    private static void True(bool value, string name)
    {
        if (!value) throw new InvalidOperationException(name);
    }
}
