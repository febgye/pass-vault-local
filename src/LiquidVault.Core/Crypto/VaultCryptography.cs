using System.Security.Cryptography;
using System.Text;
using LiquidVault.Core.Models;

namespace LiquidVault.Core.Crypto;

public static class VaultCryptography
{
    public static byte[] ContainerAad(KdfDescriptor kdf, int version = VaultEnvelope.CurrentVersion) => Encoding.UTF8.GetBytes(string.Join('|',
        VaultEnvelope.ExpectedMagic,
        version,
        kdf.Algorithm,
        kdf.Salt,
        kdf.MemoryKiB,
        kdf.Iterations,
        kdf.Parallelism));

    public static byte[] EntryAad(Guid id, string kind, int version = VaultEnvelope.CurrentVersion) => Encoding.UTF8.GetBytes($"v{version}|{id:D}|{kind}");

    public static EncryptedEntryRecord EncryptEntry(VaultKeys keys, VaultEntry entry)
    {
        entry.Validate();
        var metaAad = EntryAad(entry.Id, "meta", VaultEnvelope.CurrentVersion);
        var secretAad = EntryAad(entry.Id, "secret", VaultEnvelope.CurrentVersion);
        try
        {
            var attachments = new List<EncryptedAttachmentRecord>(entry.Attachments.Count);
            foreach (var attachment in entry.Attachments)
            {
                var aad = EntryAad(entry.Id, $"attachment|{attachment.Id:D}", VaultEnvelope.CurrentVersion);
                try
                {
                    attachments.Add(new EncryptedAttachmentRecord
                    {
                        Id = attachment.Id,
                        FileName = attachment.FileName,
                        ContentType = attachment.ContentType,
                        Size = attachment.Size,
                        CreatedAt = attachment.CreatedAt,
                        OriginalPath = attachment.OriginalPath,
                        Content = AesGcmCipher.Encrypt(keys.EntryKey, attachment.Content, aad)
                    });
                }
                finally { CryptographicOperations.ZeroMemory(aad); }
            }
            return new EncryptedEntryRecord
            {
                Id = entry.Id,
                Metadata = AesGcmCipher.EncryptJson(keys.EntryKey, VaultEntryMetadata.FromEntry(entry), metaAad),
                Secret = AesGcmCipher.EncryptJson(keys.EntryKey, VaultEntrySecret.FromEntry(entry), secretAad),
                Attachments = attachments
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(metaAad);
            CryptographicOperations.ZeroMemory(secretAad);
        }
    }

    public static VaultEntryMetadata DecryptMetadata(VaultKeys keys, EncryptedEntryRecord record, int version = VaultEnvelope.CurrentVersion)
    {
        var aad = EntryAad(record.Id, "meta", version);
        try
        {
            var meta = AesGcmCipher.DecryptJson<VaultEntryMetadata>(keys.EntryKey, record.Metadata, aad);
            if (meta.Id != record.Id) throw new VaultFormatException("条目元数据 ID 不匹配。");
            return meta;
        }
        finally { CryptographicOperations.ZeroMemory(aad); }
    }

    public static VaultEntrySecret DecryptSecret(VaultKeys keys, EncryptedEntryRecord record, int version = VaultEnvelope.CurrentVersion)
    {
        var aad = EntryAad(record.Id, "secret", version);
        try { return AesGcmCipher.DecryptJson<VaultEntrySecret>(keys.EntryKey, record.Secret, aad); }
        finally { CryptographicOperations.ZeroMemory(aad); }
    }

    public static IReadOnlyList<VaultAttachment> DecryptAttachments(VaultKeys keys, EncryptedEntryRecord record, int version = VaultEnvelope.CurrentVersion)
    {
        var result = new List<VaultAttachment>(record.Attachments.Count);
        foreach (var attachment in record.Attachments)
        {
            var aad = EntryAad(record.Id, $"attachment|{attachment.Id:D}", version);
            try
            {
                var content = AesGcmCipher.Decrypt(keys.EntryKey, attachment.Content, aad);
                if (content.LongLength != attachment.Size) throw new VaultFormatException("附件大小校验失败。");
                result.Add(new VaultAttachment { Id = attachment.Id, FileName = attachment.FileName, ContentType = attachment.ContentType, Content = content, CreatedAt = attachment.CreatedAt, OriginalPath = attachment.OriginalPath });
            }
            finally { CryptographicOperations.ZeroMemory(aad); }
        }
        return result;
    }

    public static CipherBlob EncryptContainer(VaultKeys keys, KdfDescriptor kdf, VaultContainer container)
    {
        var aad = ContainerAad(kdf);
        try { return AesGcmCipher.EncryptJson(keys.ContainerKey, container, aad); }
        finally { CryptographicOperations.ZeroMemory(aad); }
    }

    public static VaultContainer DecryptContainer(VaultKeys keys, VaultEnvelope envelope)
    {
        ValidateEnvelope(envelope);
        var aad = ContainerAad(envelope.Kdf, envelope.Version);
        try
        {
            var container = AesGcmCipher.DecryptJson<VaultContainer>(keys.ContainerKey, envelope.Cipher, aad);
            ValidateContainer(container);
            return container;
        }
        finally { CryptographicOperations.ZeroMemory(aad); }
    }

    public static void ValidateEnvelope(VaultEnvelope envelope)
    {
        if (envelope.Magic != VaultEnvelope.ExpectedMagic || envelope.Version is < 1 or > VaultEnvelope.CurrentVersion)
            throw new VaultFormatException("不是受支持的液态保险库文件。");
        KeyDerivation.ValidateDescriptor(envelope.Kdf);
    }

    public static void ValidateContainer(VaultContainer container)
    {
        if (container.VaultId == Guid.Empty || container.Revision < 1 || container.Entries.Count > 5000)
            throw new VaultFormatException("保险库容器结构无效。");
        var ids = new HashSet<Guid>();
        foreach (var record in container.Entries)
            if (record.Id == Guid.Empty || !ids.Add(record.Id) || record.Attachments.Count > 100) throw new VaultFormatException("保险库包含无效或重复条目 ID。");
        foreach (var record in container.Entries)
            foreach (var attachment in record.Attachments)
                if (attachment.Id == Guid.Empty || string.IsNullOrWhiteSpace(attachment.FileName) || attachment.Size < 0 || attachment.Size > 16 * 1024 * 1024)
                    throw new VaultFormatException("保险库包含无效附件。");
    }
}
