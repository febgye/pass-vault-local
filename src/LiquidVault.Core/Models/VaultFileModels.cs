using System.Text.Json.Serialization;

namespace LiquidVault.Core.Models;

public sealed class VaultEnvelope
{
    public const string ExpectedMagic = "LIQUID_VAULT_NATIVE";
    public const int CurrentVersion = 2;

    [JsonPropertyName("magic")] public string Magic { get; init; } = ExpectedMagic;
    [JsonPropertyName("version")] public int Version { get; init; } = CurrentVersion;
    [JsonPropertyName("kdf")] public required KdfDescriptor Kdf { get; init; }
    [JsonPropertyName("cipher")] public required CipherBlob Cipher { get; init; }
}

public sealed class KdfDescriptor
{
    [JsonPropertyName("algorithm")] public string Algorithm { get; init; } = "argon2id";
    [JsonPropertyName("salt")] public required string Salt { get; init; }
    [JsonPropertyName("memoryKiB")] public int MemoryKiB { get; init; } = 65536;
    [JsonPropertyName("iterations")] public int Iterations { get; init; } = 3;
    [JsonPropertyName("parallelism")] public int Parallelism { get; init; } = 1;
}

public sealed class CipherBlob
{
    [JsonPropertyName("nonce")] public required string Nonce { get; init; }
    [JsonPropertyName("ciphertext")] public required string Ciphertext { get; init; }
    [JsonPropertyName("tag")] public required string Tag { get; init; }
}

public sealed class VaultContainer
{
    [JsonPropertyName("vaultId")] public Guid VaultId { get; init; } = Guid.NewGuid();
    [JsonPropertyName("revision")] public long Revision { get; set; } = 1;
    [JsonPropertyName("createdAt")] public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    [JsonPropertyName("updatedAt")] public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    [JsonPropertyName("entries")] public List<EncryptedEntryRecord> Entries { get; init; } = [];
}

public sealed class EncryptedEntryRecord
{
    [JsonPropertyName("id")] public Guid Id { get; init; }
    [JsonPropertyName("meta")] public required CipherBlob Metadata { get; init; }
    [JsonPropertyName("secret")] public required CipherBlob Secret { get; init; }
    [JsonPropertyName("attachments")] public List<EncryptedAttachmentRecord> Attachments { get; init; } = [];
}

public sealed class EncryptedAttachmentRecord
{
    [JsonPropertyName("id")] public Guid Id { get; init; }
    [JsonPropertyName("fileName")] public required string FileName { get; init; }
    [JsonPropertyName("contentType")] public required string ContentType { get; init; }
    [JsonPropertyName("size")] public long Size { get; init; }
    [JsonPropertyName("createdAt")] public DateTimeOffset CreatedAt { get; init; }
    [JsonPropertyName("originalPath")] public string OriginalPath { get; init; } = string.Empty;
    [JsonPropertyName("content")] public required CipherBlob Content { get; init; }
}

public sealed record VaultIndexItem(
    Guid Id,
    VaultEntryType Type,
    string Title,
    string Username,
    string Url,
    string Note,
    string People,
    int PasswordStrength,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);
