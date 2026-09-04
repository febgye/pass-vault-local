namespace LiquidVault.Core.Models;

public sealed record VaultEntryMetadata(
    Guid Id,
    VaultEntryType Type,
    string Title,
    string Username,
    string Url,
    string Note,
    string People,
    int PasswordStrength,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt)
{
    public static VaultEntryMetadata FromEntry(VaultEntry entry) => new(
        entry.Id, entry.Type, entry.Title,
        entry.Type == VaultEntryType.Password ? entry.Username : string.Empty,
        entry.Type == VaultEntryType.Password ? entry.Url : string.Empty,
        entry.Note,
        entry.Type == VaultEntryType.Password ? string.Empty : entry.People,
        entry.Type == VaultEntryType.Password ? PasswordPolicy.Score(entry.Password) : 4,
        entry.CreatedAt, entry.UpdatedAt);
}

public sealed record VaultEntrySecret(string Password, string Content)
{
    public static VaultEntrySecret FromEntry(VaultEntry entry) => entry.Type == VaultEntryType.Password
        ? new(entry.Password, string.Empty)
        : new(string.Empty, entry.Content);
}
