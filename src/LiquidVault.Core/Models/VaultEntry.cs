namespace LiquidVault.Core.Models;

public sealed class VaultEntry
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public VaultEntryType Type { get; set; } = VaultEntryType.Password;
    public string Title { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Note { get; set; } = string.Empty;
    public string People { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public List<VaultAttachment> Attachments { get; set; } = [];
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public string OriginalPath { get; init; } = string.Empty;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    public void Validate()
    {
        if (Id == Guid.Empty) throw new VaultFormatException("条目 ID 无效。");
        if (string.IsNullOrWhiteSpace(Title) || Title.Length > 120) throw new VaultFormatException("标题不能为空且不能超过 120 个字符。");
        if (Username.Length > 200 || Password.Length > 400 || Url.Length > 300 || Note.Length > 2000 || People.Length > 300 || Content.Length > 30000)
            throw new VaultFormatException("条目字段超过允许长度。");
        if (Type == VaultEntryType.Password && string.IsNullOrEmpty(Password)) throw new VaultFormatException("密码条目不能为空。");
        if (Type != VaultEntryType.Password && Type != VaultEntryType.File && string.IsNullOrWhiteSpace(Content)) throw new VaultFormatException("正文不能为空。");
        if (Type == VaultEntryType.File && Attachments.Count == 0) throw new VaultFormatException("文件资料必须包含至少一个附件。");
        if (Attachments.Count > 100) throw new VaultFormatException("单条资料最多只能包含 100 个附件。");
        foreach (var attachment in Attachments) attachment.Validate();
        if (!string.IsNullOrWhiteSpace(Url) && (!Uri.TryCreate(Url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)))
            throw new VaultFormatException("网址只允许 http 或 https。");
    }

    public void ClearSecrets()
    {
        Password = string.Empty;
        Content = string.Empty;
        foreach (var attachment in Attachments) attachment.ClearContent();
    }
}

public sealed class VaultAttachment
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string FileName { get; init; } = string.Empty;
    public string ContentType { get; init; } = "application/octet-stream";
    public byte[] Content { get; init; } = [];
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    public static VaultAttachment Create(string fileName, string contentType, byte[] content, string originalPath = "") => new()
    {
        FileName = fileName,
        ContentType = contentType,
        OriginalPath = originalPath,
        Content = content.ToArray()
    };

    public long Size => Content.LongLength;
    public string OriginalPath { get; init; } = string.Empty;

    public static bool IsSafeOriginalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal)) return false;
        var full = Path.GetFullPath(path);
        return Path.GetDirectoryName(full) is { Length: > 0 } directory && !string.Equals(full, Path.GetPathRoot(full), StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(Path.GetFileName(full));
    }

    public void Validate()
    {
        if (Id == Guid.Empty || string.IsNullOrWhiteSpace(FileName) || FileName.Length > 260)
            throw new VaultFormatException("附件名称无效。");
        if (FileName.Contains('/') || FileName.Contains('\\') || FileName is "." or "..")
            throw new VaultFormatException("附件名称不能包含路径。");
        if (Content.Length > 16 * 1024 * 1024) throw new VaultFormatException("单个附件不能超过 16 MiB。");
        if (ContentType.Length > 200 || (!string.IsNullOrWhiteSpace(OriginalPath) && !IsSafeOriginalPath(OriginalPath))) throw new VaultFormatException("附件类型或原始路径无效。");
    }

    public void ClearContent() => Array.Clear(Content);
}
