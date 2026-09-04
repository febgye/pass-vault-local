using System.Text;

namespace LiquidVault.Core.Services;

public static class AttachmentPreviewService
{
    private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase) { ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp" };
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase) { ".txt", ".csv", ".json", ".xml", ".md", ".log" };
    public const int MaxTextPreviewBytes = 2 * 1024 * 1024;

    public static bool IsPreviewable(string fileName) => IsImagePreview(fileName) || IsTextPreview(fileName);
    public static bool IsImagePreview(string fileName) => ImageExtensions.Contains(Path.GetExtension(fileName));
    public static bool IsTextPreview(string fileName) => TextExtensions.Contains(Path.GetExtension(fileName));

    public static string DecodeText(string fileName, byte[] content)
    {
        if (!IsTextPreview(fileName)) throw new InvalidOperationException("该文件类型不支持文本预览。");
        if (content.Length > MaxTextPreviewBytes) throw new InvalidOperationException("文本文件超过 2 MiB 预览限制，请导出后查看。");
        return Encoding.UTF8.GetString(content);
    }
}
