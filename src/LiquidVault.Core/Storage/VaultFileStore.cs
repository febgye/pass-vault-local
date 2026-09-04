using System.Text.Json;
using LiquidVault.Core.Crypto;
using LiquidVault.Core.Models;

namespace LiquidVault.Core.Storage;

public sealed class VaultFileStore
{
    public const long MaxFileBytes = 64L * 1024 * 1024;
    private readonly int _backupRetention;

    public VaultFileStore(int backupRetention = 5) => _backupRetention = Math.Clamp(backupRetention, 1, 20);

    public async Task<VaultEnvelope> ReadEnvelopeAsync(string path, CancellationToken cancellationToken = default)
    {
        var file = new FileInfo(path);
        if (!file.Exists) throw new FileNotFoundException("未找到保险库文件。", path);
        if (file.Length is < 64 or > MaxFileBytes) throw new VaultFormatException("保险库文件大小无效。");
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
        try
        {
            return await JsonSerializer.DeserializeAsync<VaultEnvelope>(stream, JsonDefaults.Options, cancellationToken).ConfigureAwait(false)
                ?? throw new VaultFormatException("保险库文件为空。");
        }
        catch (JsonException ex) { throw new VaultFormatException("保险库文件 JSON 结构无效。", ex); }
    }

    public async Task WriteAtomicallyAsync(string path, VaultEnvelope envelope, Func<string, CancellationToken, Task> verifyAsync, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var tempPath = fullPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, envelope, JsonDefaults.Options, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(true);
                if (stream.Length > MaxFileBytes) throw new VaultFormatException("保险库文件大小超过 64 MiB 限制。");
            }
            await verifyAsync(tempPath, cancellationToken).ConfigureAwait(false);
            if (File.Exists(fullPath))
            {
                var backupPath = CreateBackupPath(fullPath);
                File.Replace(tempPath, fullPath, backupPath, true);
                PruneBackups(fullPath);
            }
            else File.Move(tempPath, fullPath);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    public async Task CopyVerifiedAsync(string sourcePath, string destinationPath, Func<string, CancellationToken, Task> verifyAsync, CancellationToken cancellationToken = default)
    {
        var destination = Path.GetFullPath(destinationPath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temp = destination + $".{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var target = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await source.CopyToAsync(target, cancellationToken).ConfigureAwait(false);
                await target.FlushAsync(cancellationToken).ConfigureAwait(false);
                target.Flush(true);
            }
            await verifyAsync(temp, cancellationToken).ConfigureAwait(false);
            File.Move(temp, destination, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static string CreateBackupPath(string fullPath)
    {
        var directory = Path.Combine(Path.GetDirectoryName(fullPath)!, "Backups");
        Directory.CreateDirectory(directory);
        var name = Path.GetFileNameWithoutExtension(fullPath);
        return Path.Combine(directory, $"{name}-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}.lvault.bak");
    }

    private void PruneBackups(string fullPath)
    {
        var directory = Path.Combine(Path.GetDirectoryName(fullPath)!, "Backups");
        if (!Directory.Exists(directory)) return;
        var name = Path.GetFileNameWithoutExtension(fullPath) + "-*.lvault.bak";
        foreach (var file in new DirectoryInfo(directory).EnumerateFiles(name).OrderByDescending(x => x.CreationTimeUtc).Skip(_backupRetention))
        {
            try { file.Delete(); } catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
