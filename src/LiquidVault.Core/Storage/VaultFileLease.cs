using System.Security.Cryptography;
using System.Text;
using LiquidVault.Core.Models;

namespace LiquidVault.Core.Storage;

public sealed class VaultFileLease : IDisposable
{
    private FileStream? _stream;
    private readonly string _lockPath;

    private VaultFileLease(FileStream stream, string lockPath)
    {
        _stream = stream;
        _lockPath = lockPath;
    }

    public static VaultFileLease Acquire(string vaultPath)
    {
        var lockPath = Path.GetFullPath(vaultPath) + ".lock";
        Directory.CreateDirectory(Path.GetDirectoryName(lockPath)!);
        try
        {
            var stream = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose);
            stream.SetLength(0);
            var marker = Encoding.UTF8.GetBytes($"{Environment.ProcessId}|{DateTimeOffset.UtcNow:O}");
            stream.Write(marker);
            stream.Flush(true);
            CryptographicOperations.ZeroMemory(marker);
            return new VaultFileLease(stream, lockPath);
        }
        catch (IOException) { throw new VaultBusyException(); }
    }

    public void Dispose()
    {
        var stream = Interlocked.Exchange(ref _stream, null);
        stream?.Dispose();
        try { if (File.Exists(_lockPath)) File.Delete(_lockPath); } catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
