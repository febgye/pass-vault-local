using System.Security.Cryptography;
using System.Text;
using Windows.ApplicationModel.DataTransfer;

namespace LiquidVault.App.Services;

internal sealed class ClipboardGuard : IDisposable
{
    private CancellationTokenSource? _clearCancellation;

    public async Task CopySensitiveAsync(string value, TimeSpan lifetime)
    {
        _clearCancellation?.Cancel();
        _clearCancellation?.Dispose();
        _clearCancellation = new CancellationTokenSource();
        var package = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
        package.SetText(value);
        Clipboard.SetContent(package);
        Clipboard.Flush();
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        try
        {
            await Task.Delay(lifetime, _clearCancellation.Token);
            var current = Clipboard.GetContent();
            if (current.Contains(StandardDataFormats.Text))
            {
                var text = await current.GetTextAsync();
                var currentHash = SHA256.HashData(Encoding.UTF8.GetBytes(text));
                try { if (CryptographicOperations.FixedTimeEquals(expectedHash, currentHash)) Clipboard.Clear(); }
                finally { CryptographicOperations.ZeroMemory(currentHash); }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { }
        finally { CryptographicOperations.ZeroMemory(expectedHash); }
    }

    public void Dispose()
    {
        _clearCancellation?.Cancel();
        _clearCancellation?.Dispose();
        _clearCancellation = null;
    }
}
