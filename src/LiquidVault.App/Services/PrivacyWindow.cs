using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;

namespace LiquidVault.App.Services;

internal static partial class PrivacyWindow
{
    private const uint WdaExcludeFromCapture = 0x00000011;

    public static void Enable(Window window)
    {
        try
        {
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
            _ = SetWindowDisplayAffinity(hwnd, WdaExcludeFromCapture);
        }
        catch (Exception) { }
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowDisplayAffinity(nint hWnd, uint dwAffinity);
}
