using System.Text.Json;

namespace LiquidVault.App.Services;

internal sealed class AppSettingsService
{
    private readonly string _path;
    public string CurrentVaultPath { get; set; }
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(3);

    public AppSettingsService()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LiquidVault");
        Directory.CreateDirectory(root);
        _path = Path.Combine(root, "settings.json");
        CurrentVaultPath = Path.Combine(root, "Data", "我的保险库.lvault");
    }

    public static AppSettingsService Load()
    {
        var defaults = new AppSettingsService();
        if (!File.Exists(defaults._path)) return defaults;
        try
        {
            var saved = JsonSerializer.Deserialize<SavedSettings>(File.ReadAllText(defaults._path));
            if (saved is not null && !string.IsNullOrWhiteSpace(saved.CurrentVaultPath)) defaults.CurrentVaultPath = Path.GetFullPath(saved.CurrentVaultPath);
            if (saved?.IdleTimeoutSeconds is >= 60 and <= 3600) defaults.IdleTimeout = TimeSpan.FromSeconds(saved.IdleTimeoutSeconds);
        }
        catch (Exception) { }
        return defaults;
    }

    public void Save()
    {
        var value = new SavedSettings(CurrentVaultPath, (int)IdleTimeout.TotalSeconds);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(value));
        File.Move(temp, _path, true);
    }

    private sealed record SavedSettings(string CurrentVaultPath, int IdleTimeoutSeconds);
}
