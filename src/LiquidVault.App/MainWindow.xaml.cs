using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using LiquidVault.App.Dialogs;
using LiquidVault.App.Services;
using LiquidVault.Core.Migration;
using LiquidVault.Core.Models;
using LiquidVault.Core.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.Storage.Pickers;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Microsoft.UI.Xaml.Media.Imaging;
using System.Runtime.InteropServices.WindowsRuntime;

namespace LiquidVault.App;

public sealed partial class MainWindow : Window
{
    private readonly VaultService _vaultService = new();
    private readonly V5BackupImporter _importer = new();
    private readonly ClipboardGuard _clipboard = new();
    private readonly AppSettingsService _settings = AppSettingsService.Load();
    private readonly ObservableCollection<EntryListRow> _visibleRows = [];
    private IReadOnlyList<VaultIndexItem> _index = [];
    private VaultSession? _session;
    private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow;
    private readonly DispatcherTimer _idleTimer;
    private int _failedUnlocks;
    private DateTimeOffset _unlockBlockedUntil;

    public MainWindow()
    {
        InitializeComponent();
        Title = "液态保险库";
        var windowIconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "LiquidVault.ico");
        if (File.Exists(windowIconPath))
        {
            AppWindow.SetIcon(windowIconPath);
        }
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1200, 800));
        EntryList.ItemsSource = _visibleRows;
        VaultPathBox.Text = _settings.CurrentVaultPath;
        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _idleTimer.Tick += (_, _) => CheckIdleLock();
        _idleTimer.Start();
        Closed += (_, _) => DisposeSensitiveState();
        ShowInitialView();
        PrivacyWindow.Enable(this);
    }

    private void ShowInitialView()
    {
        var exists = File.Exists(_settings.CurrentVaultPath);
        SetupView.Visibility = exists ? Visibility.Collapsed : Visibility.Visible;
        UnlockView.Visibility = exists ? Visibility.Visible : Visibility.Collapsed;
        VaultView.Visibility = Visibility.Collapsed;
        UnlockPathText.Text = exists ? _settings.CurrentVaultPath : string.Empty;
    }

    private async void ChooseVaultPath_Click(object sender, RoutedEventArgs e)
    {
        var path = await PickVaultSavePathAsync("我的保险库");
        if (path is not null) { VaultPathBox.Text = path; _settings.CurrentVaultPath = path; _settings.Save(); }
    }

    private async void CreateVault_Click(object sender, RoutedEventArgs e)
    {
        if (SetupPasswordBox.Password != SetupPasswordConfirmBox.Password) { ShowInfo(SetupInfo, "两次输入的主密码不一致。", InfoBarSeverity.Error); return; }
        await RunBusyAsync(SetupProgress, async () =>
        {
            var password = SetupPasswordBox.Password.ToCharArray();
            try
            {
                _session = await _vaultService.CreateAsync(VaultPathBox.Text, password, Argon2CheckBox.IsChecked != false);
                _settings.CurrentVaultPath = VaultPathBox.Text;
                _settings.Save();
                SetupPasswordBox.Password = SetupPasswordConfirmBox.Password = string.Empty;
                EnterVault();
            }
            finally { Array.Clear(password); }
        }, SetupInfo);
    }

    private async void Unlock_Click(object sender, RoutedEventArgs e) => await UnlockAsync();

    private async Task UnlockAsync()
    {
        if (DateTimeOffset.UtcNow < _unlockBlockedUntil)
        {
            ShowInfo(UnlockInfo, $"验证失败次数过多，请等待 {Math.Ceiling((_unlockBlockedUntil - DateTimeOffset.UtcNow).TotalSeconds)} 秒。", InfoBarSeverity.Warning);
            return;
        }
        await RunBusyAsync(UnlockProgress, async () =>
        {
            var password = UnlockPasswordBox.Password.ToCharArray();
            UnlockPasswordBox.Password = string.Empty;
            try
            {
                _session = await _vaultService.OpenAsync(_settings.CurrentVaultPath, password);
                _failedUnlocks = 0;
                _unlockBlockedUntil = default;
                EnterVault();
            }
            catch (VaultAuthenticationException)
            {
                _failedUnlocks++;
                if (_failedUnlocks >= 3) _unlockBlockedUntil = DateTimeOffset.UtcNow.AddSeconds(Math.Min(600, 60 + (_failedUnlocks - 3) * 120));
                throw;
            }
            finally { Array.Clear(password); }
        }, UnlockInfo);
    }

    private async void OpenOtherVault_Click(object sender, RoutedEventArgs e)
    {
        var path = await PickOpenPathAsync([".lvault"]);
        if (path is null) return;
        _settings.CurrentVaultPath = path;
        _settings.Save();
        UnlockPathText.Text = path;
        UnlockPasswordBox.Focus(FocusState.Programmatic);
    }

    private async void MigrateV5_Click(object sender, RoutedEventArgs e)
    {
        var backupPath = await PickOpenPathAsync([".json"]);
        if (backupPath is null) return;
        var destination = await PickVaultSavePathAsync("迁移后的保险库");
        if (destination is null) return;
        var backupPassword = new PasswordBox { Header = "旧 v5 备份主密码", MaxLength = 256 };
        var newPassword = new PasswordBox { Header = "原生保险库新主密码", MaxLength = 256, PasswordRevealMode = PasswordRevealMode.Peek };
        var confirm = new PasswordBox { Header = "确认新主密码", MaxLength = 256 };
        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(backupPassword); panel.Children.Add(newPassword); panel.Children.Add(confirm);
        var dialog = CreateDialog("迁移 v5 加密备份", panel, "验证并迁移");
        var result = await dialog.ShowAsync();
        if (result != ContentDialogResult.Primary) return;
        if (newPassword.Password != confirm.Password) { ShowInfo(SetupInfo, "两次新密码不一致。", InfoBarSeverity.Error); return; }
        await RunBusyAsync(SetupProgress, async () =>
        {
            var oldChars = backupPassword.Password.ToCharArray();
            var newChars = newPassword.Password.ToCharArray();
            backupPassword.Password = newPassword.Password = confirm.Password = string.Empty;
            try
            {
                _session = await _importer.MigrateAsync(backupPath, oldChars, destination, newChars);
                _settings.CurrentVaultPath = destination;
                _settings.Save();
                EnterVault();
                ShowInfo(StatusInfo, "v5 备份已完整验证并迁移，旧文件未被修改。", InfoBarSeverity.Success);
            }
            finally { Array.Clear(oldChars); Array.Clear(newChars); }
        }, SetupInfo);
    }

    private void EnterVault()
    {
        if (_session is null) return;
        _index = _session.GetIndex();
        _lastActivity = DateTimeOffset.UtcNow;
        SetupView.Visibility = UnlockView.Visibility = Visibility.Collapsed;
        VaultView.Visibility = Visibility.Visible;
        UnlockInfo.IsOpen = false;
        RefreshList();
        RefreshStatus();
    }

    private void Lock_Click(object sender, RoutedEventArgs e) => LockVault();

    private void LockVault()
    {
        _session?.Dispose();
        _session = null;
        _index = [];
        _visibleRows.Clear();
        SearchBox.Text = string.Empty;
        DeepSearchCheckBox.IsChecked = false;
        VaultView.Visibility = Visibility.Collapsed;
        SetupView.Visibility = Visibility.Collapsed;
        UnlockView.Visibility = Visibility.Visible;
        UnlockPathText.Text = _settings.CurrentVaultPath;
        UnlockPasswordBox.Password = string.Empty;
        UnlockPasswordBox.Focus(FocusState.Programmatic);
    }

    private async void AddEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        var dialog = new EntryEditorDialog(windowHandle: WinRT.Interop.WindowNative.GetWindowHandle(this)) { XamlRoot = RootGrid.XamlRoot };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        if (dialog.ResultEntry is not { } entry) return;
        await ExecuteVaultOperationAsync(async () =>
        {
            await _session.UpsertAsync(entry);
            EnsureImportedSourcesDeleted(entry.Attachments.Select(x => x.OriginalPath));
        }, "资料已加密保存，原文件已从电脑位置移除。");
        entry.ClearSecrets();
    }

    private async void EditEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || sender is not Button { Tag: Guid id }) return;
        var entry = _session.OpenEntry(id);
        try
        {
            var dialog = new EntryEditorDialog(entry, WinRT.Interop.WindowNative.GetWindowHandle(this)) { XamlRoot = RootGrid.XamlRoot };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
            if (dialog.ResultEntry is not { } updated) return;
            await ExecuteVaultOperationAsync(async () =>
            {
                await _session.UpsertAsync(updated);
                EnsureImportedSourcesDeleted(dialog.NewSourcePaths);
            }, "资料已更新，新增原文件已从电脑位置移除。");
            updated.ClearSecrets();
        }
        finally { entry.ClearSecrets(); }
    }

    private async void DeleteEntry_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || sender is not Button { Tag: Guid id }) return;
        var dialog = CreateDialog("删除资料", new TextBlock { Text = "确定删除这条资料？删除后只能从加密备份恢复。", TextWrapping = TextWrapping.Wrap }, "删除");
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        await ExecuteVaultOperationAsync(async () => await _session.DeleteAsync(id), "资料已删除。");
    }

    private async void PreviewFile_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || sender is not Button { Tag: Guid id }) return;
        var entry = _session.OpenEntry(id);
        try
        {
            if (entry.Attachments.Count == 0) throw new VaultFormatException("该文件资料没有附件。");
            await ShowAttachmentPreviewAsync(entry.Attachments[0]);
        }
        catch (Exception ex) when (ex is VaultException or IOException or InvalidOperationException)
        {
            ShowInfo(StatusInfo, SafeMessage(ex), InfoBarSeverity.Error);
        }
        finally { entry.ClearSecrets(); }
    }

    private async Task ShowAttachmentPreviewAsync(VaultAttachment attachment)
    {
        if (!AttachmentPreviewService.IsPreviewable(attachment.FileName))
        {
            await new ContentDialog { XamlRoot = RootGrid.XamlRoot, Title = "暂不支持预览", Content = "此文件类型不能在密码库内直接查看，请使用编辑窗口中的导出功能。", CloseButtonText = "关闭" }.ShowAsync();
            return;
        }
        if (AttachmentPreviewService.IsTextPreview(attachment.FileName))
        {
            var text = new TextBlock { Text = AttachmentPreviewService.DecodeText(attachment.FileName, attachment.Content), TextWrapping = TextWrapping.NoWrap, FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"), MinWidth = 650 };
            await new ContentDialog { XamlRoot = RootGrid.XamlRoot, Title = attachment.FileName, Content = new ScrollViewer { Content = text, Width = 650, Height = 420, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }, CloseButtonText = "关闭" }.ShowAsync();
            text.Text = string.Empty;
            return;
        }
        var image = new Image { Stretch = Microsoft.UI.Xaml.Media.Stretch.Uniform, MaxWidth = 760, MaxHeight = 560 };
        using var stream = new MemoryStream(attachment.Content, writable: false);
        try
        {
            var bitmap = new BitmapImage { DecodePixelWidth = 2048, DecodePixelHeight = 2048 };
            await bitmap.SetSourceAsync(stream.AsRandomAccessStream());
            image.Source = bitmap;
            await new ContentDialog { XamlRoot = RootGrid.XamlRoot, Title = attachment.FileName, Content = image, CloseButtonText = "关闭" }.ShowAsync();
            image.Source = null;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException or OutOfMemoryException or COMException)
        {
            await new ContentDialog { XamlRoot = RootGrid.XamlRoot, Title = "无法查看", Content = "图片无法解码或占用内存过大，请导出后使用其他程序查看。", CloseButtonText = "关闭" }.ShowAsync();
        }
    }

    private async void AddFile_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        await CreateFileEntriesAsync(await picker.PickMultipleFilesAsync());
    }

    private void RootGrid_DragOver(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        e.AcceptedOperation = DataPackageOperation.Copy;
        e.DragUIOverride.Caption = "创建文件资料";
        e.Handled = true;
    }

    private async void RootGrid_Drop(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        await CreateFileEntriesAsync((await e.DataView.GetStorageItemsAsync()).OfType<StorageFile>());
        e.Handled = true;
    }

    private async Task CreateFileEntriesAsync(IEnumerable<StorageFile> files)
    {
        if (_session is null) return;
        var failures = new List<string>();
        foreach (var file in files)
        {
            try
            {
                var properties = await file.GetBasicPropertiesAsync();
                if (properties.Size > 16 * 1024 * 1024) throw new VaultFormatException($"文件 {file.Name} 超过 16 MiB 限制。");
                var content = await File.ReadAllBytesAsync(file.Path);
                var entry = new VaultEntry
                {
                    Type = VaultEntryType.File,
                    Title = Path.GetFileNameWithoutExtension(file.Name),
                    Attachments = [VaultAttachment.Create(file.Name, file.ContentType, content, file.Path)]
                };
                Array.Clear(content);
                await ExecuteVaultOperationAsync(async () =>
                {
                    await _session.UpsertAsync(entry);
                EnsureImportedSourcesDeleted(entry.Attachments.Select(x => x.OriginalPath));
                }, $"已添加文件并移除原文件：{file.Name}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or VaultException)
            {
                failures.Add($"{file.Name}: {SafeMessage(ex)}");
            }
        }
        if (failures.Count > 0) ShowInfo(StatusInfo, string.Join(Environment.NewLine, failures), InfoBarSeverity.Warning);
    }

    private static void EnsureImportedSourcesDeleted(IEnumerable<string> paths)
    {
        foreach (var path in paths.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                if (!VaultAttachment.IsSafeOriginalPath(path)) throw new VaultFormatException("原始文件路径不安全。");
                if (File.Exists(path)) File.Delete(path);
                if (File.Exists(path)) throw new IOException("原文件未能移除，已保留加密副本。");
            }
            catch (IOException ex) { throw new VaultException($"原文件未能移除，但加密副本已保存：{ex.Message}"); }
            catch (UnauthorizedAccessException ex) { throw new VaultException($"原文件未能移除，但加密副本已保存：{ex.Message}"); }
        }
    }

    private async void CopyPassword_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || sender is not Button { Tag: Guid id }) return;
        var password = _session.RevealPassword(id);
        _ = _clipboard.CopySensitiveAsync(password, TimeSpan.FromSeconds(20));
        password = string.Empty;
        ShowInfo(StatusInfo, "密码已复制，20 秒后仅在剪贴板内容未变化时清除。", InfoBarSeverity.Warning);
    }

    private async void RevealPassword_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || sender is not Button { Tag: Guid id }) return;
        var password = _session.RevealPassword(id);
        var box = new TextBox { Text = password, IsReadOnly = true, FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas") };
        password = string.Empty;
        var dialog = CreateDialog("密码（7 秒后隐藏）", box, null);
        var show = dialog.ShowAsync();
        await Task.Delay(TimeSpan.FromSeconds(7));
        box.Text = string.Empty;
        dialog.Hide();
        _ = await show;
    }

    private async void ExportBackup_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        var passwordBox = new PasswordBox { Header = "重新输入当前主密码", MaxLength = 256 };
        var dialog = CreateDialog("导出已验证的加密备份", passwordBox, "验证并导出");
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        var destination = await PickVaultSavePathAsync($"liquid-vault-backup-{DateTime.Now:yyyy-MM-dd}");
        if (destination is null) return;
        var password = passwordBox.Password.ToCharArray();
        passwordBox.Password = string.Empty;
        try { await ExecuteVaultOperationAsync(async () => await _session.ExportVerifiedBackupAsync(destination, password), "加密备份已完整验证并导出。"); }
        finally { Array.Clear(password); }
    }

    private async void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        var current = new PasswordBox { Header = "当前主密码", MaxLength = 256 };
        var next = new PasswordBox { Header = "新主密码", MaxLength = 256, PasswordRevealMode = PasswordRevealMode.Peek };
        var confirm = new PasswordBox { Header = "确认新主密码", MaxLength = 256 };
        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(current); panel.Children.Add(next); panel.Children.Add(confirm);
        var dialog = CreateDialog("修改主密码", panel, "验证并重新加密");
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        if (next.Password != confirm.Password) { ShowInfo(StatusInfo, "两次新密码不一致。", InfoBarSeverity.Error); return; }
        var currentChars = current.Password.ToCharArray();
        var newChars = next.Password.ToCharArray();
        current.Password = next.Password = confirm.Password = string.Empty;
        try
        {
            await _vaultService.VerifyPasswordAsync(_session.Path, currentChars);
            await ExecuteVaultOperationAsync(async () => await _session.ChangeMasterPasswordAsync(newChars, true), "主密码已更新，保险库已原子重加密。");
        }
        finally { Array.Clear(currentChars); Array.Clear(newChars); }
    }

    private async void DestroyVault_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        var passwordBox = new PasswordBox { Header = "输入主密码确认", MaxLength = 256 };
        var deleteBackups = new CheckBox { Content = "同时删除程序自动生成的本地历史备份", IsChecked = false };
        var warning = new TextBlock { Text = "此操作无法撤销。手动导出到其他位置的备份不会被删除。SSD 上无法保证物理覆写。", TextWrapping = TextWrapping.Wrap };
        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(warning); panel.Children.Add(passwordBox); panel.Children.Add(deleteBackups);
        var dialog = CreateDialog("销毁保险库", panel, "永久删除");
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        var password = passwordBox.Password.ToCharArray();
        passwordBox.Password = string.Empty;
        var path = _session.Path;
        try
        {
            await _vaultService.VerifyPasswordAsync(path, password);
            _session.Dispose();
            _session = null;
            await _vaultService.DestroyAsync(path, password, deleteBackups.IsChecked == true);
            _index = [];
            _visibleRows.Clear();
            SetupView.Visibility = Visibility.Visible;
            UnlockView.Visibility = VaultView.Visibility = Visibility.Collapsed;
            ShowInfo(SetupInfo, "保险库已删除。程序无法保证 SSD 上的物理覆写。", InfoBarSeverity.Warning);
        }
        catch (Exception ex) { ShowInfo(StatusInfo, SafeMessage(ex), InfoBarSeverity.Error); }
        finally { Array.Clear(password); }
    }

    private async void SecuritySettings_Click(object sender, RoutedEventArgs e)
    {
        var choices = new[] { 60, 180, 300, 600, 1800 };
        var timeout = new ComboBox { Header = "闲置自动锁定" };
        foreach (var seconds in choices)
            timeout.Items.Add(new ComboBoxItem { Content = $"{seconds / 60} 分钟", Tag = seconds });
        timeout.SelectedIndex = Array.IndexOf(choices, (int)_settings.IdleTimeout.TotalSeconds);
        if (timeout.SelectedIndex < 0) timeout.SelectedIndex = 1;
        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(timeout);
        var dialog = CreateDialog("安全设置", panel, "保存");
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        _settings.IdleTimeout = TimeSpan.FromSeconds((int)((ComboBoxItem)timeout.SelectedItem).Tag);
        _settings.Save();
        ShowInfo(StatusInfo, "安全设置已保存。", InfoBarSeverity.Success);
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => RefreshList();
    private void DeepSearchCheckBox_Changed(object sender, RoutedEventArgs e) => RefreshList();
    private void SortBox_SelectionChanged(object sender, SelectionChangedEventArgs e) => RefreshList();
    private void CategoryList_SelectionChanged(object sender, SelectionChangedEventArgs e) => RefreshList();
    private void EntryList_ItemClick(object sender, ItemClickEventArgs e) { _lastActivity = DateTimeOffset.UtcNow; }

    private void RefreshList()
    {
        if (_session is null) return;
        var query = SearchBox.Text.Trim();
        var category = (CategoryList.SelectedItem as ListViewItem)?.Tag?.ToString() ?? "All";
        IEnumerable<VaultIndexItem> items = _index;
        if (Enum.TryParse<VaultEntryType>(category, out var type)) items = items.Where(x => x.Type == type);
        else if (category == "Recent") items = items.Where(x => x.UpdatedAt >= DateTimeOffset.UtcNow.AddDays(-7));
        if (query.Length > 0)
        {
            var contentMatches = DeepSearchCheckBox.IsChecked == true ? _session.FindInTextContents(query) : new HashSet<Guid>();
            items = items.Where(x => $"{x.Title} {x.Username} {x.Url} {x.Note} {x.People}".Contains(query, StringComparison.CurrentCultureIgnoreCase) || contentMatches.Contains(x.Id));
        }
        items = (SortBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() switch
        {
            "Created" => items.OrderByDescending(x => x.CreatedAt),
            "Title" => items.OrderBy(x => x.Title, StringComparer.CurrentCultureIgnoreCase),
            "Strength" => items.OrderByDescending(x => x.PasswordStrength).ThenBy(x => x.Title, StringComparer.CurrentCultureIgnoreCase),
            _ => items.OrderByDescending(x => x.UpdatedAt)
        };
        _visibleRows.Clear();
        foreach (var item in items) _visibleRows.Add(EntryListRow.From(item));
    }

    private async Task ExecuteVaultOperationAsync(Func<Task> operation, string success)
    {
        try
        {
            await operation();
            _index = _session?.GetIndex() ?? [];
            RefreshList();
            RefreshStatus();
            ShowInfo(StatusInfo, success, InfoBarSeverity.Success);
        }
        catch (Exception ex) { ShowInfo(StatusInfo, SafeMessage(ex), InfoBarSeverity.Error); }
    }

    private void RefreshStatus()
    {
        if (_session is null) return;
        VaultStatusText.Text = $"{_index.Count} 条资料 · 修订 {_session.Revision} · {_session.Path}";
    }

    private ContentDialog CreateDialog(string title, object content, string? primaryText) => new()
    {
        XamlRoot = RootGrid.XamlRoot,
        Title = title,
        Content = content,
        PrimaryButtonText = primaryText ?? string.Empty,
        CloseButtonText = "关闭",
        DefaultButton = primaryText is null ? ContentDialogButton.Close : ContentDialogButton.Primary
    };

    private async Task<string?> PickVaultSavePathAsync(string suggestedName)
    {
        var picker = new FileSavePicker { SuggestedFileName = suggestedName };
        picker.FileTypeChoices.Add("液态保险库", [".lvault"]);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        return (await picker.PickSaveFileAsync())?.Path;
    }

    private async Task<string?> PickOpenPathAsync(IReadOnlyList<string> extensions)
    {
        var picker = new FileOpenPicker();
        foreach (var extension in extensions) picker.FileTypeFilter.Add(extension);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        return (await picker.PickSingleFileAsync())?.Path;
    }

    private async Task RunBusyAsync(ProgressRing progress, Func<Task> operation, InfoBar info)
    {
        progress.IsActive = true;
        info.IsOpen = false;
        try { await operation(); }
        catch (Exception ex) { ShowInfo(info, SafeMessage(ex), InfoBarSeverity.Error); }
        finally { progress.IsActive = false; }
    }

    private static string SafeMessage(Exception exception) => exception switch
    {
        VaultException or IOException or UnauthorizedAccessException => exception.Message,
        _ => "操作失败。敏感错误详情未写入日志，请重试或恢复备份。"
    };

    private static void ShowInfo(InfoBar bar, string message, InfoBarSeverity severity)
    {
        bar.Message = message; bar.Severity = severity; bar.IsOpen = true;
    }

    private void RootGrid_KeyDown(object sender, KeyRoutedEventArgs e) => _lastActivity = DateTimeOffset.UtcNow;
    private void RootGrid_PointerMoved(object sender, PointerRoutedEventArgs e) => _lastActivity = DateTimeOffset.UtcNow;
    private async void UnlockPasswordBox_KeyDown(object sender, KeyRoutedEventArgs e) { if (e.Key == Windows.System.VirtualKey.Enter) await UnlockAsync(); }

    private void CheckIdleLock()
    {
        if (_session is not null && DateTimeOffset.UtcNow - _lastActivity >= _settings.IdleTimeout) LockVault();
    }

    private void DisposeSensitiveState()
    {
        _idleTimer.Stop();
        _clipboard.Dispose();
        _session?.Dispose();
        _session = null;
        UnlockPasswordBox.Password = SetupPasswordBox.Password = SetupPasswordConfirmBox.Password = string.Empty;
    }
}

public sealed record EntryListRow(Guid Id, string Title, string Subtitle, Visibility PasswordActionsVisibility, Visibility FileActionsVisibility)
{
    public static EntryListRow From(VaultIndexItem item)
    {
        var label = item.Type switch { VaultEntryType.Password => "密码", VaultEntryType.Note => "私密笔记", VaultEntryType.Chat => "聊天记录", VaultEntryType.File => "文件", _ => "通用文本" };
        var detail = item.Type == VaultEntryType.Password ? item.Username : item.People;
        return new EntryListRow(item.Id, item.Title, $"{label} · {detail} · 更新 {item.UpdatedAt.LocalDateTime:g}", item.Type == VaultEntryType.Password ? Visibility.Visible : Visibility.Collapsed, item.Type == VaultEntryType.File ? Visibility.Visible : Visibility.Collapsed);
    }
}
