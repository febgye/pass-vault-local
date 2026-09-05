using System.Collections.ObjectModel;
using LiquidVault.Core.Models;
using LiquidVault.Core.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Imaging;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;

using System.Runtime.InteropServices;

namespace LiquidVault.App.Dialogs;

public sealed partial class EntryEditorDialog : ContentDialog
{
    private readonly Guid _id;
    private readonly DateTimeOffset _createdAt;
    private readonly nint _windowHandle;
    private readonly ObservableCollection<AttachmentRow> _attachments = [];
    private readonly List<string> _newSourcePaths = [];
    public VaultEntry? ResultEntry { get; private set; }
    public IReadOnlyList<string> NewSourcePaths => _newSourcePaths;

    public EntryEditorDialog(VaultEntry? entry = null, nint windowHandle = default)
    {
        InitializeComponent();
        _windowHandle = windowHandle;
        AttachmentList.ItemsSource = _attachments;
        _id = entry?.Id ?? Guid.NewGuid();
        _createdAt = entry?.CreatedAt ?? DateTimeOffset.UtcNow;
        Title = entry is null ? "新增资料" : "编辑资料";
        if (entry is not null) LoadEntry(entry);
        PrimaryButtonClick += ValidateBeforeClose;
        Closed += (_, _) => ClearFields();
    }

    public VaultEntry BuildEntry()
    {
        var type = Enum.Parse<VaultEntryType>(((ComboBoxItem)TypeBox.SelectedItem).Tag.ToString()!);
        return new VaultEntry
        {
            Id = _id,
            Type = type,
            Title = TitleBox.Text.Trim(),
            Username = type == VaultEntryType.Password ? UsernameBox.Text : string.Empty,
            Password = type == VaultEntryType.Password ? PasswordValueBox.Password : string.Empty,
            Url = type == VaultEntryType.Password ? UrlBox.Text.Trim() : string.Empty,
            Note = NoteBox.Text,
            People = type == VaultEntryType.Password ? string.Empty : PeopleBox.Text,
            Content = type == VaultEntryType.Password ? string.Empty : ContentBox.Text,
            Attachments = _attachments.Select(x => new VaultAttachment
            {
                Id = x.Attachment.Id,
                FileName = x.Attachment.FileName,
                ContentType = x.Attachment.ContentType,
                Content = x.Attachment.Content.ToArray(),
                OriginalPath = x.Attachment.OriginalPath,
                CreatedAt = x.Attachment.CreatedAt
            }).ToList(),
            CreatedAt = _createdAt,
            UpdatedAt = DateTimeOffset.UtcNow
        };
    }

    private void LoadEntry(VaultEntry entry)
    {
        TypeBox.SelectedIndex = (int)entry.Type;
        TitleBox.Text = entry.Title;
        UsernameBox.Text = entry.Username;
        PasswordValueBox.Password = entry.Password;
        UrlBox.Text = entry.Url;
        NoteBox.Text = entry.Note;
        PeopleBox.Text = entry.People;
        ContentBox.Text = entry.Content;
        foreach (var attachment in entry.Attachments)
            _attachments.Add(new AttachmentRow(new VaultAttachment
            {
                Id = attachment.Id,
                FileName = attachment.FileName,
                ContentType = attachment.ContentType,
                Content = attachment.Content.ToArray(),
                OriginalPath = attachment.OriginalPath,
                CreatedAt = attachment.CreatedAt
            }));
        UpdateTypeVisibility();
    }

    private void ValidateBeforeClose(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        try { ResultEntry = BuildEntry(); ResultEntry.Validate(); ValidationBar.IsOpen = false; }
        catch (VaultException ex) { args.Cancel = true; ValidationBar.Message = ex.Message; ValidationBar.IsOpen = true; }
    }

    private void TypeBox_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateTypeVisibility();
    private void UpdateTypeVisibility()
    {
        if (PasswordFields is null || TypeBox.SelectedItem is not ComboBoxItem item) return;
        var isPassword = string.Equals(item.Tag?.ToString(), "Password", StringComparison.Ordinal);
        PasswordFields.Visibility = isPassword ? Visibility.Visible : Visibility.Collapsed;
        var isFile = string.Equals(item.Tag?.ToString(), "File", StringComparison.Ordinal);
        TextFields.Visibility = isPassword || isFile ? Visibility.Collapsed : Visibility.Visible;
    }

    private void GeneratePassword_Click(object sender, RoutedEventArgs e) => PasswordValueBox.Password = PasswordPolicy.Generate();

    private async void ChooseAttachments_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _windowHandle);
        await AddFilesAsync(await picker.PickMultipleFilesAsync());
    }

    private void Attachment_DragOver(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        e.AcceptedOperation = DataPackageOperation.Copy;
        e.DragUIOverride.Caption = "添加为加密附件";
        e.Handled = true;
    }

    private async void Attachment_Drop(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        var files = (await e.DataView.GetStorageItemsAsync()).OfType<StorageFile>();
        await AddFilesAsync(files);
        e.Handled = true;
    }

    private async Task AddFilesAsync(IEnumerable<StorageFile> files)
    {
        var pending = new List<AttachmentRow>();
        try
        {
            foreach (var file in files)
            {
                var properties = await file.GetBasicPropertiesAsync();
                if (properties.Size > 16 * 1024 * 1024) throw new VaultFormatException($"附件 {file.Name} 超过 16 MiB 限制。");
                var content = await File.ReadAllBytesAsync(file.Path);
                pending.Add(new AttachmentRow(VaultAttachment.Create(file.Name, file.ContentType, content, file.Path)));
                Array.Clear(content);
            }
            foreach (var row in pending)
            {
                _attachments.Add(row);
                if (!string.IsNullOrWhiteSpace(row.Attachment.OriginalPath)) _newSourcePaths.Add(row.Attachment.OriginalPath);
            }
            ValidationBar.IsOpen = false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or VaultException)
        {
            foreach (var row in pending) row.Attachment.ClearContent();
            ValidationBar.Message = ex.Message;
            ValidationBar.IsOpen = true;
        }
    }

    private void RemoveAttachment_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: AttachmentRow row } && _attachments.Remove(row))
        {
            if (!string.IsNullOrWhiteSpace(row.Attachment.OriginalPath))
                _newSourcePaths.Remove(row.Attachment.OriginalPath);
        }
    }

    private async void ExportAttachment_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: AttachmentRow row }) return;
        var picker = new FileSavePicker { SuggestedFileName = row.Attachment.FileName };
        picker.FileTypeChoices.Add("文件", [Path.GetExtension(row.Attachment.FileName) is { Length: > 0 } extension ? extension : ".bin"]);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _windowHandle);
        var destination = await picker.PickSaveFileAsync();
        if (destination is not null) await File.WriteAllBytesAsync(destination.Path, row.Attachment.Content);
    }

    private async void PreviewAttachment_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: AttachmentRow row }) return;
        try
        {
            PreviewPanel.Visibility = Visibility.Collapsed;
            PreviewScrollViewer.Content = null;
            PreviewTitle.Text = row.Attachment.FileName;
            PreviewStatus.Text = "正在加载预览…";
            PreviewPanel.Visibility = Visibility.Visible;
            if (!AttachmentPreviewService.IsPreviewable(row.Attachment.FileName))
            {
                PreviewStatus.Text = "此文件类型不能在密码库内直接查看，请使用导出。";
                return;
            }
            if (AttachmentPreviewService.IsTextPreview(row.Attachment.FileName))
            {
                var text = new TextBlock { Text = AttachmentPreviewService.DecodeText(row.Attachment.FileName, row.Attachment.Content), TextWrapping = TextWrapping.NoWrap, FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"), MinWidth = 650 };
                PreviewScrollViewer.Content = text;
                PreviewStatus.Text = "文本预览";
                return;
            }
            var image = new Image { Stretch = Microsoft.UI.Xaml.Media.Stretch.Uniform, MaxWidth = 760, MaxHeight = 560 };
            using var stream = new MemoryStream(row.Attachment.Content, writable: false);
            var bitmap = new BitmapImage { DecodePixelWidth = 2048, DecodePixelHeight = 2048 };
            await bitmap.SetSourceAsync(stream.AsRandomAccessStream());
            image.Source = bitmap;
            PreviewScrollViewer.Content = image;
            PreviewStatus.Text = "图片预览";
        }
        catch (Exception ex) when (ex is VaultException or IOException or InvalidOperationException or ArgumentException or OutOfMemoryException or COMException)
        {
            PreviewStatus.Text = $"无法查看：{ex.Message}";
        }
    }

    private void ClosePreview_Click(object sender, RoutedEventArgs e)
    {
        PreviewScrollViewer.Content = null;
        PreviewTitle.Text = string.Empty;
        PreviewStatus.Text = string.Empty;
        PreviewPanel.Visibility = Visibility.Collapsed;
    }

    private void ClearFields()
    {
        foreach (var row in _attachments) row.Attachment.ClearContent();
        _attachments.Clear();
        PasswordValueBox.Password = string.Empty;
        ContentBox.Text = string.Empty;
        UsernameBox.Text = string.Empty;
        PeopleBox.Text = string.Empty;
        NoteBox.Text = string.Empty;
    }
}

public sealed record AttachmentRow(VaultAttachment Attachment)
{
    public string DisplayText => $"{Attachment.FileName}  ({FormatSize(Attachment.Size)})";

    private static string FormatSize(long bytes) => bytes >= 1024 * 1024
        ? $"{bytes / 1024d / 1024d:F1} MiB"
        : $"{Math.Max(1, bytes / 1024d):F1} KiB";
}
