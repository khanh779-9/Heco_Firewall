using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Heco.Common.Services.Blocklists;
using Heco_Firewall.Helpers;
using Heco_Firewall.Windows;

namespace Heco_Firewall.ViewModels;

internal sealed class BlocklistsViewModel : ObservableObject
{
    private readonly IBlocklistManager _blocklistManager;
    private Blocklist? _selectedBlocklist;
    private bool _isUpdating;
    private string _statusText = string.Empty;

    // Add-editor fields
    private bool _isAdding;
    private string _newName = string.Empty;
    private string _newUrl = string.Empty;
    private BlocklistContentType _selectedContentType = BlocklistContentType.Domain;

    // Edit-editor fields
    private bool _isEditing;
    private string _editName = string.Empty;
    private string _editUrl = string.Empty;
    private BlocklistContentType _editContentType = BlocklistContentType.Domain;
    private bool _editIsEnabled = true;
    private string? _editOriginalName;

    public BlocklistsViewModel(IBlocklistManager blocklistManager)
    {
        _blocklistManager = blocklistManager;

        UpdateAllCommand = new RelayCommand(async _ => await UpdateAllAsync(), _ => !IsUpdating);
        UpdateSelectedCommand = new RelayCommand(async _ => await UpdateSelectedAsync(), _ => SelectedBlocklist?.Source == BlocklistSource.OnlineUrl && !IsUpdating);
        RemoveCommand = new RelayCommand(_ => Remove(), _ => SelectedBlocklist != null);
        ViewEntriesCommand = new RelayCommand(_ => ViewEntries(), _ => SelectedBlocklist != null);
        RefreshCommand = new RelayCommand(_ => Refresh());
        AddOnlineCommand = new RelayCommand(async _ => await AddOnlineAsync(), _ => !string.IsNullOrWhiteSpace(NewName) && !string.IsNullOrWhiteSpace(NewUrl));
        AddOfflineCommand = new RelayCommand(_ => AddOffline(), _ => !string.IsNullOrWhiteSpace(NewName));
        BeginAddCommand = new RelayCommand(_ => BeginAdd());
        CancelAddCommand = new RelayCommand(_ => CancelAdd());
        BeginEditCommand = new RelayCommand(_ => BeginEdit(), _ => SelectedBlocklist != null && !IsAdding);
        SaveEditCommand = new RelayCommand(_ => SaveEdit(), _ => !string.IsNullOrWhiteSpace(EditName));
        CancelEditCommand = new RelayCommand(_ => CancelEdit());

        _blocklistManager.BlocklistUpdated += OnBlocklistUpdated;
        Refresh();
    }

    //  Properties 

    public IReadOnlyList<Blocklist> Blocklists => _blocklistManager.Blocklists;

    public Blocklist? SelectedBlocklist
    {
        get => _selectedBlocklist;
        set
        {
            if (SetProperty(ref _selectedBlocklist, value))
                CommandManager.InvalidateRequerySuggested();
        }
    }

    public bool IsUpdating
    {
        get => _isUpdating;
        set
        {
            if (SetProperty(ref _isUpdating, value))
                CommandManager.InvalidateRequerySuggested();
        }
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public long TotalEntries => _blocklistManager.TotalEntries;
    public int OnlineCount => Blocklists.Count(b => b.Source == BlocklistSource.OnlineUrl);
    public int OfflineCount => Blocklists.Count(b => b.Source == BlocklistSource.OfflineFile);

    //  Add-editor Properties 

    public bool IsAdding
    {
        get => _isAdding;
        set => SetProperty(ref _isAdding, value);
    }

    public string NewName
    {
        get => _newName;
        set
        {
            if (SetProperty(ref _newName, value))
                CommandManager.InvalidateRequerySuggested();
        }
    }

    public string NewUrl
    {
        get => _newUrl;
        set
        {
            if (SetProperty(ref _newUrl, value))
                CommandManager.InvalidateRequerySuggested();
        }
    }

    public BlocklistContentType SelectedContentType
    {
        get => _selectedContentType;
        set => SetProperty(ref _selectedContentType, value);
    }

    public ObservableCollection<BlocklistContentType> AvailableContentTypes { get; } = new(
        [BlocklistContentType.Domain, BlocklistContentType.IP, BlocklistContentType.Wildcard, BlocklistContentType.Hosts]);

    //  Edit-editor Properties 

    public bool IsEditing
    {
        get => _isEditing;
        set => SetProperty(ref _isEditing, value);
    }

    public string EditName
    {
        get => _editName;
        set
        {
            if (SetProperty(ref _editName, value))
                CommandManager.InvalidateRequerySuggested();
        }
    }

    public string EditUrl
    {
        get => _editUrl;
        set => SetProperty(ref _editUrl, value);
    }

    public BlocklistContentType EditContentType
    {
        get => _editContentType;
        set => SetProperty(ref _editContentType, value);
    }

    public bool EditIsEnabled
    {
        get => _editIsEnabled;
        set => SetProperty(ref _editIsEnabled, value);
    }

    //  Commands 

    public ICommand UpdateAllCommand { get; }
    public ICommand UpdateSelectedCommand { get; }
    public ICommand RemoveCommand { get; }
    public ICommand ViewEntriesCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand AddOnlineCommand { get; }
    public ICommand AddOfflineCommand { get; }
    public ICommand BeginAddCommand { get; }
    public ICommand CancelAddCommand { get; }
    public ICommand BeginEditCommand { get; }
    public ICommand SaveEditCommand { get; }
    public ICommand CancelEditCommand { get; }

    //  Methods ─

    public void Refresh()
    {
        _blocklistManager.LoadAll();
        UpdateStatus();
    }

    private void BeginAdd()
    {
        NewName = string.Empty;
        NewUrl = string.Empty;
        SelectedContentType = BlocklistContentType.Domain;
        IsAdding = true;
    }

    private void CancelAdd()
    {
        IsAdding = false;
    }

    private async Task UpdateAllAsync()
    {
        IsUpdating = true;
        try
        {
            await _blocklistManager.UpdateAllOnlineBlocklists();
            Refresh();
        }
        finally
        {
            IsUpdating = false;
        }
    }

    private async Task UpdateSelectedAsync()
    {
        if (SelectedBlocklist?.Source != BlocklistSource.OnlineUrl)
            return;

        IsUpdating = true;
        try
        {
            await _blocklistManager.UpdateOnlineBlocklist(SelectedBlocklist.Name);
            Refresh();
        }
        finally
        {
            IsUpdating = false;
        }
    }

    private async Task AddOnlineAsync()
    {
        try
        {
            _blocklistManager.AddOnlineBlocklist(NewName.Trim(), NewUrl.Trim(), SelectedContentType);
            await _blocklistManager.UpdateOnlineBlocklist(NewName.Trim());
            IsAdding = false;
            Refresh();
        }
        catch (Exception ex)
        {
            DialogWindow.ShowError($"Failed to add online blocklist: {ex.Message}", "Error");
        }
    }

    private void AddOffline()
    {
        try
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Select Blocklist File",
                Filter = "Text files (*.txt)|*.txt|Hosts files (*.hosts)|*.hosts|All files (*.*)|*.*"
            };

            if (dialog.ShowDialog() != true)
                return;

            var path = dialog.FileName;
            var name = string.IsNullOrWhiteSpace(NewName) ? System.IO.Path.GetFileNameWithoutExtension(path) : NewName.Trim();

            // Try to detect content type from file name
            var ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
            var ct = ext switch
            {
                ".hosts" => BlocklistContentType.Hosts,
                _ => SelectedContentType
            };

            _blocklistManager.AddOfflineBlocklist(path, ct);
            IsAdding = false;
            Refresh();
        }
        catch (Exception ex)
        {
            DialogWindow.ShowError($"Failed to add offline blocklist: {ex.Message}", "Error");
        }
    }

    private void ViewEntries()
    {
        if (SelectedBlocklist == null) return;

        var win = new Windows.BlocklistEntriesWindow(
            _blocklistManager,
            SelectedBlocklist.Name,
            $"Entries: {SelectedBlocklist.Name}");
        win.Owner = Application.Current.MainWindow;
        win.ShowDialog();
    }

    private void Remove()
    {
        if (SelectedBlocklist == null)
            return;

        var result = DialogWindow.ShowQuestion(
            $"Remove blocklist '{SelectedBlocklist.Name}'?\n\nThis will delete all cached entries.",
            "Confirm Remove");
        if (result != DialogBoxResult.Yes) return;

        var name = SelectedBlocklist.Name;
        _blocklistManager.RemoveBlocklist(name);
        SelectedBlocklist = null;
        Refresh();
    }

    private void BeginEdit()
    {
        if (SelectedBlocklist == null) return;

        _editOriginalName = SelectedBlocklist.Name;
        EditName = SelectedBlocklist.Name;
        EditUrl = SelectedBlocklist.Url ?? string.Empty;
        EditContentType = SelectedBlocklist.ContentType;
        EditIsEnabled = SelectedBlocklist.IsEnabled;
        IsEditing = true;
    }

    private void SaveEdit()
    {
        if (_editOriginalName == null) return;

        _blocklistManager.UpdateBlocklistConfig(
            _editOriginalName,
            EditName.Trim(),
            EditContentType,
            string.IsNullOrWhiteSpace(EditUrl) ? null : EditUrl.Trim(),
            EditIsEnabled);

        IsEditing = false;
        _editOriginalName = null;
        SelectedBlocklist = null;
        Refresh();
    }

    private void CancelEdit()
    {
        IsEditing = false;
        _editOriginalName = null;
    }

    private void OnBlocklistUpdated(object? sender, BlocklistEventArgs e)
    {
        Refresh();
    }

    private void UpdateStatus()
    {
        OnPropertyChanged(nameof(Blocklists));
        StatusText = $"{Blocklists.Count} lists · {TotalEntries:N0} entries · {OnlineCount} online · {OfflineCount} offline";
        OnPropertyChanged(nameof(TotalEntries));
        OnPropertyChanged(nameof(OnlineCount));
        OnPropertyChanged(nameof(OfflineCount));
    }
}
