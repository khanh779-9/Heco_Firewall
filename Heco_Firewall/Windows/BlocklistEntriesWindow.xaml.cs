using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using Heco.Common.Services.Blocklists;

namespace Heco_Firewall.Windows;

public partial class BlocklistEntriesWindow : BaseWindow
{
    private readonly IBlocklistManager _manager;
    private readonly string _blocklistName;
    private readonly ObservableCollection<string> _entries = new();

    public BlocklistEntriesWindow(IBlocklistManager manager, string blocklistName, string title)
    {
        InitializeComponent();

        _manager = manager;
        _blocklistName = blocklistName;
        Title = title;

        var raw = _manager.GetEntries(blocklistName);
        foreach (var line in raw)
            _entries.Add(line);

        EntriesList.ItemsSource = _entries;
        UpdateCount();
    }

    private void UpdateCount()
    {
        var view = CollectionViewSource.GetDefaultView(EntriesList.ItemsSource);
        int visibleCount = 0;
        if (view != null)
        {
            foreach (var item in view)
            {
                visibleCount++;
            }
        }
        else
        {
            visibleCount = _entries.Count;
        }

        TblCount.Text = $"{visibleCount} entries" + (visibleCount != _entries.Count ? $" (filtered from {_entries.Count})" : "");

        TxtNoEntries.Visibility = visibleCount == 0 ? Visibility.Visible : Visibility.Collapsed;
        TxtNoEntries.Text = (visibleCount == 0 && _entries.Count > 0) ? "No matching entries" : "No entries";
    }

    private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        var filterText = TxtSearch.Text?.Trim();
        BtnClearSearch.Visibility = string.IsNullOrEmpty(filterText) ? Visibility.Collapsed : Visibility.Visible;

        var view = CollectionViewSource.GetDefaultView(EntriesList.ItemsSource);
        if (view != null)
        {
            if (string.IsNullOrWhiteSpace(filterText))
            {
                view.Filter = null;
            }
            else
            {
                view.Filter = obj =>
                {
                    if (obj is string entry)
                    {
                        return entry.Contains(filterText, StringComparison.OrdinalIgnoreCase);
                    }
                    return false;
                };
            }
            UpdateCount();
        }
    }

    private void ClearSearch_Click(object sender, RoutedEventArgs e)
    {
        TxtSearch.Clear();
    }

    private void AddEntry()
    {
        var text = TxtNewEntry.Text?.Trim();
        if (string.IsNullOrWhiteSpace(text)) return;
        _entries.Add(text);
        TxtNewEntry.Clear();
        UpdateCount();
    }

    private void TxtNewEntry_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            AddEntry();
            e.Handled = true;
        }
    }

    private void AddEntry_Click(object sender, RoutedEventArgs e)
    {
        AddEntry();
    }

    private void RemoveSelected_Click(object sender, RoutedEventArgs e)
    {
        var selected = EntriesList.SelectedItems.Cast<string>().ToList();
        foreach (var item in selected)
            _entries.Remove(item);
        UpdateCount();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        _manager.SetEntries(_blocklistName, _entries.ToArray());
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
