using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using Heco.Common.Enums;
using Heco.Common.Services.Profiles;
using Heco.Common.Services.Settings;

namespace Heco_Firewall.Windows;

public sealed partial class ProfileEditWindow : BaseWindow
{
    private readonly IProfileManager _profileManager;
    private readonly Profile _originalProfile;
    private readonly ObservableCollection<ProfileFingerprint> _fingerprints = new();

    public ProfileEditWindow(IProfileManager profileManager, Profile profile)
    {
        InitializeComponent();

        _profileManager = profileManager;
        _originalProfile = profile;

        TblTitle.Text = $"Edit Profile — {profile.Name}";
        TxtName.Text = profile.Name;

        // Clone fingerprints
        foreach (var fp in profile.Fingerprints)
        {
            _fingerprints.Add(new ProfileFingerprint
            {
                Type = fp.Type,
                Operator = fp.Operator,
                Value = fp.Value
            });
        }
        FingerprintsList.ItemsSource = _fingerprints;

        // Populate fingerprint type combo
        CboFingerprintType.ItemsSource = Enum.GetValues<FingerprintType>();
        CboFingerprintType.SelectedIndex = 0;

        // Action override
        if (profile.ActionOverride != null)
        {
            ChkInherit.IsChecked = false;
            ChkAllowOut.IsChecked = profile.ActionOverride.AllowOutbound == true;
            ChkAllowIn.IsChecked = profile.ActionOverride.AllowInbound == true;
            ChkBlockOut.IsChecked = profile.ActionOverride.BlockOutbound == true;
            ChkBlockIn.IsChecked = profile.ActionOverride.BlockInbound == true;
        }
        else
        {
            ChkInherit.IsChecked = true;
            SetActionCheckBoxesEnabled(false);
        }
    }

    private void SetActionCheckBoxesEnabled(bool enabled)
    {
        ChkAllowOut.IsEnabled = enabled;
        ChkAllowIn.IsEnabled = enabled;
        ChkBlockOut.IsEnabled = enabled;
        ChkBlockIn.IsEnabled = enabled;
    }

    private void Inherit_Checked(object sender, RoutedEventArgs e)
    {
        SetActionCheckBoxesEnabled(false);
        ChkAllowOut.IsChecked = false;
        ChkAllowIn.IsChecked = false;
        ChkBlockOut.IsChecked = false;
        ChkBlockIn.IsChecked = false;
    }

    private void Inherit_Unchecked(object sender, RoutedEventArgs e)
    {
        SetActionCheckBoxesEnabled(true);
    }

    private void AddFingerprint_Click(object sender, RoutedEventArgs e)
    {
        var value = TxtNewFingerprint.Text?.Trim();
        if (string.IsNullOrWhiteSpace(value))
            return;

        _fingerprints.Add(new ProfileFingerprint
        {
            Type = CboFingerprintType.SelectedItem is FingerprintType type ? type : FingerprintType.ProcessName,
            Operator = MatchOperator.Equals,
            Value = value
        });

        TxtNewFingerprint.Clear();
        TxtNewFingerprint.Focus();
    }

    private void RemoveFingerprint_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement element && element.DataContext is ProfileFingerprint fp)
            _fingerprints.Remove(fp);
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var name = TxtName.Text?.Trim();
        if (string.IsNullOrWhiteSpace(name))
        {
            DialogWindow.ShowWarning("Profile name cannot be empty.", "Validation");
            TxtName.Focus();
            return;
        }

        // Apply edits to original profile
        _originalProfile.Name = name;
        _originalProfile.Fingerprints = _fingerprints.ToList();

        if (ChkInherit.IsChecked == true)
        {
            _originalProfile.ActionOverride = null;
        }
        else
        {
            _originalProfile.ActionOverride ??= new NetworkActionSettings();
            _originalProfile.ActionOverride.AllowOutbound = ChkAllowOut.IsChecked == true ? true : null;
            _originalProfile.ActionOverride.AllowInbound = ChkAllowIn.IsChecked == true ? true : null;
            _originalProfile.ActionOverride.BlockOutbound = ChkBlockOut.IsChecked == true ? true : null;
            _originalProfile.ActionOverride.BlockInbound = ChkBlockIn.IsChecked == true ? true : null;
        }

        _profileManager.SaveProfile(_originalProfile);

        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
