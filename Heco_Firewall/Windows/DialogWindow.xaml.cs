using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Controls;

namespace Heco_Firewall.Windows;

public enum DialogIcon
{
    Info,
    Warning,
    Error,
    Question,
    None
}

public enum DialogButtons
{
    OK,
    OKCancel,
    YesNo,
    YesNoCancel
}

public enum DialogBoxResult
{
    None,
    OK,
    Cancel,
    Yes,
    No
}

public partial class DialogWindow : Window
{
    public DialogBoxResult Result { get; private set; } = DialogBoxResult.None;

    private DialogWindow(string title, string message, DialogIcon icon, DialogButtons buttons)
    {
        InitializeComponent();

        Title = title;
        TitleText.Text = title;
        MessageText.Text = message;

        SetIcon(icon);
        CreateButtons(buttons);
    }

    private void SetIcon(DialogIcon icon)
    {
        IconText.Text = icon switch
        {
            DialogIcon.Info => "i",
            DialogIcon.Warning => "!",
            DialogIcon.Error => "x",
            DialogIcon.Question => "?",
            _ => ""
        };

        var iconColor = icon switch
        {
            DialogIcon.Info => (System.Windows.Media.Brush)FindResource("BrushBlue"),
            DialogIcon.Warning => (System.Windows.Media.Brush)FindResource("BrushOrange"),
            DialogIcon.Error => (System.Windows.Media.Brush)FindResource("BrushRed"),
            DialogIcon.Question => (System.Windows.Media.Brush)FindResource("BrushAccent"),
            _ => (System.Windows.Media.Brush)FindResource("BrushTextSecondary")
        };

        IconBorder.Background = iconColor;
    }

    private void CreateButtons(DialogButtons buttons)
    {
        ButtonPanel.Children.Clear();

        switch (buttons)
        {
            case DialogButtons.OK:
                AddButton("OK", true, BtnPrimary, DialogBoxResult.OK);
                break;

            case DialogButtons.OKCancel:
                AddButton("Cancel", false, BtnSecondary, DialogBoxResult.Cancel);
                AddButton("OK", true, BtnPrimary, DialogBoxResult.OK);
                break;

            case DialogButtons.YesNo:
                AddButton("No", false, BtnSecondary, DialogBoxResult.No);
                AddButton("Yes", true, BtnPrimary, DialogBoxResult.Yes);
                break;

            case DialogButtons.YesNoCancel:
                AddButton("Cancel", false, BtnSecondary, DialogBoxResult.Cancel);
                AddButton("No", false, BtnSecondary, DialogBoxResult.No);
                AddButton("Yes", true, BtnPrimary, DialogBoxResult.Yes);
                break;
        }
    }

    private void AddButton(string text, bool isPrimary, Style style, DialogBoxResult result)
    {
        var btn = new Button
        {
            Content = text,
            Style = style,
            FontSize = 13,
            Height = 34,
            MinWidth = 88,
            Margin = new Thickness(8, 0, 0, 0),
            Tag = result
        };

        btn.Click += (s, e) =>
        {
            Result = result;
            DialogResult = true;
            Close();
        };

        ButtonPanel.Children.Add(btn);

        if (isPrimary)
            btn.Focus();
    }

    private Style BtnPrimary => (Style)FindResource("BtnPrimary");
    private Style BtnSecondary => (Style)FindResource("BtnSecondary");

    private void Window_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
            DragMove();
    }

    private void CloseBtn_Click(object sender, RoutedEventArgs e)
    {
        Result = DialogBoxResult.None;
        DialogResult = false;
        Close();
    }

    // ── Static helpers ──

    public static DialogBoxResult Show(string title, string message,
        DialogIcon icon = DialogIcon.None,
        DialogButtons buttons = DialogButtons.OK,
        Window? owner = null)
    {
        var effectiveOwner = owner ?? Application.Current.MainWindow;

        var dialog = new DialogWindow(title, message, icon, buttons);

        // Only set Owner if the owner window is loaded and visible;
        // otherwise fall back to CenterScreen so the dialog is always reachable.
        if (effectiveOwner != null && effectiveOwner.IsLoaded && effectiveOwner.IsVisible)
        {
            try
            {
                dialog.Owner = effectiveOwner;
                dialog.WindowStartupLocation = WindowStartupLocation.CenterOwner;
            }
            catch
            {
                dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            }
        }
        else
        {
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }

        dialog.ShowDialog();
        return dialog.Result;
    }

    public static DialogBoxResult ShowInfo(string message, string? title = null,
        DialogButtons buttons = DialogButtons.OK)
    {
        return Show(title ?? "Info", message, DialogIcon.Info, buttons);
    }

    public static DialogBoxResult ShowWarning(string message, string? title = null,
        DialogButtons buttons = DialogButtons.OK)
    {
        return Show(title ?? "Warning", message, DialogIcon.Warning, buttons);
    }

    public static DialogBoxResult ShowError(string message, string? title = null,
        DialogButtons buttons = DialogButtons.OK)
    {
        return Show(title ?? "Error", message, DialogIcon.Error, buttons);
    }

    public static DialogBoxResult ShowQuestion(string message, string? title = null,
        DialogButtons buttons = DialogButtons.YesNo)
    {
        return Show(title ?? "Confirm", message, DialogIcon.Question, buttons);
    }
}
