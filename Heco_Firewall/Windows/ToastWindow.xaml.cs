using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace Heco_Firewall.Windows;

public enum ToastType
{
    Success,
    Info,
    Warning,
    Error,
    Blocked
}

public partial class ToastWindow : Window
{
    private DispatcherTimer? _autoCloseTimer;
    private readonly ToastType _type;

    private static readonly Geometry SuccessIconGeometry = Geometry.Parse("M9,16.17L4.83,12l-1.42,1.41L9,19 21,7l-1.41-1.41z");
    private static readonly Geometry InfoIconGeometry = Geometry.Parse("M11,7h2v2h-2zm0,4h2v6h-2z");
    private static readonly Geometry WarningIconGeometry = Geometry.Parse("M11,7h2v6h-2zm0,8h2v2h-2z");
    private static readonly Geometry ErrorIconGeometry = Geometry.Parse("M19,6.41L17.59,5 12,10.59 6.41,5 5,6.41 10.59,12 5,17.59 6.41,19 12,13.41 17.59,19 19,17.59 13.41,12z");
    private static readonly Geometry BlockedIconGeometry = Geometry.Parse("M12,2L4,6v6c0,5.55,3.84,10.74,8,12c4.16-1.26,8-6.45,8-12V6L12,2z");

    public ToastWindow(string title, string message, ToastType type, double screenX, double screenY, int durationMs = 5000)
    {
        InitializeComponent();

        _type = type;
        TitleText.Text = title;
        MessageText.Text = message;

        Left = screenX;
        Top = screenY;

        ApplyStyle(type);
        StartAutoClose(durationMs);
    }

    private void ApplyStyle(ToastType type)
    {
        var accent = type switch
        {
            ToastType.Success => (Color)FindResource("Green"),
            ToastType.Info => (Color)FindResource("Blue"),
            ToastType.Warning => (Color)FindResource("Orange"),
            ToastType.Error => (Color)FindResource("Red"),
            ToastType.Blocked => (Color)FindResource("Red"),
            _ => (Color)FindResource("Accent")
        };

        var brush = new SolidColorBrush(accent);

        ToastBorder.BorderBrush = brush;
        ToastBorder.Background = new SolidColorBrush(Color.FromArgb(0xFA, 255, 255, 255));

        IconBorder.Background = brush;
        IconPath.Data = type switch
        {
            ToastType.Success => SuccessIconGeometry,
            ToastType.Info => InfoIconGeometry,
            ToastType.Warning => WarningIconGeometry,
            ToastType.Error => ErrorIconGeometry,
            ToastType.Blocked => BlockedIconGeometry,
            _ => InfoIconGeometry
        };
    }

    private void StartAutoClose(int durationMs)
    {
        _autoCloseTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(durationMs) };
        _autoCloseTimer.Tick += (_, _) =>
        {
            _autoCloseTimer.Stop();
            AnimateExit();
        };
        _autoCloseTimer.Start();
    }

    private async void AnimateExit()
    {
        var sb = new Storyboard();
        var fade = new DoubleAnimation(1.0, 0.0, TimeSpan.FromMilliseconds(300))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn }
        };
        var slide = new DoubleAnimation(0, 60, TimeSpan.FromMilliseconds(300))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn }
        };

        // Animate ToastBorder (not Window), since RenderTransform lives there
        Storyboard.SetTarget(fade, ToastBorder);
        Storyboard.SetTargetProperty(fade, new PropertyPath(UIElement.OpacityProperty));
        Storyboard.SetTarget(slide, ToastBorder);
        Storyboard.SetTargetProperty(slide, new PropertyPath("(UIElement.RenderTransform).(TranslateTransform.X)"));

        sb.Children.Add(fade);
        sb.Children.Add(slide);
        sb.Completed += (_, _) => Close();
        sb.Begin();

        await Task.Delay(350);
    }

    private void CloseBtn_Click(object sender, RoutedEventArgs e)
    {
        _autoCloseTimer?.Stop();
        AnimateExit();
    }

    /// <summary>Show toast at bottom-right of screen. Owner is optional.</summary>
    public static void Show(Window? owner, string title, string message, ToastType type, int durationMs = 5000)
    {
        var dispatcher = owner?.Dispatcher ?? Application.Current.Dispatcher;
        dispatcher.BeginInvoke(new Action(() =>
        {
            var workArea = SystemParameters.WorkArea;
            double x = workArea.Right - 400;
            double y = workArea.Bottom - 100;

            // Stack below existing toasts
            foreach (Window w in Application.Current.Windows)
            {
                if (w is ToastWindow tw)
                {
                    y = Math.Min(y, tw.Top - tw.ActualHeight - 8);
                }
            }

            var toast = new ToastWindow(title, message, type, x, y, durationMs);

            // Only set Owner if the owner window is loaded and visible
            if (owner != null && owner.IsLoaded)
            {
                try { toast.Owner = owner; }
                catch { /* ignore — toast is topmost anyway */ }
            }

            toast.Show();
        }));
    }
}
