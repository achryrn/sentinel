using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using Sentinel.Core.Models;

namespace Sentinel.Gui;

/// <summary>Maps a Severity to a brush (Critical → red, High → orange, etc.).</summary>
public sealed class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var severity = value is Severity s ? s : Severity.Info;
        return severity switch
        {
            Severity.Critical => new SolidColorBrush(Color.FromRgb(0xDA, 0x36, 0x33)),
            Severity.High => new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x49)),
            Severity.Medium => new SolidColorBrush(Color.FromRgb(0xD2, 0x99, 0x22)),
            Severity.Low => new SolidColorBrush(Color.FromRgb(0x58, 0xA6, 0xFF)),
            _ => new SolidColorBrush(Color.FromRgb(0x8B, 0x94, 0x9E)),
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Maps a bool to a brush (true → green, false → red).</summary>
public sealed class BoolToBrushConverter : IValueConverter
{
    public Brush TrueBrush { get; set; } = Brushes.Green;
    public Brush FalseBrush { get; set; } = Brushes.Red;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? TrueBrush : FalseBrush;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Formats a nullable double as a percentage or "—".</summary>
public sealed class PercentConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is double d ? $"{d:0.0}%" : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Formats a nullable long as bytes (KB/MB/GB) or "—".</summary>
public sealed class BytesConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not long b)
        {
            return "—";
        }
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = b;
        int i = 0;
        while (v >= 1024 && i < units.Length - 1)
        {
            v /= 1024;
            i++;
        }
        return $"{v:0.##} {units[i]}";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Formats a UTC DateTime as local time or "—".</summary>
public sealed class UtcTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is DateTime dt ? dt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "—";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Truncates a long string to a max length with ellipsis.</summary>
public sealed class TruncateConverter : IValueConverter
{
    public int MaxLength { get; set; } = 60;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var s = value as string;
        if (string.IsNullOrEmpty(s))
        {
            return "";
        }
        return s.Length <= MaxLength ? s : s[..MaxLength] + "…";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}