namespace Sentinel.Gui.Views;

/// <summary>Implemented by views that can reload their data from the service.</summary>
public interface IRefreshable
{
    Task RefreshAsync();
}