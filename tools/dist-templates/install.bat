@echo off
setlocal
echo Installing Sentinel - a UAC prompt will appear.
"%~dp0tools\Sentinel.Setup.exe"
if errorlevel 1 (
  echo.
  echo Install FAILED. Run tools\Sentinel.Setup.exe manually to see the error.
  pause
) else (
  echo.
  echo Sentinel installed. Press any key to open the dashboard...
  pause >nul
  start "" "%~dp0gui\Sentinel.Gui.exe"
)
