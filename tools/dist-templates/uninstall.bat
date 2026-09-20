@echo off
setlocal
echo Uninstalling Sentinel - a UAC prompt will appear.
"%~dp0tools\Sentinel.Setup.exe" --uninstall
pause
