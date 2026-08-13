@echo off
echo Uninstalling xikomap...
set "INSTALL_DIR=%USERPROFILE%\.xikomap\bin"
if exist "%INSTALL_DIR%\xikomap.exe" (
    del /F /Q "%INSTALL_DIR%\xikomap.exe"
    echo Executable removed.
)

echo Updating user PATH...
powershell -Command "$currentPath = [Environment]::GetEnvironmentVariable('Path', 'User'); $newPath = ($currentPath -split ';' | Where-Object { $_ -ne '%INSTALL_DIR%' }) -join ';'; [Environment]::SetEnvironmentVariable('Path', $newPath, 'User'); Write-Host 'PATH updated.'"

echo Uninstallation complete. Restart your terminal.
pause