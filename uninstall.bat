@echo off
setlocal

set "INSTALL_DIR=%USERPROFILE%\.xikomap"

echo Removing from user PATH...
powershell -Command "$path = [Environment]::GetEnvironmentVariable('PATH', 'User'); $newPath = ($path -split ';' | Where-Object { $_ -ne '%INSTALL_DIR%' }) -join ';'; [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')"

echo Deleting installation directory...
if exist "%INSTALL_DIR%" (
    rmdir /s /q "%INSTALL_DIR%"
)

echo Uninstallation complete.
pause
endlocal