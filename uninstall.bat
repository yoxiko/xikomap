@echo off
echo Uninstalling xikomap...
set "INSTALL_DIR=%USERPROFILE%\.xikomap\bin"
if exist "%INSTALL_DIR%\xikomap.exe" (
    del /F /Q "%INSTALL_DIR%\xikomap.exe"
    echo Executable removed.
)

for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "CURRENT_PATH=%%B"
set "NEW_PATH=%CURRENT_PATH:;%INSTALL_DIR%=%"
set "NEW_PATH=%NEW_PATH:%INSTALL_DIR%;=%"
if not "%CURRENT_PATH%"=="%NEW_PATH%" (
    setx Path "%NEW_PATH%"
    echo PATH updated.
)

echo Uninstallation complete. Restart your terminal.
pause