@echo off
echo Checking prerequisites...
where cargo >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Cargo is not installed. Please install Rust from https://rustup.rs/
    pause
    exit /b 1
)

echo Building xikomap in release mode...
cargo build --release
if %ERRORLEVEL% neq 0 (
    echo Build failed.
    pause
    exit /b 1
)

echo Setting up installation directory...
set "INSTALL_DIR=%USERPROFILE%\.xikomap\bin"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo Copying files...
copy /Y "target\release\xikomap.exe" "%INSTALL_DIR%\xikomap.exe"

echo Updating user PATH...
for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "CURRENT_PATH=%%B"
echo %CURRENT_PATH% | findstr /I /C:"%INSTALL_DIR%" >nul
if %ERRORLEVEL% neq 0 (
    setx Path "%CURRENT_PATH%;%INSTALL_DIR%"
    echo PATH updated.
) else (
    echo PATH already contains the installation directory.
)

echo Installation complete. Restart your terminal and run 'xikomap'.
pause