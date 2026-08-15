@echo off
echo Checking prerequisites...

:: Standard Rust installation path
set "CARGO_BIN=%USERPROFILE%\.cargo\bin"

:: If cargo is in the default directory, add it to current session PATH automatically
if exist "%CARGO_BIN%\cargo.exe" (
    set "PATH=%PATH%;%CARGO_BIN%"
)

:: Now check if cargo is available in the current session
cargo --version >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Cargo is not installed or not found in PATH.
    echo Please install Rust from https://rustup.rs/ and RESTART your terminal.
    pause
    exit /b 1
)

echo [+] Cargo found!

echo Building xikomap in release mode...
cargo build --release
if %ERRORLEVEL% neq 0 (
    echo [!] Build failed.
    pause
    exit /b 1
)

echo Setting up installation directory...
set "INSTALL_DIR=%USERPROFILE%\.xikomap\bin"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo Copying files...
copy /Y "target\release\xikomap.exe" "%INSTALL_DIR%\xikomap.exe"

echo Updating user PATH...
powershell -Command "$currentPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($currentPath -notlike '*%INSTALL_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $currentPath + ';%INSTALL_DIR%', 'User'); Write-Host 'PATH updated successfully.' } else { Write-Host 'PATH already contains the installation directory.' }"

echo [+] Installation complete. Restart your terminal and run 'xikomap'.
pause