@echo off
setlocal

echo Checking prerequisites...
where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo Rust is not installed.
    pause
    exit /b 1
)

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Python is not installed.
    pause
    exit /b 1
)

echo Building xikomap in release mode...
cargo build --release
if %errorlevel% neq 0 (
    echo Build failed.
    pause
    exit /b 1
)

echo Setting up installation directory...
set "INSTALL_DIR=%USERPROFILE%\.xikomap"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%\py_detectors" mkdir "%INSTALL_DIR%\py_detectors"

echo Copying files...
copy /Y "target\release\xikomap.exe" "%INSTALL_DIR%\" >nul
xcopy /E /Y /I "py_detectors\*" "%INSTALL_DIR%\py_detectors" >nul

echo Updating user PATH...
powershell -Command "$path = [Environment]::GetEnvironmentVariable('PATH', 'User'); if ($path -notlike '*%INSTALL_DIR%\*') { [Environment]::SetEnvironmentVariable('PATH', $path + ';%INSTALL_DIR%', 'User') }"

echo Installation complete. Restart your terminal and run 'xikomap'.
pause
endlocal