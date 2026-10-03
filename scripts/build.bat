@echo off
:: ============================================================================
:: SecureTunnel Enterprise Build Script
:: Compiles GUI/Dashboard and CLI binaries for Windows
:: ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo   Building SecureTunnel Enterprise (Windows x64 / x86)
echo ============================================================================

:: Check Go compiler
where go >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go compiler not found in PATH. Please install Go 1.22+
    pause
    exit /b 1
)

echo [1/3] Downloading / Verifying Go module dependencies...
go mod tidy
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to run 'go mod tidy'
    pause
    exit /b 1
)

echo.
echo [2/3] Compiling SecureTunnel GUI / Web Dashboard (securetunnel.exe)...
go build -ldflags "-s -w" -o securetunnel.exe main.go
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to compile securetunnel.exe
    pause
    exit /b 1
)
echo [OK] Compiled securetunnel.exe successfully.

echo.
echo [3/3] Compiling SecureTunnel Headless CLI (securetunnel-cli.exe)...
go build -ldflags "-s -w" -o securetunnel-cli.exe ./cmd/cli/main.go
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to compile securetunnel-cli.exe
    pause
    exit /b 1
)
echo [OK] Compiled securetunnel-cli.exe successfully.

echo.
echo ============================================================================
echo [BUILD COMPLETE] Both binaries built successfully!
echo   - securetunnel.exe (GUI / Web Dashboard on http://127.0.0.1:28888)
echo   - securetunnel-cli.exe (Headless CLI)
echo ============================================================================
pause
