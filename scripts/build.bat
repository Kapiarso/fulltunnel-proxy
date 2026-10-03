@echo off
:: ============================================================================
:: FullTunnel Enterprise Build Script
:: Compiles GUI/Dashboard and CLI binaries for Windows
:: ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo   Building FullTunnel Enterprise (Windows x64 / x86)
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
echo [2/3] Compiling FullTunnel GUI / Web Dashboard (fulltunnel.exe)...
go build -ldflags "-s -w" -o fulltunnel.exe main.go
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to compile fulltunnel.exe
    pause
    exit /b 1
)
echo [OK] Compiled fulltunnel.exe successfully.

echo.
echo [3/3] Compiling FullTunnel Headless CLI (fulltunnel-cli.exe)...
go build -ldflags "-s -w" -o fulltunnel-cli.exe ./cmd/cli/main.go
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to compile fulltunnel-cli.exe
    pause
    exit /b 1
)
echo [OK] Compiled fulltunnel-cli.exe successfully.

echo.
echo ============================================================================
echo [BUILD COMPLETE] Both binaries built successfully!
echo   - fulltunnel.exe (GUI / Web Dashboard on http://127.0.0.1:28888)
echo   - fulltunnel-cli.exe (Headless CLI)
echo ============================================================================
pause
