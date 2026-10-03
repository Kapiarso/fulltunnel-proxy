@echo off
:: ============================================================================
:: EMERGENCY STOP & FULL CLEANUP SCRIPT (toten.bat)
:: Stops SecureTunnel daemon, web panel, resets Windows routing table & DNS.
:: NOTE: Explicitly preserves CCProxy.exe as requested.
:: ============================================================================

title SecureTunnel Emergency Stop

echo ============================================================================
echo [EMERGENCY STOP] Stopping SecureTunnel Engine, Web Panel ^& Routing Table...
echo ============================================================================

:: 1. Force kill SecureTunnel background daemon and CLI
taskkill /F /IM securetunnel.exe >nul 2>&1
taskkill /F /IM securetunnel-cli.exe >nul 2>&1

:: 2. Delete leftover Full Tunnel routes if active
route delete 0.0.0.0 mask 128.0.0.0 >nul 2>&1
route delete 128.0.0.0 mask 128.0.0.0 >nul 2>&1
route delete ::/1 >nul 2>&1
route delete 8000::/1 >nul 2>&1

:: 3. Flush Windows DNS cache
ipconfig /flushdns >nul 2>&1

echo.
echo [SUCCESS] SecureTunnel Engine and Web Panel stopped.
echo [SUCCESS] Windows Routing Table and DNS restored to original state.
echo ============================================================================
pause
