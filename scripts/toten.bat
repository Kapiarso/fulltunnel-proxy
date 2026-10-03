@echo off
:: ============================================================================
:: EMERGENCY STOP & FULL CLEANUP SCRIPT (toten.bat)
:: Stops FullTunnel daemon, web panel, resets Windows routing table & DNS.
:: ============================================================================

title FullTunnel Emergency Stop

echo ============================================================================
echo [EMERGENCY STOP] Stopping FullTunnel Engine, Web Panel ^& Routing Table...
echo ============================================================================

:: 1. Force kill FullTunnel background daemon and CLI
taskkill /F /IM fulltunnel.exe >nul 2>&1
taskkill /F /IM fulltunnel-cli.exe >nul 2>&1
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
echo [SUCCESS] FullTunnel Engine and Web Panel stopped.
echo [SUCCESS] Windows Routing Table and DNS restored to original state.
echo ============================================================================
pause
