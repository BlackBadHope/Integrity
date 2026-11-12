@echo off
chcp 65001 >nul
title [PANIC] Integrity Emergency LLM Killswitch
echo ================================================================
echo [EMERGENCY] Activating the Integrity master LLM killswitch...
echo ================================================================
python -m integrity_killswitch panic --sync --reason "Triggered by owner via PANIC_KILL_ALL_LLMS.cmd"
echo.
echo All LLMs are cut off from the infrastructure, the bus and the secrets.
echo Press any key to close...
pause >nul
