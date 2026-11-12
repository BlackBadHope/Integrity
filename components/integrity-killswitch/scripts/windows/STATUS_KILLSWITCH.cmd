@echo off
chcp 65001 >nul
title Integrity LLM Safe Switch Status
python -m integrity_killswitch status
echo.
pause
