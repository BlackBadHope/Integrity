@echo off
chcp 65001 >nul
title Integrity LLM Safe Switch Web Panel
echo ================================================================
echo Starting the Integrity LLM Safe Switch dashboard on 127.0.0.1:8890...
echo ================================================================
start http://127.0.0.1:8890
python -m integrity_killswitch serve --port 8890
