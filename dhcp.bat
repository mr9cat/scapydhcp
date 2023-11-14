@echo off

@REM %1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
@REM cd /d "%~dp0"

chcp 65001

.\venv\Scripts\python.exe -u .\server.py windows
