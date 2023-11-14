@echo off

@REM %1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
@REM cd /d "%~dp0"

chcp 65001

python --version| findstr "3.10." >nul && (
    echo python version is 3.10
) || (
    echo python version is not 3.10
    echo.
    echo --- python版本不是3.10 即将退出安装
    timeout 5
	exit
)
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r require.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
