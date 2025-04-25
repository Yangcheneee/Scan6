@echo off
set PYTHON_SCRIPT=arc/main.py
set PYTHON_EXE=python
set INTERVAL_SECONDS=10*60  :: 间隔时间（秒）

:loop
echo 正在运行 Python 脚本: %PYTHON_SCRIPT%
%PYTHON_EXE% %PYTHON_SCRIPT%

echo 等待 %INTERVAL_SECONDS% 秒后再次运行...
timeout /t %INTERVAL_SECONDS% /nobreak >nul

goto loop