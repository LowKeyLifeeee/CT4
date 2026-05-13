@echo off
REM ─────────────────────────────────────────────────────────────
REM  install_lab.bat — Cài đặt dependencies cho PCAP Analyzer
REM  Bài lab An toàn mạng — VMware (Kali Linux + Windows)
REM ─────────────────────────────────────────────────────────────
echo.
echo [*] Cai dat dependencies cho Lab ICMP Flood Analyzer...
echo.

python -m pip install --upgrade pip
python -m pip install -r "%~dp0requirements_lab.txt"

echo.
echo [OK] Cai dat hoan tat!
echo.
echo Cach su dung:
echo   python pcap_analyzer.py capture.pcap --all
echo   python pcap_analyzer.py capture.pcap -t 50 -w 2 --chart
echo.
pause
