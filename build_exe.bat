@echo off
echo Installing dependencies...
pip install pyinstaller reportlab

echo Building EXE...
python -m PyInstaller --onefile --windowed --name SmartNetworkScanner main.py

echo.
echo Done! Find your EXE in the "dist" folder.
pause
