@echo off
py -m pip install --upgrade pywin32
pip install -r requirements.txt
cls
py main.py
pause