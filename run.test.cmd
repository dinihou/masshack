set "PYTHONIOENCODING=UTF-8"
chcp 65001
cls
call %cd%\venv\Scripts\activate.bat
py .\masshack.py -ipaddr "127.0.0.1" --scanner "apache" --exploit "test"
pause