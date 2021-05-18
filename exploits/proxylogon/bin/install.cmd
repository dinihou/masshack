py -m pip install virtualenv
py -m virtualenv venv
call %cd%\venv\Scripts\activate.bat
pip install -r requirements.txt
pause
