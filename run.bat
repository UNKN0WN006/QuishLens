@echo off
setlocal
cd /d %~dp0
if not exist .venv\Scripts\python.exe (
  echo Creating virtual environment...
  python -m venv .venv || exit /b 1
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt || exit /b 1
if not exist data\demo\benign_qr.png python scripts\generate_demo_samples.py
if not exist app\models\url_classifier.joblib python scripts\bootstrap_demo_model.py
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
