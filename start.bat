@echo off
title DEFA 2.0 — Digital Evidence File Analyzer
color 0B
echo ========================================================
echo        DEFA 2.0 — DIGITAL EVIDENCE FILE ANALYZER
echo ========================================================
echo.
echo  Starting DEFA 2.0 Interactive Forensics Dashboard...
echo.
echo  Local Dashboard : http://127.0.0.1:8000
echo  Interactive API : http://127.0.0.1:8000/docs
echo.
echo  AI Assistant (Optional Free Local AI):
echo    1. Download Ollama from https://ollama.com
echo    2. Run: ollama run llama3.2
echo    (DEFA works 100%% offline even without Ollama)
echo.
echo  Opening browser at http://127.0.0.1:8000 ...
start http://127.0.0.1:8000
echo.
python main.py serve --host 127.0.0.1 --port 8000
pause

