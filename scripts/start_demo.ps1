Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "detector.live|streamlit" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
.\scripts\reset_lab.ps1
python scripts\export_ownership.py datasets\demo\ownership.json
Start-Process powershell -WorkingDirectory $PWD -ArgumentList "-NoExit", "-Command", ".venv\Scripts\Activate.ps1; python -m detector.live --ownership datasets\demo\ownership.json --reset"
Start-Process powershell -WorkingDirectory $PWD -ArgumentList "-NoExit", "-Command", ".venv\Scripts\Activate.ps1; streamlit run dashboard\app.py"