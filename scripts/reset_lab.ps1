docker compose down -v
if (Test-Path logs\app.jsonl) { Remove-Item logs\app.jsonl }
docker compose up -d
Write-Host "Waiting for the app..."
for ($i = 0; $i -lt 30; $i++) {
    try { Invoke-RestMethod http://127.0.0.1:8000/health | Out-Null; Write-Host "App is up"; break }
    catch { Start-Sleep -Seconds 2 }
}
if (Test-Path logs\app.jsonl) { Remove-Item logs\app.jsonl }