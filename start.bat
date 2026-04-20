@echo off
setlocal

echo Building Pingtym...
if not exist bin mkdir bin

go build -o bin\server.exe cmd\server\main.go
if %errorlevel% neq 0 ( echo Build failed: server & exit /b 1 )

go build -o bin\cron.exe cmd\cron\main.go
if %errorlevel% neq 0 ( echo Build failed: cron & exit /b 1 )

echo Starting web server at http://localhost:8080 ...
start "Pingtym Server" cmd /k "bin\server.exe"

:: Give the server a moment to initialize the database
timeout /t 3 /nobreak > nul

echo Running health check worker every 60 seconds. Press Ctrl+C to stop.
:loop
bin\cron.exe
timeout /t 60 /nobreak > nul
goto loop
