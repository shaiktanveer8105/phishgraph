@echo off
REM Requires JDK 17+ on PATH
if not exist out mkdir out
javac -d out src\phishgraph\*.java
if errorlevel 1 exit /b 1
echo Build OK. Run with run.bat
