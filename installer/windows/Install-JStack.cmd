@echo off
rem Jstack OS for Windows: double-click to install next to Windows.
rem Downloads the latest installer script and runs it as administrator.
rem If Install-JStack.ps1 is next to this file, that copy is used instead.
setlocal
set "HERE=%~dp0"
if exist "%HERE%Install-JStack.ps1" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%Install-JStack.ps1" %*
  goto :end
)
set "PS1=%TEMP%\Install-JStack.ps1"
powershell.exe -NoProfile -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/1jehuang/jstack-os/releases/latest/download/Install-JStack.ps1' -OutFile $env:TEMP\Install-JStack.ps1"
if errorlevel 1 (
  echo Could not download the installer. Check the internet connection.
  goto :end
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
:end
pause
