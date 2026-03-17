@echo off

:: ----------------------------------------------------------------
:: Self-elevation script to request Administrator privileges
:: Adapted to launch main_analysis_ml.py (ML-enabled) from USB toolkit
:: ----------------------------------------------------------------
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:: ----------------------------------------------------------------

ECHO =======================================
ECHO       LIVE FORENSIC TRIAGE TOOL (ML)
ECHO =======================================
ECHO.
ECHO Starting analysis. This may take a moment...
ECHO Please keep this window open.
ECHO.

:: Optional: load environment variables from toolkit\env.bat if present (for SMTP creds)
if exist "%~dp0toolkit\env.bat" (
    echo Loading toolkit environment variables...
    call "%~dp0toolkit\env.bat"
)

:: Find portable Python if bundled under Tools\Python\python.exe, otherwise fall back to system python
set "PYTHON="
if exist "%~dp0Tools\Python\python.exe" (
    set "PYTHON=%~dp0Tools\Python\python.exe"
) else (
    for %%P in (python.exe python3.exe) do (
        where %%P >nul 2>&1 && set "PYTHON=%%P" && goto :foundPython
    )
)
:foundPython
if "%PYTHON%"=="" (
    echo No Python interpreter found. Please ensure Tools\Python\python.exe exists on the USB or python is on PATH.
    pause
    goto :eof
)

:: Run the new ML-enabled script (default ML mode ON). You can pass --ml-mode off if needed.
"%PYTHON%" "%~dp0Scripts\main_analysis.py" --ml-mode on

ECHO.
ECHO =======================================
ECHO Analysis Complete!
ECHO A report has been saved to the Reports folder.
ECHO =======================================
ECHO.
pause

:: restore original dir
popd
exit /B 0
