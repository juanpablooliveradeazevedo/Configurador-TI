@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist "%~dp0main_gui.pyw" goto :incompleto
where pyw >nul 2>&1
if not errorlevel 1 (
    start "" pyw -3 "%~dp0main_gui.pyw" %*
    exit /b 0
)
where pythonw >nul 2>&1
if not errorlevel 1 (
    start "" pythonw "%~dp0main_gui.pyw" %*
    exit /b 0
)
where py >nul 2>&1
if not errorlevel 1 (
    start "" py -3 "%~dp0main_gui.pyw" %*
    exit /b 0
)
where python >nul 2>&1
if not errorlevel 1 (
    start "" python "%~dp0main_gui.pyw" %*
    exit /b 0
)
echo Python nao encontrado. Para uso sem Python, utilize o pacote com ConfiguradorTI.exe.
echo Consulte LEIA-ME.txt. Nenhuma permissao de administrador foi solicitada.
pause
exit /b 1
:incompleto
echo Pacote incompleto: main_gui.pyw nao foi encontrado ao lado deste iniciador.
echo Extraia o ZIP inteiro antes de iniciar.
pause
exit /b 1
