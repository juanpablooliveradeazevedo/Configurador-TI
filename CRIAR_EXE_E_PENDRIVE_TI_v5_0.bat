@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Configurador TI 2A - Build e distribuicao portatil
where py >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Python Launcher nao encontrado para compilar.
    echo O pacote ConfiguradorTI.exe pronto nao precisa de Python no destino.
    pause
    exit /b 1
)
for %%F in (main_gui.pyw main_gui.py core_logic.py app_paths.py app_status.py release_metadata.py build_config.py navigation_registry.py domain_hubs.py audit_timeline.py audit_timeline_gui.py change_intelligence.py change_intelligence_gui.py incident_replay.py monitoring_foundation.py monitoring_intelligence.py monitoring_gui.py endpoint_posture.py endpoint_posture_gui.py assist.py assist_gui.py baseline_defensivo.py baseline_defensivo_gui.py style.qss distribuicao\LEIA-ME.txt desenvolvimento\build_portatil.py desenvolvimento\build_release.py) do (
    if not exist "%%F" (
        echo [ERRO] Pacote incompleto: %%F
        pause
        exit /b 1
    )
)
echo [1/2] Preparando dependencias de build...
py -3 -m pip install --upgrade "cryptography>=46.0.0" PyQt6 "pyinstaller>=6.22.1"
if errorlevel 1 goto :falha
rem O perfil PORTABLE preserva --onefile e --noconsole; a chamada real e
rem estruturada em Python com shell=False. Saidas anteriores nao sao apagadas.
echo [2/2] Gerando e validando release PORTABLE...
py -3 "%~dp0desenvolvimento\build_release.py" ^
 --profile PORTABLE ^
 --output-root "%~dp0dist\releases"
if errorlevel 1 goto :falha
echo.
echo Entregue ao usuario o ZIP Configurador_TI_PORTATIL da release validada indicada acima.
echo Basta extrair e abrir ConfiguradorTI.exe. Nao e preciso instalar Python no destino.
pause
exit /b 0
:falha
echo [ERRO] Build ou montagem falhou. Consulte a mensagem acima.
echo Pacotes de uso anteriores foram preservados. Nao use uma saida parcial.
pause
exit /b 1
