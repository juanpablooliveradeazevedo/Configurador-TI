#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configurador de TI - Versão Aprimorada
Autor: Assistente Venice
Versão: 4.5 (Seguro + Interface colorida + correções visuais/Windows Update)
Descrição: Ferramenta completa para configuração de rede, DNS e manutenção de sistemas Windows

Mudanças desta versão (v4.5):
  - CORRIGIDO: "Executar Windows Update" podia travar indefinidamente. A causa era
    um deadlock clássico do Python: stdout e stderr do PowerShell eram lidos como
    pipes separados, mas só o stdout era esvaziado durante a execução — se o
    PowerShell escrevesse o suficiente em stderr para encher o buffer do pipe
    (64 KB), o processo travava esperando escrever, e o programa travava esperando
    ler. Agora stderr é unificado ao stdout (stderr=subprocess.STDOUT), então nunca
    fica sem ser lido. O script PowerShell também ganhou um try/catch geral, então
    qualquer falha real (ex.: política bloqueando o WUA) volta como mensagem clara
    em vez de travar ou falhar silenciosamente.
  - CORRIGIDO: ícones/emojis aparecendo como "?"/"??" no .exe compilado. Não era
    problema de codificação (UTF-8 já estava correto) e sim de FONTE: o console
    clássico do Windows (conhost.exe, o que abre com duplo clique) não tem glifo
    para vários emojis compostos. Agora o programa detecta esse cenário e troca
    automaticamente os ícones por tags em texto puro (ex.: 🌐 → [REDE]), que
    renderizam em qualquer fonte. Em Windows Terminal/VS Code os emojis originais
    continuam aparecendo normalmente.
  - Cores aplicadas de forma consistente em todos os submenus (antes só o menu
    principal e alguns submenus tinham cor por item).

Mudanças de segurança (v4.11, mantidas nesta versão):
  - Senha de e-mail (SMTP) agora é criptografada com DPAPI antes de ir para o disco.
  - Comandos PowerShell que carregam senha (criar usuário local, ingressar em domínio)
    passam a ser executados via arquivo .ps1 temporário com ACL restrita, em vez de
    argumento de linha de comando (evita exposição via listagem de processos).
  - Arquivos/pastas sensíveis (log, backups de DNS, coletas, config de centralização)
    recebem ACL restrita ao usuário atual + Administradores (quando o sistema de
    arquivos suportar NTFS; sem efeito em pendrive FAT32/exFAT).
  - O programa não exige mais Administrador só para abrir: a elevação (UAC) agora
    é solicitada sob demanda, apenas quando uma ação específica realmente precisa.
  - Modo Cliente/Central: por padrão toda instalação é "Cliente" (só coleta e grava
    na pasta compartilhada, nunca guarda a senha de e-mail). Só a instalação marcada
    explicitamente como "Central" (Centralização > opção 8) configura SMTP e envia
    os relatórios consolidados — evita duplicar/expor a mesma senha em N máquinas.
"""

import html
import os
import sys
import atexit
import ntpath

# ==========================================
# BLINDAGEM CONTRA sys.stdout/stderr == None (v5.3)
# ==========================================
# Em builds do PyInstaller com --noconsole/--windowed, dependendo da versão,
# sys.stdout e sys.stderr podem vir como None (não existe console pra escrever).
# Como o backend tem dezenas de print() espalhados (usados normalmente pelo
# modo console/CLI), qualquer um deles chamando print() com stdout=None faria
# o programa levantar "AttributeError: 'NoneType' object has no attribute
# 'write'" bem no meio de uma operação — e isso aconteceria de forma
# imprevisível, dependendo de qual tela/ação o usuário estivesse usando.
# Corrigido de uma vez só aqui: se stdout/stderr vierem None, substitui por
# um "escritor nulo" que simplesmente descarta o texto, em vez de travar.
class _EscritorNulo:
    def write(self, *args, **kwargs): return 0
    def flush(self, *args, **kwargs): pass
    def isatty(self): return False

if sys.stdout is None:
    sys.stdout = _EscritorNulo()
if sys.stderr is None:
    sys.stderr = _EscritorNulo()
import re
import json
import time
import threading
import queue
import ctypes
import logging
import logging.handlers
import subprocess

# ==========================================
# SUPRESSÃO DE JANELAS DE CONSOLE (v5.3)
# ==========================================
# Quando o app roda como GUI compilada com --noconsole, ele não tem console
# próprio. Todo comando que chama um executável de console (powershell.exe,
# ping, arp, taskkill, powercfg, schtasks etc.) faz o Windows abrir uma janela
# de console NOVA para esse processo filho — e como o programa dispara muitos
# desses comandos (às vezes dezenas em paralelo, como na varredura de rede),
# isso pisca várias janelas pretas na tela, confundindo o usuário.
#
# Em vez de editar um por um todos os ~20 pontos que chamam subprocess.run()/
# Popen() (arriscado, fácil esquecer algum agora ou no futuro), aplicamos aqui
# uma correção central: qualquer subprocess.run()/Popen() chamado a partir
# deste processo, em qualquer lugar do programa, passa a receber a flag
# CREATE_NO_WINDOW automaticamente — sem precisar tocar em cada chamada.
if os.name == "nt":
    _CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    _subprocess_run_original = subprocess.run
    _subprocess_popen_original = subprocess.Popen

    def _run_sem_janela(*args, **kwargs):
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | _CREATE_NO_WINDOW
        return _subprocess_run_original(*args, **kwargs)

    class _PopenSemJanela(_subprocess_popen_original):
        def __init__(self, *args, **kwargs):
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | _CREATE_NO_WINDOW
            super().__init__(*args, **kwargs)

    subprocess.run = _run_sem_janela
    subprocess.Popen = _PopenSemJanela
import ipaddress
import socket
import struct
import random
import shutil
import fnmatch
import stat
import hashlib
import math
import platform
import smtplib
import ssl
import tempfile
import base64
import secrets
import zlib
from email.message import EmailMessage
from pathlib import Path
from app_paths import PortablePaths
from typing import List, Tuple, Optional, Dict, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum, auto
from functools import wraps, lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# CONFIGURAÇÕES GLOBAIS E CONSTANTES
# ==========================================
# Diretório base portátil: usa a pasta do .py ou do .exe, e não o diretório
# de onde o programa foi chamado. Isso permite executar diretamente de pendrive.
if getattr(sys, "frozen", False):
    DIRETORIO_BASE = Path(sys.executable).resolve().parent
else:
    DIRETORIO_BASE = Path(__file__).resolve().parent

# Somente localização de persistências; algoritmos e schemas permanecem.
CAMINHOS = PortablePaths(DIRETORIO_BASE)
ARQUIVO_LOG = str(CAMINHOS.file("configurador_ti.log"))
ARQUIVO_PERFIS = str(CAMINHOS.file("perfis_dns.json"))
ARQUIVO_CONFIG = str(CAMINHOS.file("configurador_ti_config.json"))
PASTA_BACKUP = str(CAMINHOS.directory("dados/backups/dns", "backups_dns"))
ARQUIVO_CENTRAL = str(CAMINHOS.file("centralizacao_ti.json"))
PASTA_COLETAS = str(CAMINHOS.directory("coletas", "coletas_centralizadas"))
PASTA_RELATORIOS = CAMINHOS.directory("relatorios")
PASTA_REDE = CAMINHOS.file("inteligencia_rede.json").parent
PASTA_TRIAGEM = CAMINHOS.file("triagem_tecnica.json").parent
ARQUIVO_HISTORICO_BENCHMARK_CONFIGURADOR_TI = str(CAMINHOS.file("benchmark_configurador_ti_historico.json"))
BENCHMARK_CONFIGURADOR_TI_VERSION = 1
SCHEMA_HISTORICO_BENCHMARK_CONFIGURADOR_TI = 1
LIMITE_HISTORICO_BENCHMARK_POR_MAQUINA = 30
TAREFA_COLETA_DIARIA = "ConfiguradorTI_RelatorioDiario"
TAREFA_MANUTENCAO = "ConfiguradorTI_Manutencao"
MODOS_HEADLESS_AUTORIZADOS = {
    "--coleta-diaria",
    "--manutencao-programada",
    "--saude-armazenamento-elevada",
    "--windows-update-elevado",
}
MODOS_AGENDADOS_AUTORIZADOS = {
    "--coleta-diaria",
    "--manutencao-programada",
}
MODO_SAUDE_ARMAZENAMENTO_ELEVADA = "--saude-armazenamento-elevada"
MODO_WINDOWS_UPDATE_ELEVADO = "--windows-update-elevado"
ARG_RESULTADO_SAUDE_ELEVADA = "--resultado"
ARG_NONCE_SAUDE_ELEVADA = "--nonce"
ARG_RESULTADO_WINDOWS_UPDATE = "--resultado"
ARG_NONCE_WINDOWS_UPDATE = "--nonce"
WINDOWS_UPDATE_TIMEOUT_SEGUNDOS = 6 * 60 * 60
WINDOWS_UPDATE_STALL_SEGUNDOS = 45 * 60
_ultima_operacao = 0.0
_cache_ps = {}
_historico_operacoes_sessao = []
_lock_relancamento_uac = threading.RLock()
_lock_saude_armazenamento = threading.Lock()
_lock_benchmark_configurador_ti = threading.Lock()
_lock_analise_defensiva = threading.Lock()
_lock_inventario_empresa = threading.RLock()
_lock_cache_analise_defensiva = threading.RLock()
_cache_assinaturas_analise_defensiva = {}
_cache_hashes_analise_defensiva = {}
_RESET_PYINSTALLER_AUSENTE = object()


def _serializar_coleta_saude_armazenamento(func):
    """Impede duas consultas Storage simultâneas sem bloquear a thread da GUI."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        cancel_callback = kwargs.get("cancel_callback")
        if cancel_callback is None and len(args) > 1:
            cancel_callback = args[1]

        while not _lock_saude_armazenamento.acquire(timeout=0.2):
            try:
                cancelada = bool(
                    callable(cancel_callback) and cancel_callback()
                )
            except Exception:
                cancelada = False
            if cancelada:
                try:
                    logger.info(
                        "SAUDE_ARMAZENAMENTO_RELIABILITY "
                        "fonte=Get-StorageReliabilityCounter "
                        "status=cancelado etapa=espera_storage"
                    )
                except Exception:
                    pass
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Análise de saúde de armazenamento cancelada.",
                    "Discos": [],
                }

        try:
            return func(*args, **kwargs)
        finally:
            _lock_saude_armazenamento.release()

    return wrapper


def _executavel_reinicio_gui():
    """Retorna o executável adequado para relançar a GUI via UAC.

    A versão console continua relançando com ``sys.executable``. Quando o
    processo foi iniciado pela GUI, porém, ``python.exe`` abriria uma janela
    de terminal no relançamento; nesse caso preferimos o irmão ``pythonw.exe``
    (ou o que estiver no PATH). O modo de depuração pode preservar o console
    com ``CONFIGURADOR_TI_DEBUG_CONSOLE=1``.
    """
    if getattr(sys, "frozen", False) or os.name != "nt":
        return sys.executable

    nome_script = Path(sys.argv[0]).name.lower() if sys.argv else ""
    modo_gui = (
        os.environ.get("CONFIGURADOR_TI_GUI_MODE") == "1"
        or nome_script in {"main_gui.py", "main_gui.pyw"}
    )
    if not modo_gui or os.environ.get("CONFIGURADOR_TI_DEBUG_CONSOLE") == "1":
        return sys.executable

    atual = Path(sys.executable)
    if atual.name.lower() == "pythonw.exe":
        return str(atual)

    candidato = atual.with_name("pythonw.exe")
    if candidato.is_file():
        return str(candidato)

    encontrado = shutil.which("pythonw.exe")
    if encontrado:
        return encontrado

    raise FileNotFoundError(
        "pythonw.exe não foi encontrado para relançar a GUI sem console. "
        "Use o launcher main_gui.pyw ou defina "
        "CONFIGURADOR_TI_DEBUG_CONSOLE=1 para depuração."
    )


def executar_relancamento_uac(
    executavel: str,
    parametros: str = "",
    diretorio: Optional[str] = None,
    motivo: str = "",
) -> int:
    """Relança a própria aplicação via UAC com ambiente PyInstaller isolado.

    Desde o PyInstaller 6.9, um processo iniciado pelo mesmo sys.executable
    é tratado, por padrão, como processo auxiliar que pode reutilizar o runtime
    já extraído. No relançamento UAC a nova instância precisa sobreviver à
    anterior; portanto, somente no EXE congelado e somente quando o destino é o
    executável atual, a interface pública PYINSTALLER_RESET_ENVIRONMENT é
    definida durante a criação do processo.

    ShellExecuteW não aceita um bloco de ambiente. A alteração temporária é
    protegida por lock e sempre restaurada em finally. Executáveis externos
    e a execução por fonte não recebem a variável.
    """
    chave = "PYINSTALLER_RESET_ENVIRONMENT"
    congelado = bool(getattr(sys, "frozen", False))
    destino_proprio = False
    if congelado:
        try:
            destino_proprio = os.path.samefile(executavel, sys.executable)
        except (OSError, TypeError, ValueError):
            try:
                destino_proprio = (
                    os.path.normcase(os.path.abspath(str(executavel)))
                    == os.path.normcase(os.path.abspath(str(sys.executable)))
                )
            except Exception:
                destino_proprio = False

    aplicar_reset = congelado and destino_proprio

    def classificar(valor) -> str:
        if valor is _RESET_PYINSTALLER_AUSENTE:
            return "ausente"
        if valor in {"0", "1"}:
            return str(valor)
        return "outro"

    with _lock_relancamento_uac:
        anterior = os.environ.get(chave, _RESET_PYINSTALLER_AUSENTE)
        resultado = None
        if aplicar_reset:
            os.environ[chave] = "1"
        try:
            if aplicar_reset:
                registrar_evento_instancia(
                    "PYINSTALLER_RESET_ENVIRONMENT_PREPARADO",
                    motivo=(
                        f"{motivo or 'RELANCAMENTO_UAC'};"
                        f"valor_anterior={classificar(anterior)}"
                    ),
                    executavel_destino=str(executavel),
                )
            resultado = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                str(executavel),
                parametros,
                diretorio,
                1,
            )
            return resultado
        finally:
            if aplicar_reset:
                if anterior is _RESET_PYINSTALLER_AUSENTE:
                    os.environ.pop(chave, None)
                else:
                    os.environ[chave] = anterior
                registrar_evento_instancia(
                    "PYINSTALLER_RESET_ENVIRONMENT_RESTAURADO",
                    motivo=(
                        f"{motivo or 'RELANCAMENTO_UAC'};"
                        f"valor_anterior={classificar(anterior)};"
                        f"resultado_shell="
                        f"{resultado if resultado is not None else 'excecao'}"
                    ),
                    executavel_destino=str(executavel),
                )


def preparar_relancamento_gui_administrador() -> Dict[str, Any]:
    """Monta somente o relançamento allowlisted da própria GUI.

    Nenhum argumento recebido do usuário é encaminhado. No EXE onefile não há
    parâmetros; em fonte, apenas o caminho absoluto de ``main_gui.pyw`` é
    passado ao ``pythonw.exe`` selecionado pelo runtime.
    """
    if os.name != "nt":
        return {"Status": "nao_suportado"}
    if verificar_admin():
        return {"Status": "ja_administrador"}
    executavel = _executavel_reinicio_gui()
    if getattr(sys, "frozen", False):
        argumentos = []
    else:
        entrada = (DIRETORIO_BASE / "main_gui.pyw").resolve()
        if not entrada.is_file():
            raise FileNotFoundError("main_gui.pyw não foi encontrado para o relançamento.")
        argumentos = [str(entrada)]
    return {
        "Status": "pronto",
        "Executavel": str(executavel),
        "Argumentos": argumentos,
        "Parametros": subprocess.list2cmdline(argumentos),
        "Diretorio": str(DIRETORIO_BASE),
    }


def reiniciar_gui_como_administrador(
    motivo: str = "SESSAO_ADMINISTRATIVA_EXPLICITA",
) -> Dict[str, Any]:
    """Solicita UAC para a GUI inteira sem alterar a política padrão do app."""
    try:
        plano = preparar_relancamento_gui_administrador()
        if plano.get("Status") != "pronto":
            return plano
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_SOLICITADO",
            motivo=motivo,
            executavel_destino=plano["Executavel"],
            argumentos_destino=plano["Argumentos"],
        )
        resultado = executar_relancamento_uac(
            plano["Executavel"],
            plano["Parametros"],
            plano["Diretorio"],
            motivo=motivo,
        )
        if resultado <= 32:
            registrar_evento_instancia(
                "RELANCAMENTO_UAC_CANCELADO_OU_FALHOU",
                motivo=f"{motivo};codigo={resultado}",
            )
            return {"Status": "uac_cancelado_ou_falhou", "Codigo": int(resultado)}
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_ACEITO",
            motivo=motivo,
            executavel_destino=plano["Executavel"],
            argumentos_destino=plano["Argumentos"],
        )
        logger.info("RELANCAMENTO_ADMIN_EXPLICITO | status=aceito")
        return {"Status": "iniciado", "Codigo": int(resultado)}
    except Exception as exc:
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_FALHOU",
            motivo=f"{motivo};tipo={type(exc).__name__}",
        )
        try:
            logger.exception("Falha no relançamento administrativo explícito")
        except Exception:
            pass
        return {"Status": "erro", "Tipo": type(exc).__name__}


def executar_auxiliar_elevado_aguardando(
    executavel: str,
    argumentos,
    diretorio: Optional[str] = None,
    timeout: int = 90,
    cancel_callback=None,
    status_callback=None,
) -> Dict[str, Any]:
    """Inicia um processo auxiliar via UAC e aguarda seu término.

    Diferentemente do relançamento global, este helper mantém a GUI normal
    aberta, não altera sua política de privilégios e conserva um handle apenas
    para observar/cancelar o processo auxiliar. Não captura stdout/stderr: o
    contrato de retorno usa exclusivamente um arquivo temporário validado.
    """
    if os.name != "nt":
        return {
            "Status": "nao_suportado",
            "Mensagem": "A coleta elevada está disponível somente no Windows.",
        }
    if not isinstance(executavel, str) or not executavel.strip():
        return {"Status": "erro", "Tipo": "ExecutavelInvalido"}
    if not isinstance(argumentos, (list, tuple)) or not all(
        isinstance(item, str) for item in argumentos
    ):
        return {"Status": "erro", "Tipo": "ArgumentosInvalidos"}

    try:
        from ctypes import wintypes

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("fMask", wintypes.ULONG),
                ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", wintypes.LPVOID),
                ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD),
                ("hIcon", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE),
            ]

        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        shell_execute_ex = shell32.ShellExecuteExW
        shell_execute_ex.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
        shell_execute_ex.restype = wintypes.BOOL

        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x00000040 | 0x00000400  # NOCLOSEPROCESS | FLAG_NO_UI
        info.lpVerb = "runas"
        info.lpFile = str(executavel)
        info.lpParameters = subprocess.list2cmdline(list(argumentos))
        info.lpDirectory = str(diretorio) if diretorio else None
        info.nShow = 0  # SW_HIDE; somente o prompt UAC permanece visível.

        if not shell_execute_ex(ctypes.byref(info)):
            codigo = ctypes.get_last_error()
            if codigo == 1223:  # ERROR_CANCELLED: usuário recusou o UAC.
                return {"Status": "uac_cancelado", "Codigo": codigo}
            return {
                "Status": "erro",
                "Tipo": "ShellExecuteEx",
                "Codigo": int(codigo),
            }
        if not info.hProcess:
            return {"Status": "erro", "Tipo": "HandleAusente"}

        wait_for_single_object = kernel32.WaitForSingleObject
        wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        wait_for_single_object.restype = wintypes.DWORD
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_exit_code.restype = wintypes.BOOL
        terminate_process = kernel32.TerminateProcess
        terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
        terminate_process.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        limite = time.monotonic() + max(5, int(timeout))
        try:
            while True:
                if callable(status_callback):
                    try:
                        status_callback()
                    except Exception:
                        pass
                espera = int(wait_for_single_object(info.hProcess, 200))
                if espera == 0:  # WAIT_OBJECT_0
                    codigo_saida = wintypes.DWORD()
                    if not get_exit_code(info.hProcess, ctypes.byref(codigo_saida)):
                        return {"Status": "erro", "Tipo": "ExitCodeIndisponivel"}
                    return {"Status": "ok", "CodigoSaida": int(codigo_saida.value)}
                if espera != 258:  # WAIT_TIMEOUT
                    return {
                        "Status": "erro",
                        "Tipo": "WaitForSingleObject",
                        "Codigo": espera,
                    }
                try:
                    cancelada = bool(
                        callable(cancel_callback) and cancel_callback()
                    )
                except Exception:
                    cancelada = False
                if cancelada:
                    terminate_process(info.hProcess, 125)
                    wait_for_single_object(info.hProcess, 3000)
                    return {"Status": "cancelado", "CodigoSaida": 125}
                if time.monotonic() >= limite:
                    terminate_process(info.hProcess, 124)
                    wait_for_single_object(info.hProcess, 3000)
                    return {"Status": "timeout", "CodigoSaida": 124}
        finally:
            close_handle(info.hProcess)
    except Exception as exc:
        return {"Status": "erro", "Tipo": type(exc).__name__}

# ==========================================
# ENDURECIMENTO DE SEGURANÇA (v4.11)
# ==========================================
# Este bloco concentra as melhorias de segurança pedidas na revisão:
#   1) Criptografia da senha de e-mail com DPAPI do Windows (não fica mais em texto puro).
#   2) Execução de comandos PowerShell que contêm senha via arquivo .ps1 temporário
#      com ACL restrita, em vez de argumento de linha de comando (evita exposição
#      via listagem de processos).
#   3) Restrição de ACL (NTFS) nos arquivos/pastas sensíveis gerados pelo programa.
#   4) Elevação de privilégios sob demanda (não força admin para operações de leitura).
#
# Observação importante sobre portabilidade (pendrive): a criptografia DPAPI usada
# aqui é vinculada à MÁQUINA (CRYPTPROTECT_LOCAL_MACHINE). Isso significa que, se
# você copiar o pendrive/pasta para outro computador, a senha de e-mail salva não
# poderá ser decifrada lá e precisará ser reconfigurada. Isso é esperado: é o preço
# de não guardar mais a senha em texto puro.
#
# Observação sobre pendrives FAT32/exFAT: essas pastas de arquivo não suportam ACL
# NTFS. As funções abaixo tentam aplicar a ACL e simplesmente ignoram (sem travar
# o programa) quando o sistema de arquivos não suporta.

_PREFIXO_DPAPI = "dpapi:"
CRYPTPROTECT_LOCAL_MACHINE = 0x4
CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_disponivel() -> bool:
    return os.name == "nt"


def criptografar_dpapi(texto_plano: str) -> str:
    """Criptografa uma string com DPAPI (escopo de máquina) e devolve em Base64.

    Segredos nunca são devolvidos em texto puro como fallback. Fora do Windows
    ou quando o DPAPI falha, o chamador recebe erro e não deve salvar a
    configuração sensível.
    """
    if not texto_plano:
        return ""
    if not _dpapi_disponivel():
        raise RuntimeError(
            "DPAPI indisponível; a senha não foi salva para evitar texto puro."
        )
    try:
        dados = texto_plano.encode("utf-8")
        entrada = _DATA_BLOB(len(dados), ctypes.cast(ctypes.create_string_buffer(dados, len(dados)), ctypes.POINTER(ctypes.c_char)))
        saida = _DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(entrada), "ConfiguradorTI-Email", None, None, None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(saida)
        )
        if not ok:
            raise RuntimeError("CryptProtectData falhou.")
        cifrado = ctypes.string_at(saida.pbData, saida.cbData)
        ctypes.windll.kernel32.LocalFree(saida.pbData)
        return _PREFIXO_DPAPI + base64.b64encode(cifrado).decode("ascii")
    except Exception as e:
        logger.error("Falha ao criptografar com DPAPI; senha não foi salva: %s", e)
        raise RuntimeError(
            "Não foi possível proteger a senha com DPAPI; configuração não salva."
        ) from e


def descriptografar_dpapi(valor_salvo: str) -> str:
    """Reverte criptografar_dpapi. Aceita também valores antigos em texto puro
    (compatibilidade com configurações salvas por versões anteriores)."""
    if not valor_salvo:
        return ""
    if not valor_salvo.startswith(_PREFIXO_DPAPI):
        return valor_salvo  # valor legado em texto puro
    if not _dpapi_disponivel():
        return ""
    try:
        cifrado = base64.b64decode(valor_salvo[len(_PREFIXO_DPAPI):])
        entrada = _DATA_BLOB(len(cifrado), ctypes.cast(ctypes.create_string_buffer(cifrado, len(cifrado)), ctypes.POINTER(ctypes.c_char)))
        saida = _DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(entrada), None, None, None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(saida)
        )
        if not ok:
            raise RuntimeError("CryptUnprotectData falhou.")
        texto = ctypes.string_at(saida.pbData, saida.cbData).decode("utf-8")
        ctypes.windll.kernel32.LocalFree(saida.pbData)
        return texto
    except Exception as e:
        logger.warning("Falha ao decifrar senha salva (%s). Pode ter sido salva em outra máquina.", e)
        return ""


def restringir_acl_arquivo(caminho: str) -> None:
    """Restringe um arquivo/pasta (NTFS) ao usuário atual + Administradores.

    Silenciosamente ignorado se o sistema de arquivos não suportar ACL (ex.: pendrive
    formatado em FAT32/exFAT) ou fora do Windows.
    """
    if os.name != "nt":
        return
    try:
        identidade = os.environ.get("USERNAME", "%USERNAME%")
        try:
            consulta = subprocess.run(
                ["whoami.exe", "/user", "/fo", "csv", "/nh"],
                capture_output=True, text=False, timeout=10, shell=False,
            )
            texto = decodificar_saida_windows(
                consulta.stdout or consulta.stderr
            )
            encontrado = re.search(r"S-1-5-(?:\d+-)+\d+", texto)
            if consulta.returncode == 0 and encontrado:
                identidade = "*" + encontrado.group(0)
        except Exception:
            pass
        subprocess.run(
            ["icacls", str(caminho), "/inheritance:r",
             "/grant:r", f"{identidade}:F",
             "/grant:r", "*S-1-5-32-544:F"],  # grupo Administradores (SID universal)
            capture_output=True, text=True, timeout=15, shell=False,
        )
    except Exception:
        pass  # não trava o programa por causa de ACL (ex.: FAT32/exFAT)


def executar_powershell_com_senha(comando: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Executa um comando PowerShell que contém segredo (senha) sem passá-lo como
    argumento de linha de comando (o que ficaria visível em Get-Process/Process Explorer).

    O comando é escrito em um arquivo .ps1 temporário com ACL restrita ao usuário
    atual, executado com -File, e o arquivo é sobrescrito e apagado logo em seguida.
    """
    if not isinstance(comando, str) or not comando.strip():
        raise ValueError("Comando PowerShell inválido.")

    pasta_tmp = Path(DIRETORIO_BASE) / ".ps_tmp"
    pasta_tmp.mkdir(parents=True, exist_ok=True)
    restringir_acl_arquivo(str(pasta_tmp))

    caminho_ps1 = pasta_tmp / f"cmd_{os.getpid()}_{int(time.time()*1000)}.ps1"
    conteudo = "$ErrorActionPreference='Stop'\n" + comando
    try:
        caminho_ps1.write_text(conteudo, encoding="utf-8-sig")
        restringir_acl_arquivo(str(caminho_ps1))

        resultado_bruto = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(caminho_ps1)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout
        )
        return resultado_bruto
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"O comando demorou mais de {timeout} segundos para terminar.") from e
    finally:
        # Sobrescreve o conteúdo antes de apagar (mitigação; não é wipe seguro de disco).
        try:
            tamanho = caminho_ps1.stat().st_size
            with open(caminho_ps1, "r+b") as f:
                f.write(b"0" * tamanho)
            caminho_ps1.unlink(missing_ok=True)
        except Exception:
            pass


def elevacao_sob_demanda(motivo: str = "") -> bool:
    """Solicita elevação de privilégios apenas quando a ação exige (menos
    incômodo e mais seguro do que exigir admin o tempo todo).

    Se o processo já for admin, retorna True imediatamente. Caso contrário,
    pergunta ao usuário se deseja elevar agora; se aceitar, reabre o programa
    elevado (via UAC) e encerra a instância atual sem privilégio.
    Retorna False se o usuário recusar (a ação deve ser cancelada pelo chamador).
    """
    if verificar_admin():
        return True
    print(f"\n{Cores.AMARELO}⚠️  Esta ação ({motivo or 'operação selecionada'}) exige privilégios de Administrador.{Cores.RESET}")
    if not confirmar_acao("Deseja elevar o programa para Administrador agora?", True):
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_CANCELADO",
            motivo=f"BACKEND:{motivo or 'operacao selecionada'}",
        )
        print(f"{Cores.CINZA}Ação cancelada (sem privilégios de administrador).{Cores.RESET}")
        return False
    try:
        executavel = _executavel_reinicio_gui()
        argumentos_destino = [] if getattr(sys, "frozen", False) else list(sys.argv)
        parametros = "" if getattr(sys, "frozen", False) else " ".join(f'"{a}"' for a in sys.argv)
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_SOLICITADO",
            motivo=f"BACKEND:{motivo or 'operacao selecionada'}",
            executavel_destino=executavel,
            argumentos_destino=argumentos_destino,
        )
        resultado = executar_relancamento_uac(
            executavel,
            parametros,
            str(DIRETORIO_BASE),
            motivo=f"BACKEND:{motivo or 'operacao selecionada'}",
        )
        if resultado <= 32:
            raise OSError(
                f"ShellExecuteW retornou código {resultado} ao solicitar UAC."
            )
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_ACEITO",
            motivo=f"BACKEND:{motivo or 'operacao selecionada'}",
            executavel_destino=executavel,
            argumentos_destino=argumentos_destino,
        )
    except Exception as e:
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_FALHOU",
            motivo=f"BACKEND:{motivo or 'operacao selecionada'}:{type(e).__name__}",
        )
        print(f"{Cores.VERMELHO}❌ Não foi possível elevar: {e}{Cores.RESET}")
        try:
            logger.exception("Falha ao solicitar elevação de privilégios")
        except Exception:
            pass
        if os.environ.get("CONFIGURADOR_TI_GUI_MODE") != "1":
            try:
                input("Pressione Enter...")
            except (EOFError, OSError):
                pass
        return False
    registrar_instancia_encerrando(
        f"RELANCAMENTO_UAC_BACKEND:{motivo or 'operacao selecionada'}"
    )
    sys.exit(0)

# ==========================================
# CONFIGURAÇÃO DE LOGGING AVANÇADO
# ==========================================
def configurar_logging():
    global ARQUIVO_LOG
    logger = logging.getLogger("ConfiguradorTI")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    
    # Limpar handlers existentes
    logger.handlers = []
    
    file_formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(module)s", '
        '"funcao": "%(funcName)s", "linha": %(lineno)d, "mensagem": "%(message)s"}'
    )

    # A inicialização não pode falhar apenas porque a pasta do programa está
    # sem permissão de escrita (por exemplo, pendrive protegido ou Program
    # Files). Tenta primeiro o caminho portátil e depois a pasta temporária do
    # usuário. Se ambos falharem, mantém o console/NullHandler e deixa o app
    # abrir, sem remover o logging das instalações em que ele está disponível.
    erros_arquivo = []
    candidatos_log = [
        Path(ARQUIVO_LOG),
        Path(tempfile.gettempdir()) / "ConfiguradorTI" / "configurador_ti.log",
    ]
    file_handler = None
    for candidato in candidatos_log:
        try:
            candidato.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                str(candidato), maxBytes=5*1024*1024, backupCount=3,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(file_formatter)
            ARQUIVO_LOG = str(candidato)
            logger.addHandler(file_handler)
            break
        except (OSError, PermissionError) as exc:
            erros_arquivo.append(f"{candidato}: {exc}")
    
    # Handler para console (apenas warnings+)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(console_handler)
    if file_handler is None:
        logger.addHandler(logging.NullHandler())
        try:
            console_handler.handle(logging.LogRecord(
                "ConfiguradorTI", logging.WARNING, __file__, 0,
                "Não foi possível criar o arquivo de log. A aplicação continuará sem log em disco. "
                + " | ".join(erros_arquivo), (), None
            ))
        except Exception:
            pass
    elif erros_arquivo:
        logger.warning(
            "O log portátil não pôde ser criado; usando caminho alternativo: %s",
            ARQUIVO_LOG,
        )
    return logger

logger = configurar_logging()
CAMINHOS.log_events(logger)
try:
    # Restringe o log (pode conter nomes de host, IPs, usuários locais) ao
    # usuário atual + Administradores. Silenciosamente ignorado em FAT32/exFAT.
    if os.name == "nt":
        subprocess.run(
            ["icacls", ARQUIVO_LOG, "/inheritance:r",
             "/grant:r", f"{os.environ.get('USERNAME','%USERNAME%')}:F",
             "/grant:r", "*S-1-5-32-544:F"],
            capture_output=True, text=True, timeout=15
        )
except Exception:
    pass


# ==========================================
# RASTREAMENTO SEGURO DE INSTÂNCIAS (FASE 1B-R5)
# ==========================================
# O runtime --onefile do PyInstaller cria um diretório _MEI exclusivo para
# cada instância. Estes eventos permitem correlacionar, sem dados sensíveis,
# qual PID iniciou, relançou ou encerrou cada runtime observado em Windows.
_ARGUMENTOS_INSTANCIA_PERMITIDOS = {
    "--coleta-diaria",
    "--manutencao-programada",
    MODO_SAUDE_ARMAZENAMENTO_ELEVADA,
    ARG_RESULTADO_SAUDE_ELEVADA,
    ARG_NONCE_SAUDE_ELEVADA,
}
_MARCADORES_SEGREDO_ARGUMENTO = (
    "senha", "password", "passwd", "token", "secret", "segredo",
    "credential", "credencial", "api-key", "apikey",
)
_encerramento_instancia_registrado = False
_lock_encerramento_instancia = threading.Lock()


def _sanitizar_argumentos_instancia(argumentos=None) -> List[str]:
    """Retorna argumentos adequados para log, sem copiar valores arbitrários.

    O caminho de entrada e os modos internos conhecidos ajudam a identificar
    a origem da instância. Valores posicionais desconhecidos são omitidos e
    opções que possam representar segredo têm seu valor explicitamente
    redigido.
    """
    if argumentos is None:
        argumentos = sys.argv
    if isinstance(argumentos, (str, bytes)):
        argumentos = [argumentos]

    seguros = []
    redigir_proximo = False
    for indice, argumento in enumerate(argumentos):
        texto = str(argumento)
        if redigir_proximo:
            seguros.append("<redigido>")
            redigir_proximo = False
            continue

        chave = texto.split("=", 1)[0].lstrip("-/").casefold()
        if any(marcador in chave for marcador in _MARCADORES_SEGREDO_ARGUMENTO):
            if "=" in texto:
                seguros.append(texto.split("=", 1)[0] + "=<redigido>")
            else:
                seguros.append(texto)
                redigir_proximo = True
            continue

        if indice == 0 or texto in _ARGUMENTOS_INSTANCIA_PERMITIDOS:
            seguros.append(texto)
        elif texto.startswith(("--", "/")):
            seguros.append(texto.split("=", 1)[0] + ("=<omitido>" if "=" in texto else ""))
        else:
            seguros.append("<argumento-omitido>")
    return seguros


def _valor_log_instancia(valor, limite: int = 1200) -> str:
    """Escapa um campo para não quebrar o formato de uma linha do log."""
    texto = str(valor)
    texto = texto.replace("\\", "\\\\").replace('"', '\\"')
    texto = texto.replace("\r", "\\r").replace("\n", "\\n")
    return texto[:limite]


def registrar_evento_instancia(
    evento: str,
    motivo: str = "",
    executavel_destino: str = "",
    argumentos_destino=None,
) -> None:
    """Registra o ciclo de vida da instância sem depender de console."""
    try:
        try:
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False
        except Exception:
            admin = False

        campos = {
            "evento": evento,
            "instante": datetime.now().astimezone().isoformat(timespec="seconds"),
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "executavel": sys.executable,
            "argv": json.dumps(_sanitizar_argumentos_instancia(), ensure_ascii=False),
            "frozen": bool(getattr(sys, "frozen", False)),
            "meipass": getattr(sys, "_MEIPASS", ""),
            "gui": os.environ.get("CONFIGURADOR_TI_GUI_MODE") == "1",
            "admin": admin,
        }
        if motivo:
            campos["motivo"] = motivo
        if executavel_destino:
            campos["destino"] = executavel_destino
        if argumentos_destino is not None:
            campos["argv_destino"] = json.dumps(
                _sanitizar_argumentos_instancia(argumentos_destino),
                ensure_ascii=False,
            )
        mensagem = "INSTANCIA | " + " | ".join(
            f'{chave}="{_valor_log_instancia(valor)}"'
            for chave, valor in campos.items()
        )
        logger.info(mensagem)
    except Exception:
        # Instrumentação nunca pode impedir a inicialização/saída.
        pass


def registrar_instancia_encerrando(motivo: str = "") -> None:
    """Registra uma vez o encerramento normal ou solicitado da instância."""
    global _encerramento_instancia_registrado
    try:
        with _lock_encerramento_instancia:
            if _encerramento_instancia_registrado:
                return
            _encerramento_instancia_registrado = True
        registrar_evento_instancia("INSTANCIA_ENCERRANDO", motivo=motivo)
    except Exception:
        pass


registrar_evento_instancia("INSTANCIA_INICIADA")
atexit.register(registrar_instancia_encerrando, "ATEXIT")

# ==========================================
# INTERFACE E PALETA DE CORES ANSI
# ==========================================
class Cores:
    RESET = "\033[0m"
    VERMELHO = "\033[91m"
    VERDE = "\033[92m"
    AMARELO = "\033[93m"
    AZUL = "\033[94m"
    MAGENTA = "\033[95m"
    CIANO = "\033[96m"
    NEGRITO = "\033[1m"
    AZUL_CLARO = "\033[38;5;75m"
    CINZA = "\033[90m"
    FUNDO_VERDE = "\033[42m"
    FUNDO_VERMELHO = "\033[41m"


# ==========================================
# ÍCONES SEGUROS (fallback quando o console não tem fonte com emoji)
# ==========================================
# O prompt clássico do Windows (conhost.exe, usado ao dar duplo-clique no
# .exe) normalmente usa a fonte "Consolas"/"Terminal", que não tem glifo
# para vários emojis compostos (ex.: 🛠️🚪🏢📊) — mesmo com a codificação
# UTF-8 correta, o caractere aparece como "?" ou "??" por FALTA DE FONTE,
# não por erro de codificação. A tabela abaixo troca cada ícone por uma
# tag em texto puro (ASCII), que renderiza em QUALQUER fonte/console.
# A troca só é aplicada quando detectamos um console sem suporte
# confiável a emoji (ver detectar_suporte_emoji); no Windows Terminal,
# VS Code etc. os emojis originais continuam aparecendo normalmente.
_TABELA_ICONES_SEGUROS = {
    0x274C: '[ERRO]', 0x2705: '[OK]', 0x26A0: '[AVISO]', 0x1F4CB: '[LOG]',
    0x1F310: '[REDE]', 0x1F504: '[ATUALIZAR]', 0x1F4CA: '[RELATORIO]',
    0x1F3E2: '[EMPRESA]', 0x1F50E: '[BUSCAR]', 0x21A9: '[VOLTAR]',
    0x1F50D: '[BUSCAR]', 0x1F4E1: '[MONITOR]', 0x26A1: '[ENERGIA]',
    0x1F6AA: '[SAIR]', 0x2713: '[OK]', 0x2717: '[X]', 0x1F4BE: '[SALVAR]',
    0x1F5A8: '[IMPRESSORA]', 0x1F680: '[IMPLANTACAO]', 0x2699: '[CONFIG]',
    0x1F9E0: '[MEMORIA]', 0x1F6E0: '[MANUTENCAO]', 0x1F50C: '[CONEXAO]',
    0x1F522: '[NUM]', 0x1F4C8: '[GRAFICO]', 0x1FA9F: '[WINDOWS]',
    0x1F4C2: '[PASTA]', 0x270F: '[EDITAR]', 0x1F9F9: '[LIMPAR]',
    0x1F5A5: '[PC]', 0x1F4E6: '[PACOTE]', 0x1F6E1: '[SEGURANCA]',
    0x1F4DF: '[DISP]', 0x21BB: '[SYNC]', 0x1F4BB: '[PC]', 0x1F9F1: '[FIREWALL]',
    0x1F5D1: '[LIXEIRA]', 0x1F9EA: '[TESTE]', 0x1F4A1: '[DICA]',
    0x1F50B: '[BATERIA]', 0x1F527: '[FERRAMENTA]', 0x1F7E2: '[ATIVO]',
    0x1F7E1: '[ALERTA]', 0x1F534: '[INATIVO]', 0x2795: '[+]',
    0x1F4E7: '[EMAIL]', 0x1F4E4: '[ENVIAR]', 0x1F510: '[SEGURO]',
    0x1F4C4: '[DOC]', 0x1F5DC: '[COMPACTAR]', 0x1F464: '[USUARIO]',
    0x1F517: '[LINK]', 0x267B: '[RECICLAR]', 0x1F4BD: '[DISCO]',
    0xFE0F: '',  # seletor de variação (colorido) — apenas remove, é invisível
}


def detectar_suporte_emoji() -> bool:
    """Detecta, de forma conservadora, se o terminal atual tem fonte capaz
    de exibir emojis coloridos. Fora do Windows, assume que sim (macOS/Linux
    modernos resolvem isso na própria fonte do terminal). No Windows, só
    consideramos "seguro" o Windows Terminal, VS Code e ConEmu — o prompt
    clássico (conhost.exe), que é o que o usuário final normalmente vê ao
    abrir o .exe com duplo clique, cai no fallback em texto puro.
    """
    if os.name != "nt":
        return True
    if os.environ.get("WT_SESSION") or os.environ.get("WT_PROFILE_ID"):
        return True
    if os.environ.get("TERM_PROGRAM", "").lower() == "vscode":
        return True
    if os.environ.get("ConEmuANSI") == "ON":
        return True
    return False


_SUPORTA_EMOJI = detectar_suporte_emoji()


def txt_icone(s: str) -> str:
    """Aplica o fallback de ícones seguros quando necessário. Também é usada
    diretamente por quem monta strings fora do caminho normal de print()."""
    if _SUPORTA_EMOJI:
        return s
    return s.translate(_TABELA_ICONES_SEGUROS)


def _obter_handle_console_saida():
    """Retorna o handle do console de saída quando stdout é um console real."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle in (0, -1):
            return None
        modo = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(modo)):
            return None
        return handle
    except Exception:
        return None


class _ConsoleANSIWriter:
    """Fallback interno para consoles Windows que não interpretam ANSI/VT.

    Não usa colorama nem qualquer pacote externo. Converte os códigos ANSI
    usados pela interface para atributos nativos do console Win32.
    """
    _ansi = re.compile(r"\x1b\[([0-9;]*)m")

    # Bits de cor do console Win32.
    _FG_BLUE = 0x0001
    _FG_GREEN = 0x0002
    _FG_RED = 0x0004
    _FG_INTENSITY = 0x0008
    _BG_BLUE = 0x0010
    _BG_GREEN = 0x0020
    _BG_RED = 0x0040
    _BG_INTENSITY = 0x0080

    _fg_map = {
        30: 0, 31: _FG_RED, 32: _FG_GREEN, 33: _FG_RED | _FG_GREEN,
        34: _FG_BLUE, 35: _FG_RED | _FG_BLUE, 36: _FG_GREEN | _FG_BLUE,
        37: _FG_RED | _FG_GREEN | _FG_BLUE,
        90: _FG_INTENSITY,
        91: _FG_RED | _FG_INTENSITY,
        92: _FG_GREEN | _FG_INTENSITY,
        93: _FG_RED | _FG_GREEN | _FG_INTENSITY,
        94: _FG_BLUE | _FG_INTENSITY,
        95: _FG_RED | _FG_BLUE | _FG_INTENSITY,
        96: _FG_GREEN | _FG_BLUE | _FG_INTENSITY,
        97: _FG_RED | _FG_GREEN | _FG_BLUE | _FG_INTENSITY,
    }
    _bg_map = {
        40: 0, 41: _BG_RED, 42: _BG_GREEN, 43: _BG_RED | _BG_GREEN,
        44: _BG_BLUE, 45: _BG_RED | _BG_BLUE, 46: _BG_GREEN | _BG_BLUE,
        47: _BG_RED | _BG_GREEN | _BG_BLUE,
        100: _BG_INTENSITY,
        101: _BG_RED | _BG_INTENSITY,
        102: _BG_GREEN | _BG_INTENSITY,
        103: _BG_RED | _BG_GREEN | _BG_INTENSITY,
        104: _BG_BLUE | _BG_INTENSITY,
        105: _BG_RED | _BG_BLUE | _BG_INTENSITY,
        106: _BG_GREEN | _BG_BLUE | _BG_INTENSITY,
        107: _BG_RED | _BG_GREEN | _BG_BLUE | _BG_INTENSITY,
    }

    def __init__(self, stream, handle):
        self.stream = stream
        self.handle = handle
        self.kernel32 = ctypes.windll.kernel32
        self._default = self._get_default_attributes()
        self._current = self._default

    def _get_default_attributes(self):
        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                        ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ("dwSize", COORD),
                ("dwCursorPosition", COORD),
                ("wAttributes", ctypes.c_ushort),
                ("srWindow", SMALL_RECT),
                ("dwMaximumWindowSize", COORD),
            ]

        info = CONSOLE_SCREEN_BUFFER_INFO()
        if self.kernel32.GetConsoleScreenBufferInfo(self.handle, ctypes.byref(info)):
            return int(info.wAttributes)
        return 7

    def _set_attr(self, attr):
        self._current = attr
        try:
            self.kernel32.SetConsoleTextAttribute(self.handle, attr)
        except Exception:
            pass

    def _apply_sgr(self, params):
        if not params:
            params = [0]
        for code in params:
            if code == 0:
                self._set_attr(self._default)
            elif code == 1:
                self._set_attr(self._current | self._FG_INTENSITY)
            elif code in self._fg_map:
                # Mantém o fundo atual.
                bg = self._current & 0x00F0
                self._set_attr(bg | self._fg_map[code])
            elif code in self._bg_map:
                fg = self._current & 0x000F
                self._set_attr(fg | self._bg_map[code])
            elif code == 22:
                self._set_attr(self._current & ~self._FG_INTENSITY)
            elif code == 39:
                self._set_attr((self._current & 0x00F0) | (self._default & 0x000F))
            elif code == 49:
                self._set_attr((self._current & 0x000F) | (self._default & 0x00F0))
            elif code == 38:
                # O código 38;5;75 (AZUL_CLARO) usado no programa recebe
                # uma aproximação visual em azul/ciano brilhante.
                self._set_attr((self._current & 0x00F0) |
                               self._FG_BLUE | self._FG_GREEN | self._FG_INTENSITY)
        return

    def write(self, data):
        if not data:
            return 0
        if not _SUPORTA_EMOJI:
            data = data.translate(_TABELA_ICONES_SEGUROS)
        pos = 0
        for match in self._ansi.finditer(data):
            self.stream.write(data[pos:match.start()])
            raw = match.group(1)
            try:
                params = [int(x) for x in raw.split(";") if x != ""]
            except ValueError:
                params = [0]
            self._apply_sgr(params)
            pos = match.end()
        self.stream.write(data[pos:])
        return len(data)

    def flush(self):
        self.stream.flush()

    def isatty(self):
        try:
            return self.stream.isatty()
        except Exception:
            return True

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _FiltroIconesWriter:
    """Wrapper leve para quando o console JÁ suporta ANSI/VT nativamente
    (não precisa da conversão de cores do _ConsoleANSIWriter) mas a fonte
    ainda pode não ter os glifos de emoji — troca só os ícones, sem mexer
    em nada relacionado a cor."""

    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        if data:
            data = data.translate(_TABELA_ICONES_SEGUROS)
        return self.stream.write(data)

    def flush(self):
        self.stream.flush()

    def isatty(self):
        try:
            return self.stream.isatty()
        except Exception:
            return True

    def __getattr__(self, name):
        return getattr(self.stream, name)


def habilitar_cores_terminal():
    """Habilita ANSI/VT e usa fallback Win32 quando ANSI não estiver disponível."""
    if os.name != "nt":
        return True

    handle = _obter_handle_console_saida()
    if handle is None:
        return False

    try:
        kernel32 = ctypes.windll.kernel32
        modo = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(modo)):
            return False

        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        novo_modo = modo.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if kernel32.SetConsoleMode(handle, novo_modo):
            # VT nativo funcionando: cores não precisam de conversão, mas
            # ainda pode faltar glifo de emoji na fonte do console — aplica
            # só o filtro de ícones nesse caso (sem tocar em nada de cor).
            if not _SUPORTA_EMOJI:
                try:
                    if not isinstance(sys.stdout, (_ConsoleANSIWriter, _FiltroIconesWriter)):
                        sys.stdout = _FiltroIconesWriter(sys.stdout)
                except Exception:
                    pass
            return True
    except Exception:
        pass

    # Consoles legados: converte ANSI para atributos Win32.
    try:
        if not isinstance(sys.stdout, _ConsoleANSIWriter):
            sys.stdout = _ConsoleANSIWriter(sys.stdout, handle)
        return True
    except Exception:
        return False


def inicializar_terminal():
    """Inicializa cores e codificação do console sem dependências externas.

    A ordem é importante no executável PyInstaller: primeiro ajustamos o
    TextIOWrapper do Python para UTF-8 e depois instalamos o fallback ANSI.
    Assim os ícones Unicode não são convertidos em '?' antes de o escritor
    de cores receber o texto.
    """
    try:
        if os.name == "nt":
            try:
                # API nativa é preferível ao os.system/chcp, pois não cria
                # outro processo e funciona melhor no executável portátil.
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleOutputCP(65001)
                kernel32.SetConsoleCP(65001)

                # O PyInstaller pode iniciar stdout/stderr com a codificação
                # OEM/ANSI. Reconfiguramos ANTES do wrapper ANSI para que
                # acentos e emojis cheguem corretamente ao console.
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                if hasattr(sys.stderr, "reconfigure"):
                    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                try:
                    os.system("chcp 65001 > nul")
                    if hasattr(sys.stdout, "reconfigure"):
                        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                    if hasattr(sys.stderr, "reconfigure"):
                        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
                except Exception:
                    pass

        # Depois da codificação, habilita ANSI/VT ou o conversor Win32 interno.
        habilitar_cores_terminal()
    except Exception:
        pass

# ==========================================
# ENUMS PARA MENUS
# ==========================================
class MenuPrincipal(Enum):
    REDE = "1"
    SISTEMA = "2"
    LOGS = "3"
    RELATORIO = "4"
    EMPRESA = "5"
    MONITORAMENTO = "6"
    CENTRAL = "7"
    SAIR = "0"

class MenuRede(Enum):
    CONSULTAR = "1"
    PERFIS_DNS = "2"
    DNS_MANUAL = "3"
    RESTAURAR_DHCP = "4"
    RENOVAR_CONEXAO = "5"
    TESTAR_DNS = "6"
    IP_FIXO = "7"
    VOLTAR = "0"

class MenuSistema(Enum):
    DIAGNOSTICO = "1"
    LIMPEZA_TEMP = "2"
    SPOOLER = "3"
    INFO_DETALHADA = "4"
    VERIFICAR_DISCO = "5"
    OTIMIZAR_DISCO = "6"
    PLANO_ENERGIA = "7"
    WINDOWS_UPDATE = "8"
    VERSAO_WINDOWS = "9"
    RENOMEAR_COMPUTADOR = "10"
    GERENCIADOR_TAREFAS = "11"
    MONITORAMENTO_ATIVO = "12"
    PERFIL_EMPRESA = "13"
    INVENTARIO_REDE = "14"
    VOLTAR = "0"

# ==========================================
# DATACLASSES PARA ESTRUTURAS DE DADOS
# ==========================================
@dataclass
class AdaptadorRede:
    nome: str
    status: str
    interface_alias: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    link_speed: Optional[str] = None
    gateway: Optional[str] = None
    dns: List[str] = field(default_factory=list)
    
    def esta_ativo(self) -> bool:
        return self.status in ['Up', '1', 'Connected']

@dataclass
class PerfilDNS:
    nome: str
    servidores: List[str]
    descricao: Optional[str] = None
    criado_em: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'nome': self.nome,
            'servidores': self.servidores,
            'descricao': self.descricao,
            'criado_em': self.criado_em.isoformat()
        }
    
    @classmethod
    def from_dict(cls, dados: Dict) -> 'PerfilDNS':
        return cls(
            nome=dados['nome'],
            servidores=dados['servidores'],
            descricao=dados.get('descricao'),
            criado_em=datetime.fromisoformat(dados['criado_em']) if 'criado_em' in dados else datetime.now()
        )

@dataclass
class InfoSistema:
    hostname: str
    usuario: str
    os_info: str
    cpu: str
    placa_mae: str
    ram_total_gb: float
    ram_livre_gb: float
    discos: List[Dict] = field(default_factory=list)
    particoes: List[Dict] = field(default_factory=list)
    
    @property
    def ram_usada_gb(self) -> float:
        return round(self.ram_total_gb - self.ram_livre_gb, 2)
    
    @property
    def ram_percentual(self) -> float:
        return round((self.ram_usada_gb / self.ram_total_gb) * 100, 1) if self.ram_total_gb > 0 else 0

# ==========================================
# FUNÇÕES UTILITÁRIAS
# ==========================================
def limpar_tela():
    os.system("cls" if os.name == "nt" else "clear")

def mostrar_progresso(iteracao: int, total: int, prefixo: str = '', sufixo: str = '', tamanho: int = 50):
    preenchido = int(tamanho * iteracao // total)
    barra = '█' * preenchido + '-' * (tamanho - preenchido)
    porcentagem = (iteracao / total) * 100
    print(f'\r{Cores.CIANO}{prefixo} |{barra}| {porcentagem:.1f}% {sufixo}{Cores.RESET}', end='', flush=True)
    if iteracao == total:
        print()

def normalizar_texto_console(texto):
    """Corrige casos comuns de mojibake e remove artefatos HTML da saída."""
    if texto is None:
        return ""

    texto = str(texto).replace("&#x20;", " ")
    # Quando bytes UTF-8 foram interpretados como cp1252/cp850, tenta recuperar.
    candidatos = [texto]
    for origem in ("latin1", "cp1252"):
        try:
            candidato = texto.encode(origem).decode("utf-8")
            candidatos.append(candidato)
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

    # Alguns comandos nativos antigos retornam OEM/ANSI e podem chegar ao
    # programa já com a tabela errada. Tenta uma conversão reversível apenas
    # se ela melhorar claramente os caracteres portugueses.
    for origem, destino in (("cp1252", "cp850"), ("cp850", "cp1252")):
        try:
            candidato = texto.encode(origem).decode(destino)
            if candidato != texto:
                candidatos.append(candidato)
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

    def qualidade(valor):
        ruim = (
            valor.count("�") * 20 +
            valor.count("Ã") * 5 +
            valor.count("Â") * 4 +
            valor.count("├") * 5 +
            valor.count("┬") * 5 +
            valor.count("Ý") * 8 +
            valor.count("þ") * 8 +
            valor.count("Ò") * 6 +
            valor.count("ß") * 6
        )
        bom = sum(valor.count(ch) for ch in "áàãâéêíóôõúçÁÀÃÂÉÊÍÓÔÕÚÇ")
        return ruim - bom

    return min(candidatos, key=qualidade)


def decodificar_saida_windows(dados) -> str:
    """Decodifica saída de utilitários nativos sem presumir UTF-8.

    ``schtasks`` costuma usar a página OEM do Windows PT-BR, enquanto outros
    ambientes devolvem ANSI ou UTF-8. A seleção por qualidade evita mojibake e
    mantém a função independente de uma janela de console.
    """
    if dados is None:
        return ""
    if isinstance(dados, str):
        return normalizar_texto_console(dados)
    candidatos = []
    for codec in ("utf-8", "cp850", "cp1252", "cp437", "latin-1"):
        try:
            texto = dados.decode(codec)
        except (UnicodeDecodeError, LookupError):
            continue
        penalidade = (
            texto.count("�") * 20
            + texto.count("Ã") * 5
            + texto.count("Â") * 4
            + texto.count("├") * 5
        )
        bonus = sum(
            texto.count(ch)
            for ch in "áàãâéêíóôõúçÁÀÃÂÉÊÍÓÔÕÚÇ"
        )
        candidatos.append((penalidade - bonus, texto))
    if candidatos:
        candidatos.sort(key=lambda item: item[0])
        return normalizar_texto_console(candidatos[0][1])
    return str(dados)


def _alvo_modo_agendado(modo: str):
    """Monta o /TR para fonte ou EXE congelado com quoting do Windows."""
    if modo not in MODOS_AGENDADOS_AUTORIZADOS:
        raise ValueError("Modo agendado não autorizado.")
    if getattr(sys, "frozen", False):
        executavel = str(Path(sys.executable).resolve())
        argumentos = [executavel, modo]
        destino = executavel
        argumentos_log = [modo]
    else:
        script = str(Path(sys.argv[0]).resolve())
        executavel = str(Path(sys.executable).resolve())
        argumentos = [executavel, script, modo]
        destino = executavel
        argumentos_log = [script, modo]
    return subprocess.list2cmdline(argumentos), destino, argumentos_log


def _executar_schtasks(argumentos, timeout: int = 30):
    """Executa schtasks sem shell e devolve código e mensagem normalizada."""
    try:
        resultado = subprocess.run(
            ["schtasks.exe", *list(argumentos)],
            capture_output=True,
            text=False,
            timeout=timeout,
        )
        mensagem = decodificar_saida_windows(
            resultado.stdout or resultado.stderr
        ).strip()
        return resultado.returncode, mensagem
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, str(exc)


def barra_progresso(percentual, largura=34):
    """Retorna uma barra visual simples para o terminal."""
    try:
        percentual = max(0, min(100, int(float(percentual))))
    except (TypeError, ValueError):
        percentual = 0
    preenchido = int(largura * percentual / 100)
    return "[" + "█" * preenchido + "░" * (largura - preenchido) + f"] {percentual:3d}%"


def imprimir_progresso_linha(linha, prefixo=""):
    """Converte linhas de progresso do Windows em uma única barra visual."""
    texto = normalizar_texto_console(linha).strip()
    match = re.search(r"(\d{1,3})\s*%\s*conclu", texto, flags=re.IGNORECASE)
    if not match:
        return False

    percentual = int(match.group(1))
    print(
        f"\r{Cores.CIANO}{prefixo}{barra_progresso(percentual)}{Cores.RESET}",
        end="",
        flush=True,
    )
    return True


def executar_com_indicador(funcao, mensagem: str):
    """Executa uma tarefa demorada mostrando um indicador animado."""
    resultado = {"valor": None, "erro": None}
    concluido = threading.Event()

    def worker():
        try:
            resultado["valor"] = funcao()
        except Exception as exc:
            resultado["erro"] = exc
        finally:
            concluido.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    frames = ["|", "/", "-", "\\"]
    inicio = time.time()
    i = 0

    while not concluido.is_set():
        decorrido = int(time.time() - inicio)
        print(
            f"\r{Cores.CIANO}{frames[i % len(frames)]} {mensagem} "
            f"• Tempo decorrido: {decorrido}s{Cores.RESET}",
            end="",
            flush=True,
        )
        i += 1
        time.sleep(0.15)

    thread.join()
    print("\r" + " " * 100 + "\r", end="", flush=True)

    if resultado["erro"] is not None:
        raise resultado["erro"]
    return resultado["valor"]


def _job_windows_kill_on_close(processo):
    """Mantém a árvore do PowerShell ligada ao helper elevado no Windows."""
    if os.name != "nt" or processo is None or not hasattr(processo, "_handle"):
        return None
    try:
        from ctypes import wintypes

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        criar = kernel32.CreateJobObjectW
        criar.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        criar.restype = wintypes.HANDLE
        definir = kernel32.SetInformationJobObject
        definir.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        definir.restype = wintypes.BOOL
        atribuir = kernel32.AssignProcessToJobObject
        atribuir.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        atribuir.restype = wintypes.BOOL
        fechar = kernel32.CloseHandle
        fechar.argtypes = [wintypes.HANDLE]

        job = criar(None, None)
        if not job:
            return None
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
        if not definir(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            fechar(job)
            return None
        if not atribuir(job, wintypes.HANDLE(int(processo._handle))):
            fechar(job)
            return None
        return job
    except Exception:
        return None


def _fechar_job_windows(job, encerrar=False, codigo=1):
    if not job or os.name != "nt":
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if encerrar:
            kernel32.TerminateJobObject(job, int(codigo))
        kernel32.CloseHandle(job)
    except Exception:
        pass


def _encerrar_processo_controlado(processo, job=None, codigo=1):
    """Finaliza a árvore vinculada; fallback nunca usa shell de comando."""
    if processo is None:
        return
    if processo.poll() is not None:
        _fechar_job_windows(job)
        return
    if job:
        _fechar_job_windows(job, encerrar=True, codigo=codigo)
        job = None
    else:
        try:
            processo.terminate()
        except Exception:
            pass
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill.exe", "/PID", str(processo.pid), "/T", "/F"],
                    capture_output=True, timeout=10, shell=False,
                )
            except Exception:
                pass
    try:
        processo.wait(timeout=10)
    except Exception:
        try:
            processo.kill()
        except Exception:
            pass


def executar_windows_update_com_progresso(
    script: str, progress_callback=None, cancel_callback=None,
    timeout_segundos: int = WINDOWS_UPDATE_TIMEOUT_SEGUNDOS,
    stall_segundos: int = WINDOWS_UPDATE_STALL_SEGUNDOS,
) -> Tuple[bool, str]:
    """Executa o fluxo existente com leitura não bloqueante e limites claros.

    Um leitor dedicado drena stdout+stderr. O laço de controle continua capaz
    de observar cancelamento, timeout global e ausência prolongada de saída.
    Sucesso exige código zero e marcador ``RESULTADO|`` emitido pelo script.
    """
    args = [
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
        script,
    ]
    processo = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, shell=False,
        creationflags=(
            getattr(subprocess, "CREATE_NO_WINDOW", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        ),
    )
    job = _job_windows_kill_on_close(processo)
    percentual = 0
    mensagem = "Iniciando Windows Update"
    inicio = time.monotonic()
    ultima_saida = inicio
    resultado_final = "Operação concluída."
    linhas_stderr: List[str] = []
    marcador_resultado = False
    fila = queue.Queue()

    def decodificar(dados):
        for codec in ("utf-8", "cp850", "cp1252", "latin-1"):
            try:
                return dados.decode(codec)
            except UnicodeDecodeError:
                pass
        return dados.decode("utf-8", errors="replace")

    def leitor():
        try:
            if processo.stdout is not None:
                for linha in iter(processo.stdout.readline, b""):
                    fila.put(linha)
        finally:
            fila.put(None)

    thread_leitor = threading.Thread(
        target=leitor, name="Configurador TI-WindowsUpdate-stdout", daemon=True
    )
    thread_leitor.start()
    leitor_concluido = False

    try:
        while True:
            try:
                cancelada = bool(
                    callable(cancel_callback) and cancel_callback()
                )
            except Exception:
                cancelada = False
            if cancelada:
                _encerrar_processo_controlado(processo, job, codigo=125)
                job = None
                registrar_log(
                    "SISTEMA", "WINDOWS_UPDATE_CANCELADO", "etapa=execucao"
                )
                return False, "Windows Update cancelado com segurança."

            agora = time.monotonic()
            if agora - inicio >= max(60, int(timeout_segundos)):
                _encerrar_processo_controlado(processo, job, codigo=124)
                job = None
                registrar_log(
                    "SISTEMA", "WINDOWS_UPDATE_TIMEOUT",
                    f"etapa=global;limite_s={int(timeout_segundos)}",
                )
                return False, "Windows Update excedeu o limite global de execução."
            if agora - ultima_saida >= max(30, int(stall_segundos)):
                _encerrar_processo_controlado(processo, job, codigo=123)
                job = None
                registrar_log(
                    "SISTEMA", "WINDOWS_UPDATE_TIMEOUT",
                    f"etapa=sem_saida;limite_s={int(stall_segundos)}",
                )
                return False, "Windows Update ficou sem progresso observável além do limite seguro."

            try:
                linha = fila.get(timeout=0.2)
            except queue.Empty:
                if processo.poll() is not None and leitor_concluido:
                    break
                continue
            if linha is None:
                leitor_concluido = True
                if processo.poll() is not None:
                    break
                continue
            if linha:
                ultima_saida = time.monotonic()
            texto = normalizar_texto_console(decodificar(linha).strip())
            if texto.startswith("PROGRESSO|"):
                partes = texto.split("|", 2)
                try:
                    percentual = int(partes[1])
                except (ValueError, IndexError):
                    pass
                mensagem = partes[2] if len(partes) > 2 else mensagem
                if callable(progress_callback):
                    try:
                        progress_callback(percentual, mensagem)
                    except Exception:
                        pass
            elif texto.startswith("RESULTADO|"):
                resultado_final = texto.split("|", 1)[1].strip()
                marcador_resultado = True
            elif texto.startswith("ERRO_WU|"):
                linhas_stderr.append(texto.split("|", 1)[1].strip())
            elif texto:
                # Qualquer outra linha (agora que stderr também vem por aqui)
                # é guardada para explicar uma eventual falha no final.
                linhas_stderr.append(texto)
        try:
            processo.wait(timeout=15)
        except subprocess.TimeoutExpired:
            _encerrar_processo_controlado(processo, job, codigo=122)
            job = None
            return False, "Windows Update não encerrou o processo auxiliar corretamente."
    finally:
        if processo.stdout is not None:
            try:
                processo.stdout.close()
            except Exception:
                pass
        thread_leitor.join(timeout=3)
        _fechar_job_windows(job)

    if processo.returncode == 0 and marcador_resultado:
        registrar_log("SISTEMA", "WINDOWS_UPDATE", resultado_final)
        return True, resultado_final
    if processo.returncode == 0 and not marcador_resultado:
        linhas_stderr.append("O processo terminou sem o marcador de resultado esperado.")
    erro = "\n".join(linhas_stderr[-15:]) or resultado_final
    return False, erro


def confirmar_acao(mensagem: str, padrao: bool = False) -> bool:
    opcoes = " [S/n]: " if padrao else " [s/N]: "
    resposta = input(f"{mensagem}{opcoes}").strip().lower()
    if resposta == '':
        return padrao
    return resposta in ['s', 'sim', 'yes', 'y']

def sanitizar_texto(texto: str) -> str:
    if not texto:
        return ""
    limpo = "".join(c for c in texto if ord(c) >= 32 and ord(c) < 127)
    return limpo.replace("'", "").replace('"', '').replace(";", "").replace("`", "").strip()

def sanitizar_comando_ps(comando: str) -> str:
    """Escapa caracteres perigosos em comandos PowerShell."""
    caracteres_perigosos = [';', '&', '|', '>', '<', '`']
    for char in caracteres_perigosos:
        comando = comando.replace(char, f"`{char}")
    return comando

def validar_ip_estrito(ip: str) -> Tuple[bool, str]:
    if not ip or not isinstance(ip, str):
        return False, "IP vazio ou inválido."
    
    if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
        return False, "Formato IP inválido."
    
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return False, "Endereço IP é loopback (127.x.x.x)."
        if addr.is_multicast:
            return False, "Endereço IP é multicast."
        if addr.is_reserved:
            return False, "Endereço IP reservado."
        if addr.is_private:
            return True, "OK (IP privado)"
        return True, "OK"
    except ValueError:
        return False, "IP inválido."

def testar_servidor_dns(ip_dns: str, timeout: int = 5) -> Tuple[bool, float]:
    """Faz uma consulta DNS UDP diretamente ao servidor informado."""
    try:
        endereco = ipaddress.ip_address(ip_dns)
        if endereco.version != 4:
            return False, -1

        # Consulta A para example.com, montada manualmente para garantir que
        # a requisição seja enviada exatamente ao IP de DNS escolhido.
        transaction_id = random.randint(0, 0xFFFF)
        flags = 0x0100  # recursion desired
        header = struct.pack('!HHHHHH', transaction_id, flags, 1, 0, 0, 0)
        qname = b''.join(len(parte).to_bytes(1, 'big') + parte.encode('ascii')
                         for parte in 'example.com'.split('.')) + b'\x00'
        question = qname + struct.pack('!HH', 1, 1)  # A / IN
        pacote = header + question

        inicio = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(pacote, (str(endereco), 53))
            resposta, _ = sock.recvfrom(4096)
        latencia = (time.perf_counter() - inicio) * 1000

        if len(resposta) < 12:
            return False, -1
        resposta_id, resposta_flags, _, _, _, _ = struct.unpack('!HHHHHH', resposta[:12])
        rcode = resposta_flags & 0x000F
        if resposta_id != transaction_id or rcode != 0:
            return False, -1
        return True, latencia
    except (OSError, ValueError, socket.timeout):
        return False, -1

def verificar_rate_limit(segundos: float = 1.0) -> None:
    global _ultima_operacao
    agora = time.time()
    if agora - _ultima_operacao < segundos:
        raise RuntimeError(f"Aguarde {segundos}s entre operações de rede.")
    _ultima_operacao = agora

def executar_powershell(comando: str, timeout: int = 30, usar_cache: bool = False) -> subprocess.CompletedProcess:
    """Executa um comando no PowerShell e retorna stdout, stderr e returncode."""
    if not isinstance(comando, str) or not comando.strip():
        raise ValueError("Comando PowerShell inválido.")
    if "\x00" in comando:
        raise ValueError("Comando contém caractere nulo.")

    chave_cache = hashlib.md5(comando.encode("utf-8")).hexdigest()
    if usar_cache and chave_cache in _cache_ps:
        return _cache_ps[chave_cache]

    args = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
        "$ErrorActionPreference='Stop'; "
        + comando
    ]

    try:
        resultado_bruto = subprocess.run(
            args,
            capture_output=True,
            text=False,
            timeout=timeout
        )

        def _decodificar_saida(dados):
            """Decodifica saídas do Windows sem trocar acentos por mojibake."""
            if not dados:
                return ""

            # UTF-8 válido tem prioridade.
            try:
                return dados.decode("utf-8")
            except UnicodeDecodeError:
                pass

            candidatos = []
            for codec in ("cp1252", "cp850", "cp437", "latin-1"):
                try:
                    valor = dados.decode(codec)
                except UnicodeDecodeError:
                    continue

                # Penaliza caracteres de controle e padrões comuns de mojibake.
                penalidade = sum(ord(ch) < 32 and ch not in "\\r\\n\\t" for ch in valor)
                penalidade += valor.count("Ã") * 4
                penalidade += valor.count("Â") * 3
                penalidade += valor.count("├") * 5
                penalidade += valor.count("�") * 10

                # Português comum ajuda a desempatar cp1252/cp850.
                bonus = sum(valor.count(ch) for ch in "áàãâéêíóôõúçÁÀÃÂÉÊÍÓÔÕÚÇ")
                candidatos.append((penalidade - bonus, valor))

            if candidatos:
                candidatos.sort(key=lambda item: item[0])
                return candidatos[0][1]

            return dados.decode("utf-8", errors="replace")

        resultado = subprocess.CompletedProcess(
            resultado_bruto.args,
            resultado_bruto.returncode,
            _decodificar_saida(resultado_bruto.stdout),
            _decodificar_saida(resultado_bruto.stderr),
        )
    except FileNotFoundError as e:
        raise RuntimeError("PowerShell não foi encontrado neste computador.") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"O comando demorou mais de {timeout} segundos para terminar."
        ) from e

    if usar_cache and resultado.returncode == 0:
        _cache_ps[chave_cache] = resultado

    return resultado

def registrar_log(categoria: str, acao: str, detalhes: str):
    """Registra no log e no histórico confiável da execução atual."""
    registro = {
        "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "categoria": str(categoria),
        "acao": str(acao),
        "detalhes": str(detalhes),
    }
    _historico_operacoes_sessao.append(registro)
    logger.info(
        f"[{registro['categoria']}] {registro['acao']} | "
        f"Detalhes: {registro['detalhes']}"
    )

def escapar_ps_string(valor: str) -> str:
    """Escapa uma string para uso literal entre aspas simples no PowerShell."""
    return str(valor).replace("'", "''")

# ==========================================
# GERENCIADOR DE BACKUP
# ==========================================
class GerenciadorBackup:
    def __init__(self, pasta_backup: str = PASTA_BACKUP):
        self.pasta_backup = Path(pasta_backup)
        try:
            self.pasta_backup.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as exc:
            alternativa = Path(tempfile.gettempdir()) / "ConfiguradorTI" / "backups_dns"
            try:
                alternativa.mkdir(parents=True, exist_ok=True)
                self.pasta_backup = alternativa
                logger.warning(
                    "Pasta portátil de backups indisponível (%s). Usando: %s",
                    exc, alternativa,
                )
            except (OSError, PermissionError) as fallback_exc:
                # Não impede o backend/GUI de iniciar. criar_backup() já trata
                # falhas posteriores e retorna None sem remover a operação DNS.
                logger.warning(
                    "Não foi possível preparar pasta de backups (%s | %s).",
                    exc, fallback_exc,
                )
    
    def criar_backup(self, interface: str) -> Optional[str]:
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            arquivo_backup = self.pasta_backup / f"{sanitizar_texto(interface)}_{timestamp}.json"
            
            # Obter config atual de DNS
            cmd = f"Get-DnsClientServerAddress -InterfaceAlias \'{escapar_ps_string(interface)}\' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses | ConvertTo-Json"
            res = executar_powershell(cmd)
            
            dns_atual = []
            if res.returncode == 0 and res.stdout.strip():
                try:
                    dns_atual = json.loads(res.stdout.strip())
                    if isinstance(dns_atual, str):
                        dns_atual = [dns_atual]
                except json.JSONDecodeError:
                    pass
            
            backup_data = {
                'interface': interface,
                'timestamp': timestamp,
                'data_hora': datetime.now().isoformat(),
                'dns': dns_atual,
                'sistema': ModuloSistema.obter_informacoes_sistema()
            }
            
            with open(arquivo_backup, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            return str(arquivo_backup)
        except Exception as e:
            logger.error(f"Erro ao criar backup: {e}")
            return None
    
    def listar_backups(self, interface: Optional[str] = None) -> List[Path]:
        try:
            backups = list(self.pasta_backup.glob("*.json"))
            if interface:
                backups = [b for b in backups if interface in b.name]
            return sorted(backups, key=lambda x: x.stat().st_mtime, reverse=True)
        except Exception:
            return []
    
    def restaurar_backup(self, arquivo_backup: Union[str, Path]) -> bool:
        try:
            with open(arquivo_backup, 'r', encoding='utf-8') as f:
                dados = json.load(f)
            
            interface = dados.get('interface')
            dns = dados.get('dns', [])
            
            if interface and dns:
                return ModuloRede.aplicar_dns(interface, dns, backup_anterior=False)
            return False
        except Exception as e:
            logger.error(f"Erro ao restaurar backup: {e}")
            return False

# ==========================================
# GERENCIADOR DE PERFIS
# ==========================================
class GerenciadorPerfis:
    def __init__(self, arquivo: str = ARQUIVO_PERFIS):
        self.arquivo = arquivo
        self.perfis: Dict[str, PerfilDNS] = {}
        self.carregar()
    
    def carregar(self):
        if not os.path.exists(self.arquivo):
            self.perfis = {
                "Cloudflare": PerfilDNS("Cloudflare", ["1.1.1.1", "1.0.0.1"], "DNS rápido e privado da Cloudflare"),
                "Google": PerfilDNS("Google", ["8.8.8.8", "8.8.4.4"], "DNS público do Google"),
                "OpenDNS": PerfilDNS("OpenDNS", ["208.67.222.222", "208.67.220.220"], "DNS com filtro de segurança")
            }
            self.salvar()
            return
        
        try:
            with open(self.arquivo, 'r', encoding='utf-8') as f:
                dados = json.load(f)
                self.perfis = {k: PerfilDNS.from_dict(v) if isinstance(v, dict) else PerfilDNS(k, v) 
                              for k, v in dados.items()}
        except Exception as e:
            logger.error(f"Erro ao carregar perfis: {e}")
            self.perfis = {}
    
    def salvar(self):
        try:
            with open(self.arquivo, 'w', encoding='utf-8') as f:
                json.dump({k: v.to_dict() for k, v in self.perfis.items()}, 
                         f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Erro ao salvar perfis: {e}")
    
    def adicionar(self, perfil: PerfilDNS) -> bool:
        self.perfis[perfil.nome] = perfil
        self.salvar()
        return True
    
    def remover(self, nome: str) -> bool:
        if nome in self.perfis:
            del self.perfis[nome]
            self.salvar()
            return True
        return False
    
    def obter(self, nome: str) -> Optional[PerfilDNS]:
        return self.perfis.get(nome)
    
    def listar(self) -> List[PerfilDNS]:
        return list(self.perfis.values())

gerenciador_perfis = GerenciadorPerfis()


def _volume_suporta_acl_persistente(caminho) -> Optional[bool]:
    """Informa se o volume Windows mantém ACLs; ``None`` significa indeterminado.

    FAT32/exFAT não devem transformar uma publicação válida em falha apenas por
    não oferecerem ACLs persistentes. Fora do Windows a correção é um no-op.
    """
    if os.name != "nt":
        return False
    try:
        caminho_absoluto = os.path.abspath(str(caminho))
        raiz_volume = ctypes.create_unicode_buffer(261)
        if not ctypes.windll.kernel32.GetVolumePathNameW(
            ctypes.c_wchar_p(caminho_absoluto), raiz_volume, len(raiz_volume)
        ):
            return None
        flags = ctypes.c_uint(0)
        if not ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(raiz_volume.value), None, 0, None, None,
            ctypes.byref(flags), None, 0,
        ):
            return None
        return bool(flags.value & 0x00000008)  # FILE_PERSISTENT_ACLS
    except Exception:
        return None


def _identidade_usuario_publicacao_windows() -> str:
    """Retorna o SID do usuário da execução, inclusive sob token elevado."""
    dominio = os.environ.get("USERDOMAIN", "").strip()
    usuario = os.environ.get("USERNAME", "").strip()
    identidade = f"{dominio}\\{usuario}" if dominio and usuario else usuario
    try:
        consulta = subprocess.run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=False, timeout=10, shell=False,
        )
        texto = decodificar_saida_windows(consulta.stdout or consulta.stderr)
        encontrado = re.search(r"S-1-5-(?:\d+-)+\d+", texto)
        if consulta.returncode == 0 and encontrado:
            return "*" + encontrado.group(0)
    except Exception:
        pass
    if identidade:
        return identidade
    raise PermissionError("Não foi possível identificar o usuário para publicar o artefato.")


def _ajustar_acl_publicacao_atomica(caminho) -> None:
    """Prepara a ACL do temporário antes do ``os.replace`` no Windows.

    O reset restaura a herança segura da pasta irmã e as concessões explícitas
    garantem acesso ao mesmo usuário em processo normal e aos Administradores.
    Nenhuma permissão é concedida a Everyone. Em volumes sem ACL persistente,
    como FAT32/exFAT, a etapa é ignorada deliberadamente.
    """
    if os.name != "nt":
        return
    suporte_acl = _volume_suporta_acl_persistente(caminho)
    if suporte_acl is False:
        return

    identidade = _identidade_usuario_publicacao_windows()
    comandos = (
        ["icacls.exe", str(caminho), "/reset", "/q"],
        [
            "icacls.exe", str(caminho), "/inheritance:e",
            "/grant:r", f"{identidade}:M",
            "/grant:r", "*S-1-5-32-544:F", "/q",
        ],
        ["icacls.exe", str(caminho)],
    )
    for comando in comandos:
        try:
            resultado = subprocess.run(
                comando, capture_output=True, text=False, timeout=15, shell=False,
            )
        except Exception as exc:
            raise PermissionError(
                "Não foi possível preparar a ACL segura do artefato publicado."
            ) from exc
        if resultado.returncode != 0:
            detalhe = decodificar_saida_windows(
                resultado.stderr or resultado.stdout
            ).strip()
            raise PermissionError(
                "Não foi possível preparar a ACL segura do artefato publicado"
                + (f": {detalhe}" if detalhe else ".")
            )


def _validar_leitura_artefato(caminho, *, exigir_conteudo: bool = False) -> Path:
    """Confirma que o artefato final existe e pode ser lido localmente."""
    arquivo = Path(caminho)
    if not arquivo.is_file():
        raise OSError(f"Artefato publicado não encontrado: {arquivo}")
    with arquivo.open("rb") as fluxo:
        primeiro_byte = fluxo.read(1)
    if exigir_conteudo and not primeiro_byte:
        raise OSError(f"Artefato publicado está vazio: {arquivo}")
    return arquivo


def _gravar_arquivo_atomico(
    destino, conteudo, *, binario: bool = False, tentativas: int = 3
) -> Path:
    """Grava em arquivo temporário irmão e substitui sem perder o anterior.

    O temporário permanece na mesma pasta para que ``os.replace`` continue
    atômico no Windows. PermissionError transitório (antivírus/indexador ou
    leitor que abriu o arquivo sem compartilhamento de exclusão) recebe apenas
    três tentativas curtas; qualquer outra falha é propagada e o arquivo
    anterior permanece intacto.
    """
    caminho = Path(destino)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    descritor, nome_temporario = tempfile.mkstemp(
        prefix=f".{caminho.name}.", suffix=".tmp", dir=str(caminho.parent)
    )
    temporario = Path(nome_temporario)
    try:
        modo = "wb" if binario else "w"
        kwargs = {} if binario else {"encoding": "utf-8", "newline": ""}
        with os.fdopen(descritor, modo, **kwargs) as arquivo:
            arquivo.write(conteudo)
            arquivo.flush()
            os.fsync(arquivo.fileno())
        descritor = -1
        _ajustar_acl_publicacao_atomica(temporario)
        _validar_leitura_artefato(temporario)

        ultimo_erro = None
        substituido = False
        for tentativa in range(max(1, min(int(tentativas), 3))):
            try:
                os.replace(str(temporario), str(caminho))
            except PermissionError as exc:
                ultimo_erro = exc
                if tentativa + 1 >= max(1, min(int(tentativas), 3)):
                    raise
                time.sleep(0.08 * (tentativa + 1))
            else:
                temporario = None
                substituido = True
                break
        if substituido:
            return _validar_leitura_artefato(caminho)
        if ultimo_erro is not None:
            raise ultimo_erro
        raise OSError("A substituição atômica não foi concluída.")
    finally:
        if descritor >= 0:
            try:
                os.close(descritor)
            except OSError:
                pass
        if temporario is not None:
            try:
                temporario.unlink(missing_ok=True)
            except OSError:
                pass


def _salvar_inventario_empresa(dados) -> Path:
    """Serializa o inventário sob lock e preserva o JSON anterior em falha."""
    conteudo = json.dumps(dados, ensure_ascii=False, indent=2)
    with _lock_inventario_empresa:
        return _gravar_arquivo_atomico(ARQUIVO_INVENTARIO, conteudo)


def _raiz_temporaria_saude_armazenamento_elevada() -> Path:
    return (
        Path(tempfile.gettempdir())
        / "ConfiguradorTI"
        / "saude_armazenamento"
    )


def _validar_destino_saude_armazenamento_elevada(caminho) -> Path:
    """Aceita somente o arquivo imprevisível criado no escopo temporário R2."""
    candidato = Path(str(caminho))
    if not candidato.is_absolute():
        raise ValueError("Destino temporário deve ser absoluto.")
    if candidato.suffix.casefold() != ".json" or not candidato.name.startswith(
        "resultado_"
    ):
        raise ValueError("Nome de destino temporário inválido.")
    if not candidato.parent.name.startswith("coleta_"):
        raise ValueError("Pasta temporária de coleta inválida.")

    raiz = _raiz_temporaria_saude_armazenamento_elevada().resolve(strict=True)
    if candidato.is_symlink() or candidato.parent.is_symlink():
        raise ValueError("Links não são aceitos no destino temporário.")
    resolvido = candidato.resolve(strict=True)
    if resolvido.parent.parent != raiz:
        raise ValueError("Destino temporário fora do escopo autorizado.")
    if not resolvido.is_file():
        raise ValueError("Destino temporário não é um arquivo regular.")
    return resolvido


def _estrutura_json_controlada(valor, profundidade: int = 0) -> bool:
    """Limita profundidade e volume antes de entregar JSON à GUI normal."""
    if profundidade > 10:
        return False
    if valor is None or isinstance(valor, (bool, int, float)):
        return True
    if isinstance(valor, str):
        return len(valor) <= 16384
    if isinstance(valor, list):
        return len(valor) <= 512 and all(
            _estrutura_json_controlada(item, profundidade + 1) for item in valor
        )
    if isinstance(valor, dict):
        return len(valor) <= 256 and all(
            isinstance(chave, str)
            and len(chave) <= 128
            and _estrutura_json_controlada(item, profundidade + 1)
            for chave, item in valor.items()
        )
    return False


def _validar_envelope_saude_armazenamento_elevada(
    envelope, nonce: str
) -> Dict[str, Any]:
    if not isinstance(envelope, dict) or envelope.get("Schema") != 1:
        raise ValueError("Envelope elevado inválido.")
    nonce_recebido = envelope.get("Nonce")
    if not isinstance(nonce_recebido, str) or not secrets.compare_digest(
        nonce_recebido, nonce
    ):
        raise ValueError("Nonce do resultado elevado não confere.")
    resultado = envelope.get("Resultado")
    if not isinstance(resultado, dict) or not _estrutura_json_controlada(resultado):
        raise ValueError("Resultado elevado possui estrutura inválida.")
    if not isinstance(resultado.get("Sucesso"), bool):
        raise ValueError("Resultado elevado não informa sucesso de forma válida.")
    discos = resultado.get("Discos")
    if not isinstance(discos, list) or len(discos) > 64:
        raise ValueError("Lista de discos elevada inválida.")
    if not all(isinstance(disco, dict) for disco in discos):
        raise ValueError("Item de disco elevado inválido.")
    return resultado


def _gravar_envelope_saude_armazenamento_elevada(
    destino, nonce: str, resultado: Dict[str, Any]
) -> None:
    caminho = _validar_destino_saude_armazenamento_elevada(destino)
    envelope = {"Schema": 1, "Nonce": nonce, "Resultado": resultado}
    if not _estrutura_json_controlada(envelope):
        raise ValueError("Resultado excede os limites do contrato elevado.")
    conteudo = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    dados = conteudo.encode("utf-8")
    if not dados or len(dados) > 4 * 1024 * 1024:
        raise ValueError("Resultado elevado excede o limite permitido.")
    with caminho.open("w", encoding="utf-8", newline="") as arquivo:
        arquivo.write(conteudo)
        arquivo.flush()
        os.fsync(arquivo.fileno())


def _raiz_temporaria_windows_update() -> Path:
    """Raiz persistente por usuário; nunca usa o diretório ``_MEIPASS``."""
    return Path(tempfile.gettempdir()) / "ConfiguradorTI" / "windows_update"


def _validar_destino_windows_update(caminho) -> Path:
    """Valida o arquivo precriado do contrato local de Windows Update."""
    candidato = Path(str(caminho))
    if not candidato.is_absolute():
        raise ValueError("Destino do Windows Update deve ser absoluto.")
    if candidato.suffix.casefold() != ".json" or not candidato.name.startswith(
        "resultado_"
    ):
        raise ValueError("Nome de resultado do Windows Update inválido.")
    if not candidato.parent.name.startswith("execucao_"):
        raise ValueError("Pasta de execução do Windows Update inválida.")
    raiz = _raiz_temporaria_windows_update().resolve(strict=True)
    if candidato.is_symlink() or candidato.parent.is_symlink():
        raise ValueError("Links não são aceitos no IPC do Windows Update.")
    resolvido = candidato.resolve(strict=True)
    if resolvido.parent.parent != raiz or not resolvido.is_file():
        raise ValueError("Destino do Windows Update fora do escopo autorizado.")
    return resolvido


def _envelope_windows_update(
    nonce: str, estado: str, percentual: int, mensagem: str, resultado=None
) -> Dict[str, Any]:
    envelope = {
        "Schema": 1,
        "Nonce": nonce,
        "Estado": str(estado),
        "Percentual": max(0, min(100, int(percentual))),
        "Mensagem": str(mensagem or "")[:1000],
        "AtualizadoEm": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    if resultado is not None:
        envelope["Resultado"] = resultado
    return envelope


def _gravar_estado_windows_update(
    destino, nonce: str, estado: str, percentual: int, mensagem: str,
    resultado=None,
) -> None:
    """Atualiza o arquivo existente in-place, preservando proprietário/DACL.

    Não usa ``os.replace`` neste IPC entre integridades: substituir o inode no
    processo elevado recriaria proprietário/ACL e reproduziria o WinError 5 da
    branch histórica. Leituras concorrentes toleram JSON parcial e aguardam a
    próxima atualização completa autenticada pelo nonce.
    """
    caminho = _validar_destino_windows_update(destino)
    envelope = _envelope_windows_update(
        nonce, estado, percentual, mensagem, resultado
    )
    if not _estrutura_json_controlada(envelope):
        raise ValueError("Estado do Windows Update excede o contrato local.")
    conteudo = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    if len(conteudo.encode("utf-8")) > 256 * 1024:
        raise ValueError("Estado do Windows Update excede o limite permitido.")
    with caminho.open("r+", encoding="utf-8", newline="") as arquivo:
        arquivo.seek(0)
        arquivo.write(conteudo)
        arquivo.truncate()
        arquivo.flush()
        os.fsync(arquivo.fileno())


def _ler_estado_windows_update(destino, nonce: str, exigir_final=False):
    """Lê somente envelopes completos e autenticados; parcial retorna None."""
    try:
        caminho = _validar_destino_windows_update(destino)
        tamanho = caminho.stat().st_size
        if tamanho <= 0 or tamanho > 256 * 1024:
            return None
        envelope = json.loads(caminho.read_text(encoding="utf-8"))
        if not isinstance(envelope, dict) or envelope.get("Schema") != 1:
            return None
        recebido = envelope.get("Nonce")
        if not isinstance(recebido, str) or not secrets.compare_digest(
            recebido, nonce
        ):
            return None
        if envelope.get("Estado") not in {"PREPARING", "RUNNING", "COMPLETED"}:
            return None
        percentual = envelope.get("Percentual")
        if not isinstance(percentual, int) or not 0 <= percentual <= 100:
            return None
        if exigir_final:
            resultado = envelope.get("Resultado")
            if envelope.get("Estado") != "COMPLETED" or not isinstance(
                resultado, dict
            ) or not isinstance(resultado.get("Sucesso"), bool):
                return None
        return envelope
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _executar_windows_update_elevado_isolado(
    progress_callback=None, cancel_callback=None
) -> Tuple[bool, str]:
    """Eleva somente o helper allowlisted e mantém a GUI normal aberta."""
    pasta_execucao = None
    caminho_resultado = None
    ultimo_estado = {"chave": None}
    try:
        raiz = _raiz_temporaria_windows_update()
        raiz.mkdir(parents=True, exist_ok=True)
        restringir_acl_arquivo(str(raiz))
        pasta_execucao = Path(
            tempfile.mkdtemp(prefix="execucao_", dir=str(raiz))
        )
        restringir_acl_arquivo(str(pasta_execucao))
        descritor, nome_resultado = tempfile.mkstemp(
            prefix="resultado_", suffix=".json", dir=str(pasta_execucao)
        )
        os.close(descritor)
        caminho_resultado = Path(nome_resultado)
        restringir_acl_arquivo(str(caminho_resultado))
        _validar_destino_windows_update(caminho_resultado)

        nonce = secrets.token_urlsafe(32)
        _gravar_estado_windows_update(
            caminho_resultado, nonce, "PREPARING", 1,
            "Aguardando autorização do Windows...",
        )
        argumentos_modo = [
            MODO_WINDOWS_UPDATE_ELEVADO,
            ARG_RESULTADO_WINDOWS_UPDATE,
            str(caminho_resultado),
            ARG_NONCE_WINDOWS_UPDATE,
            nonce,
        ]
        if getattr(sys, "frozen", False):
            executavel = str(Path(sys.executable).resolve())
            argumentos_processo = argumentos_modo
        else:
            executavel = _executavel_reinicio_gui()
            argumentos_processo = [str(Path(__file__).resolve()), *argumentos_modo]

        def atualizar_status():
            envelope = _ler_estado_windows_update(caminho_resultado, nonce)
            if not envelope:
                return
            chave = (
                envelope.get("Percentual"), envelope.get("Mensagem"),
                envelope.get("Estado"),
            )
            if chave == ultimo_estado["chave"]:
                return
            ultimo_estado["chave"] = chave
            if callable(progress_callback):
                progress_callback(int(chave[0]), str(chave[1]))

        registrar_log(
            "SISTEMA", "WINDOWS_UPDATE_HELPER_STAGE",
            "etapa=solicitar_uac;status=iniciado",
        )
        processo = executar_auxiliar_elevado_aguardando(
            executavel,
            argumentos_processo,
            str(DIRETORIO_BASE),
            timeout=WINDOWS_UPDATE_TIMEOUT_SEGUNDOS + 120,
            cancel_callback=cancel_callback,
            status_callback=atualizar_status,
        )
        status = str(processo.get("Status") or "erro")
        if status == "uac_cancelado":
            return False, "UAC cancelado; o Windows Update não foi iniciado."
        if status == "cancelado":
            return False, "Windows Update cancelado com segurança."
        if status == "timeout":
            return False, "O helper do Windows Update excedeu o limite global."
        if status != "ok":
            codigo = processo.get("Codigo")
            if int(codigo or 0) == 5:
                return False, (
                    "Acesso negado pelo Windows (WinError 5) ao iniciar o helper "
                    "elevado. Consulte o log e valide a política UAC."
                )
            return False, (
                "Não foi possível iniciar o helper elevado do Windows Update "
                f"({processo.get('Tipo') or status}; código={codigo or 'N/A'})."
            )

        atualizar_status()
        envelope = _ler_estado_windows_update(
            caminho_resultado, nonce, exigir_final=True
        )
        if envelope is None:
            return False, (
                "O helper elevado terminou sem um resultado autenticado válido."
            )
        resultado = dict(envelope["Resultado"])
        mensagem = str(
            resultado.get("Mensagem") or "Windows Update concluído sem detalhes."
        )
        if int(processo.get("CodigoSaida", -1)) != 0:
            return False, mensagem
        return bool(resultado.get("Sucesso")), mensagem
    except Exception as exc:
        logger.exception("Falha no helper isolado do Windows Update")
        return False, (
            "Não foi possível concluir o Windows Update isolado "
            f"({type(exc).__name__}). Consulte o log."
        )
    finally:
        falhas = []
        if caminho_resultado is not None:
            try:
                caminho_resultado.unlink(missing_ok=True)
            except OSError as exc:
                falhas.append(type(exc).__name__)
        if pasta_execucao is not None:
            try:
                pasta_execucao.rmdir()
            except OSError as exc:
                falhas.append(type(exc).__name__)
        if falhas:
            logger.warning(
                "WINDOWS_UPDATE_HELPER_STAGE etapa=cleanup status=parcial tipos=%s",
                ",".join(falhas),
            )

# ==========================================
# MÓDULO DE REDE COMPLETO
# ==========================================
class ModuloRede:
    _backup_manager = GerenciadorBackup()
    
    @staticmethod
    def listar_adaptadores_detalhados() -> List[AdaptadorRede]:
        """
        Lista os adaptadores usando uma única chamada PowerShell.
        Em caso de erro, mostra o motivo em vez de falhar silenciosamente.
        """
        cmd = r"""
$adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
    $_.Status -ne 'Disabled'
})

$result = foreach ($adapter in $adapters) {
    $ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1

    $gateway = Get-NetRoute -InterfaceIndex $adapter.ifIndex `
        -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 `
        -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric |
        Select-Object -First 1 -ExpandProperty NextHop

    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
        -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.ServerAddresses } |
        Where-Object { $_ })

    [PSCustomObject]@{
        Nome           = [string]$adapter.Name
        InterfaceAlias = [string]$adapter.InterfaceAlias
        Status         = [string]$adapter.Status
        MacAddress     = [string]$adapter.MacAddress
        LinkSpeed      = [string]$adapter.LinkSpeed
        IP             = if ($ip) { [string]$ip.IPAddress } else { $null }
        Gateway        = if ($gateway) { [string]$gateway } else { $null }
        DNS            = @($dns)
    }
}

@($result) | ConvertTo-Json -Depth 4 -Compress
"""
        try:
            res = executar_powershell(cmd, timeout=20)

            if res.returncode != 0:
                erro = res.stderr.strip() or res.stdout.strip() or "Erro desconhecido."
                logger.error(f"PowerShell falhou ao listar adaptadores: {erro}")
                print(f"{Cores.VERMELHO}❌ Erro ao obter adaptadores:{Cores.RESET} {erro}")
                return []

            saida = res.stdout.strip()
            if not saida:
                print(f"{Cores.AMARELO}⚠️ O Windows não retornou nenhum adaptador de rede.{Cores.RESET}")
                return []

            try:
                dados = json.loads(saida)
            except json.JSONDecodeError as e:
                logger.error(f"JSON inválido ao listar adaptadores: {saida!r}")
                print(f"{Cores.VERMELHO}❌ Não foi possível interpretar a resposta do Windows.{Cores.RESET}")
                print(f"{Cores.CINZA}{saida[:500]}{Cores.RESET}")
                return []

            if isinstance(dados, dict):
                dados = [dados]
            if not isinstance(dados, list):
                print(f"{Cores.VERMELHO}❌ Formato inesperado ao obter adaptadores.{Cores.RESET}")
                return []

            adaptadores = []
            for item in dados:
                if not isinstance(item, dict):
                    continue
                dns = item.get("DNS") or []
                if isinstance(dns, str):
                    dns = [dns]

                nome = str(item.get("Nome") or item.get("InterfaceAlias") or "").strip()
                alias = str(item.get("InterfaceAlias") or nome).strip()
                if not nome:
                    continue

                adaptadores.append(AdaptadorRede(
                    nome=nome,
                    interface_alias=alias,
                    status=str(item.get("Status") or "N/A"),
                    ip=item.get("IP"),
                    mac=item.get("MacAddress"),
                    link_speed=item.get("LinkSpeed"),
                    gateway=item.get("Gateway"),
                    dns=dns
                ))

            if not adaptadores:
                print(f"{Cores.AMARELO}⚠️ Nenhum adaptador ativo foi encontrado.{Cores.RESET}")

            return adaptadores

        except Exception as e:
            logger.exception("Erro ao listar adaptadores")
            print(f"{Cores.VERMELHO}❌ Erro ao listar adaptadores: {e}{Cores.RESET}")
            return []

    @staticmethod
    def obter_detalhes_rede(interface_preferida: Optional[str] = None,
                             cancel_callback=None) -> Dict[str, Any]:
        """Consulta somente leitura para o painel integrado de Rede & DNS."""
        def cancelado():
            try:
                return bool(cancel_callback and cancel_callback())
            except Exception:
                return False

        def falha(mensagem, erro=""):
            return {"Sucesso": False, "Cancelada": False, "Mensagem": mensagem,
                    "Erro": erro or mensagem, "SelecionadaPorUsuario": bool(interface_preferida),
                    "Interface": {}}

        if cancelado():
            return {"Sucesso": False, "Cancelada": True,
                    "Mensagem": "Atualização das informações de rede cancelada.",
                    "Erro": "", "SelecionadaPorUsuario": bool(interface_preferida),
                    "Interface": {}}
        script = r"""
$ErrorActionPreference='SilentlyContinue'
$result=@(foreach($adapter in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {$_.Status -ne 'Disabled'})) {
 $i=[int]$adapter.ifIndex
 $v4=@(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -and $_.IPAddress -notlike '127.*'} | Sort-Object @{Expression={if ($_.IPAddress -like '169.254.*') {1} else {0}}},IPAddress | ForEach-Object {[pscustomobject]@{Endereco=[string]$_.IPAddress;Prefixo=$_.PrefixLength}})
 $v6=@(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -and $_.IPAddress -notlike '::1'} | ForEach-Object {[string]$_.IPAddress})
 $r=@(Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1)
 $ipif=Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
 $dns=@(Get-DnsClientServerAddress -InterfaceIndex $i -ErrorAction SilentlyContinue | ForEach-Object {$_.ServerAddresses} | Where-Object {$_})
 $w=@(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object {($_.IPEnabled -eq $true) -and (([string]$_.InterfaceIndex -eq [string]$i) -or ([string]$_.Index -eq [string]$i))} | Select-Object -First 1)
 $p=Get-NetConnectionProfile -InterfaceIndex $i -ErrorAction SilentlyContinue | Select-Object -First 1
 [pscustomobject]@{Nome=[string]$adapter.Name;Alias=[string]$adapter.InterfaceAlias;Descricao=[string]$adapter.InterfaceDescription;Indice=$i;Status=[string]$adapter.Status;Midia=if($adapter.MediaType){[string]$adapter.MediaType}else{[string]$adapter.NdisPhysicalMedium};IPv4=@($v4);IPv6=@($v6);Gateway=if($r -and $r[0].NextHop){[string]$r[0].NextHop}else{''};MetricaRota=if($r){$r[0].RouteMetric}else{$null};MetricaInterface=if($ipif){$ipif.InterfaceMetric}else{$null};DNS=@($dns);MAC=[string]$adapter.MacAddress;Link=[string]$adapter.LinkSpeed;DHCP=if($w){[bool]$w[0].DHCPEnabled}else{$null};ServidorDHCP=if($w -and $w[0].DHCPServer){[string]$w[0].DHCPServer}else{''};Perfil=if($p){[string]$p.NetworkCategory}else{''}}
})
@($result)|ConvertTo-Json -Depth 6 -Compress
"""
        try:
            resposta = executar_powershell(script, timeout=20)
            if resposta.returncode != 0:
                erro = resposta.stderr.strip() or resposta.stdout.strip() or "Falha na consulta PowerShell."
                logger.warning("DETALHES_REDE_FALHARAM | %s", erro)
                return falha("Não foi possível consultar as informações de rede.", erro)
            bruto = json.loads(resposta.stdout or "[]")
        except Exception as exc:
            erro = str(exc) or "Falha ao consultar as interfaces de rede."
            logger.warning("DETALHES_REDE_FALHARAM | %s", erro)
            return falha("Não foi possível consultar as informações de rede.", erro)
        if cancelado():
            return {"Sucesso": False, "Cancelada": True,
                    "Mensagem": "Atualização das informações de rede cancelada.",
                    "Erro": "", "SelecionadaPorUsuario": bool(interface_preferida),
                    "Interface": {}}
        bruto = [bruto] if isinstance(bruto, dict) else bruto
        if not isinstance(bruto, list) or not bruto:
            return falha("Nenhum adaptador de rede disponível foi retornado pelo Windows.")

        def texto(valor):
            return "" if valor is None else str(valor).strip()

        def lista(valor):
            if valor is None:
                return []
            return valor if isinstance(valor, list) else [valor]

        interfaces = []
        for item in bruto:
            if not isinstance(item, dict):
                continue
            nome, alias = texto(item.get("Nome")), texto(item.get("Alias"))
            if not nome and not alias:
                continue
            ipv4, prefixo = "", None
            for entrada in lista(item.get("IPv4")):
                endereco = texto(entrada.get("Endereco") if isinstance(entrada, dict) else entrada)
                try:
                    candidato = ipaddress.IPv4Address(endereco)
                except (ipaddress.AddressValueError, ValueError):
                    continue
                if candidato.is_loopback:
                    continue
                ipv4 = str(candidato)
                try:
                    prefixo = int(entrada.get("Prefixo") if isinstance(entrada, dict) else None)
                    if not 0 <= prefixo <= 32:
                        raise ValueError
                except (TypeError, ValueError):
                    prefixo = None
                break
            mascara = rede = ""
            apipa = False
            if ipv4:
                endereco = ipaddress.IPv4Address(ipv4)
                apipa = endereco.is_link_local
                if prefixo is not None:
                    rede_objeto = ipaddress.ip_network(f"{endereco}/{prefixo}", strict=False)
                    mascara, rede = str(rede_objeto.netmask), str(rede_objeto)
            dns4, dns6 = [], []
            for servidor in lista(item.get("DNS")):
                try:
                    endereco = ipaddress.ip_address(texto(servidor).split("%", 1)[0])
                except ValueError:
                    continue
                destino = dns4 if endereco.version == 4 else dns6
                if str(endereco) not in destino:
                    destino.append(str(endereco))
            try:
                rota, metricainterface = int(item.get("MetricaRota")), int(item.get("MetricaInterface"))
                metrica = rota + metricainterface
            except (TypeError, ValueError):
                metrica = item.get("MetricaRota") if item.get("MetricaRota") is not None else item.get("MetricaInterface")
            dhcp = item.get("DHCP")
            dhcp = "Sim" if dhcp is True else "Não" if dhcp is False else "Não disponível"
            status = texto(item.get("Status"))
            status_normalizado = ("Conectado" if status.casefold() in ("up","connected","1","ativo","conectado")
                                  else "Desabilitado" if status.casefold() in ("disabled","desabilitado")
                                  else "Desconectado" if status.casefold() in ("disconnected","desconectado","down")
                                  else "Não disponível")
            interfaces.append({"Nome": nome or alias, "Alias": alias or nome,
                "Descricao": texto(item.get("Descricao")), "InterfaceIndex": item.get("Indice"),
                "Status": status, "StatusNormalizado": status_normalizado,
                "TipoMidia": texto(item.get("Midia")), "IPv4": ipv4, "Mascara": mascara,
                "PrefixLength": prefixo, "Rede": rede, "Gateway": texto(item.get("Gateway")),
                "MetricaEfetiva": metrica, "MAC": texto(item.get("MAC")),
                "VelocidadeLink": texto(item.get("Link")), "DNSIPv4": dns4, "DNSIPv6": dns6,
                "DHCPHabilitado": dhcp, "ServidorDHCP": texto(item.get("ServidorDHCP")),
                "IPv6": [texto(x) for x in lista(item.get("IPv6")) if texto(x)],
                "PerfilRede": texto(item.get("Perfil")), "APIPA": apipa,
                "InterfaceElegivel": False, "MotivoInelegivel": "",
                "AtualizadoEm": datetime.now().strftime("%d/%m/%Y %H:%M:%S")})
        if not interfaces:
            return falha("Nenhum adaptador de rede disponível foi retornado pelo Windows.")
        avaliacao = ModuloEmpresa._avaliar_interfaces_varredura([{
            "InterfaceAlias": x["Alias"], "InterfaceIndex": x["InterfaceIndex"],
            "Status": x["Status"], "Descricao": x["Descricao"], "Tipo": x["TipoMidia"],
            "IPv4": x["IPv4"], "PrefixLength": x["PrefixLength"],
            "Gateway": x["Gateway"], "RouteMetric": x["MetricaEfetiva"], "DNS": x["DNSIPv4"]
        } for x in interfaces])
        preferida = texto(interface_preferida)
        if preferida:
            selecionada = next((x for x in interfaces if preferida.casefold() in
                                {x["Nome"].casefold(), x["Alias"].casefold()}), None)
            if not selecionada:
                return falha("O adaptador selecionado não foi encontrado na nova consulta.", preferida)
        else:
            candidata = avaliacao.get("Selecionada") or {}
            selecionada = next((x for x in interfaces if str(x["InterfaceIndex"]) == str(candidata.get("InterfaceIndex"))), None)
            if not selecionada:
                selecionada = next((x for x in interfaces if x["StatusNormalizado"] == "Conectado"), interfaces[0])
        elegivel = any(str(x["InterfaceIndex"]) == str(selecionada["InterfaceIndex"])
                       for x in avaliacao.get("Candidatas", []))
        selecionada["InterfaceElegivel"] = elegivel
        if not elegivel:
            selecionada["MotivoInelegivel"] = next((x.get("Motivo") for x in avaliacao.get("Rejeitadas", [])
                if str(x.get("Alias") or "").casefold() == selecionada["Alias"].casefold()), "interface_nao_elegivel")
        mensagem = ("Informações de rede atualizadas." if elegivel else
                    "A interface possui endereço APIPA; conectividade IPv4 não está disponível."
                    if selecionada["APIPA"] else
                    "Informações atualizadas, mas a interface não atende aos critérios de conectividade IPv4 ativa.")
        registrar_log("REDE", "DETALHES_REDE_ATUALIZADOS", "Interface: %s; IPv4: %s; Elegível: %s" %
                      (selecionada["Alias"] or "—", selecionada["IPv4"] or "—", "sim" if elegivel else "não"))
        return {"Sucesso": True, "Cancelada": False, "Mensagem": mensagem, "Erro": "",
                "SelecionadaPorUsuario": bool(preferida), "Interface": selecionada}

    @staticmethod
    def executar_diagnostico_rede_rapido(interface_preferida: Optional[str] = None,
                                         detalhes_precoletados=None,
                                         cancel_callback=None) -> Dict[str, Any]:
        """Testes curtos e sob demanda, sem alterar DNS, DHCP, rota ou serviço."""
        def cancelado():
            try:
                return bool(cancel_callback and cancel_callback())
            except Exception:
                return False
        def cancelar(linhas, detalhes):
            return {"Sucesso": False, "Cancelada": True, "Mensagem": "Diagnóstico rápido cancelado.",
                    "Linhas": linhas, "Detalhes": detalhes, "ResultadoGeral": "Cancelado"}
        if cancelado():
            return cancelar([], {})
        detalhes = detalhes_precoletados if isinstance(detalhes_precoletados, dict) else {}
        interface = detalhes.get("Interface") if detalhes.get("Sucesso") else {}
        preferida = str(interface_preferida or "").strip().casefold()
        if not interface or (preferida and preferida not in {
            str(interface.get("Nome") or "").casefold(), str(interface.get("Alias") or "").casefold()}):
            detalhes = ModuloRede.obter_detalhes_rede(interface_preferida, cancel_callback)
            interface = detalhes.get("Interface") if detalhes.get("Sucesso") else {}
        if cancelado():
            return cancelar([], detalhes)
        if not interface:
            mensagem = detalhes.get("Mensagem") or "Não foi possível consultar a interface de rede."
            logger.warning("DIAGNOSTICO_REDE_FALHOU | %s", mensagem)
            return {"Sucesso": False, "Cancelada": False, "Mensagem": mensagem,
                    "Linhas": [], "Detalhes": detalhes, "ResultadoGeral": "Indisponível"}
        linhas = []
        def add(nome, estado, detalhe):
            linhas.append({"Verificacao": nome, "Estado": estado, "Detalhe": detalhe})
        conectada = interface.get("StatusNormalizado") == "Conectado"
        add("Interface", "OK" if conectada else "Falha",
            "Interface ativa: %s." % (interface.get("Alias") or "—") if conectada else
            "Interface não está ativa (%s)." % (interface.get("StatusNormalizado") or "Não disponível"))
        try:
            ip = ipaddress.IPv4Address(str(interface.get("IPv4") or ""))
            ipv4_valido = not ip.is_link_local and not ip.is_unspecified
        except (ipaddress.AddressValueError, ValueError):
            ipv4_valido = False
        add("IPv4", "OK" if ipv4_valido else "Falha",
            "%s configurado." % interface.get("IPv4") if ipv4_valido else
            "Endereço APIPA detectado; não há conectividade IPv4 utilizável." if interface.get("APIPA")
            else "Não há endereço IPv4 válido na interface.")
        gateway = str(interface.get("Gateway") or "").strip()
        try:
            gw = ipaddress.IPv4Address(gateway)
            gateway_valido = not (gw.is_unspecified or gw.is_loopback or gw.is_multicast)
        except (ipaddress.AddressValueError, ValueError):
            gateway_valido = False
        if not gateway_valido:
            add("Gateway", "Não disponível", "Não há rota padrão IPv4 configurada.")
        elif not conectada or not ipv4_valido:
            add("Gateway", "Não aplicável", "O teste foi ignorado porque a interface não está pronta.")
        else:
            ok, ms = ModuloEmpresa._medir_ping_monitoramento(gateway, timeout_ms=800)
            add("Gateway", "OK" if ok else "Atenção",
                "%s respondeu em %s ms." % (gateway, ms if ms is not None else "—") if ok
                else "%s não respondeu ao ping curto." % gateway)
        if cancelado():
            return cancelar(linhas, detalhes)
        dns4 = [str(x) for x in interface.get("DNSIPv4") or [] if str(x).strip()]
        dns6 = [str(x) for x in interface.get("DNSIPv6") or [] if str(x).strip()]
        dns_ok = None
        if not dns4 and not dns6:
            add("DNS configurado", "Falha", "Nenhum servidor DNS foi informado pela interface.")
            add("Resolução DNS", "Não aplicável", "Não há servidor DNS para testar.")
        else:
            add("DNS configurado", "OK", ", ".join(dns4 + dns6))
            if not dns4:
                add("Resolução DNS", "Não disponível", "Há apenas DNS IPv6; o teste IPv4 direto não foi executado.")
            elif not conectada or not ipv4_valido:
                add("Resolução DNS", "Não aplicável", "O teste foi ignorado porque a interface não está pronta.")
            else:
                dns_ok, ms = testar_servidor_dns(dns4[0], timeout=2)
                add("Resolução DNS", "OK" if dns_ok else "Atenção",
                    "%s respondeu em %.0f ms." % (dns4[0], ms) if dns_ok
                    else "%s não respondeu à consulta DNS curta." % dns4[0])
        if cancelado():
            return cancelar(linhas, detalhes)
        if not conectada or not ipv4_valido or not gateway_valido:
            internet_ok = None
            add("Conectividade externa", "Não aplicável", "O teste TCP foi ignorado sem rota IPv4 utilizável.")
        else:
            internet_ok, ms = ModuloEmpresa._testar_internet_monitoramento(timeout=1.5)
            add("Conectividade externa", "OK" if internet_ok else "Atenção",
                "TCP externo disponível (%s ms)." % (ms if ms is not None else "—") if internet_ok
                else "O teste TCP externo não respondeu no tempo curto.")
        if not conectada or not ipv4_valido:
            geral, mensagem = "Indisponível", "A interface não possui conectividade IPv4 utilizável."
        elif not dns4 and not dns6:
            geral, mensagem = "Falha", "Nenhum servidor DNS está configurado na interface."
        elif internet_ok and dns_ok is True:
            geral, mensagem = "OK", "Conectividade básica disponível."
        elif any(x["Estado"] == "Falha" for x in linhas):
            geral, mensagem = "Falha", "O diagnóstico encontrou uma configuração essencial ausente."
        else:
            geral, mensagem = "Atenção", "O diagnóstico foi concluído com limitações de conectividade."
        registrar_log("REDE", "DIAGNOSTICO_REDE_EXECUTADO",
                      "Interface: %s; Resultado: %s" % (interface.get("Alias") or "—", geral))
        return {"Sucesso": True, "Cancelada": False, "Mensagem": mensagem,
                "Linhas": linhas, "Detalhes": detalhes, "ResultadoGeral": geral}

    @staticmethod
    def consultar_detalhes_interface(nome_adaptador: str):
        adaptador_limpo = sanitizar_texto(nome_adaptador)
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}{'─' * 50}{Cores.RESET}")
        print(f"{Cores.CIANO}{Cores.NEGRITO}  INFORMAÇÕES DETALHADAS: {adaptador_limpo}{Cores.RESET}")
        print(f"{Cores.CIANO}{Cores.NEGRITO}{'─' * 50}{Cores.RESET}")
        
        # Informações do adaptador
        try:
            cmd = f"Get-NetAdapter -Name \'{escapar_ps_string(adaptador_limpo)}\' | Select-Object MacAddress, LinkSpeed, Status | ConvertTo-Json"
            res = executar_powershell(cmd)
            if res.stdout.strip():
                detalhes = json.loads(res.stdout.strip())
                status = detalhes.get('Status', 'N/A')
                status_cor = Cores.VERDE if status == 'Up' else Cores.VERMELHO
                print(f"\n📟 Endereço MAC: {Cores.AZUL_CLARO}{detalhes.get('MacAddress', 'N/A')}{Cores.RESET}")
                print(f"⚡ Velocidade: {Cores.AMARELO}{detalhes.get('LinkSpeed', 'N/A')}{Cores.RESET}")
                print(f"🔌 Status: {status_cor}{status}{Cores.RESET}")
        except Exception as e:
            print(f"{Cores.AMARELO}⚠️ Erro ao obter informações do adaptador: {e}{Cores.RESET}")
        
        # IP e Máscara
        try:
            cmd = f"Get-NetIPAddress -InterfaceAlias \'{escapar_ps_string(adaptador_limpo)}\' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress, PrefixLength | ConvertTo-Json"
            res = executar_powershell(cmd)
            if res.stdout.strip():
                dados = json.loads(res.stdout.strip())
                if isinstance(dados, list):
                    dados = dados[0]
                print(f"\n🌐 Endereço IP: {Cores.VERDE}{dados.get('IPAddress', 'N/A')}{Cores.RESET}")
                print(f"🔢 Máscara de rede: /{dados.get('PrefixLength', 'N/A')}")
            else:
                print(f"\n🌐 Endereço IP: {Cores.VERMELHO}Desconectado / Não atribuído{Cores.RESET}")
        except Exception as e:
            print(f"{Cores.AMARELO}⚠️ Erro ao obter IP: {e}{Cores.RESET}")
        
        # Gateway
        try:
            cmd = f"Get-NetRoute -InterfaceAlias \'{escapar_ps_string(adaptador_limpo)}\' -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop | ConvertTo-Json"
            res = executar_powershell(cmd)
            if res.stdout.strip():
                gw = json.loads(res.stdout.strip())
                if isinstance(gw, list):
                    gw = gw[0]
                print(f"🚪 Gateway Padrão: {Cores.AZUL_CLARO}{gw}{Cores.RESET}")
            else:
                print("🚪 Gateway Padrão: Não encontrado")
        except Exception as e:
            print(f"{Cores.AMARELO}⚠️ Erro ao obter Gateway: {e}{Cores.RESET}")
        
        # DNS
        try:
            cmd = f"Get-DnsClientServerAddress -InterfaceAlias \'{escapar_ps_string(adaptador_limpo)}\' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses | ConvertTo-Json"
            res = executar_powershell(cmd)
            if res.stdout.strip():
                dns_lista = json.loads(res.stdout.strip())
                if isinstance(dns_lista, str):
                    dns_lista = [dns_lista]
                print(f"\n📋 Servidores DNS Configurados:")
                for ip in dns_lista:
                    # Testar cada DNS
                    ok, latencia = testar_servidor_dns(ip, timeout=2)
                    status = f"{Cores.VERDE}✓{Cores.RESET}" if ok else f"{Cores.VERMELHO}✗{Cores.RESET}"
                    lat_str = f" ({latencia:.0f}ms)" if ok else ""
                    print(f"   • {Cores.VERDE}{ip}{Cores.RESET} {status}{lat_str}")
            else:
                print("\n📋 DNS Configurado: Nenhum (DHCP)")
        except Exception as e:
            print(f"{Cores.AMARELO}⚠️ Erro ao obter DNS: {e}{Cores.RESET}")
        
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}{'─' * 50}{Cores.RESET}")

    @staticmethod
    def consultar_detalhes_interface_texto(nome_adaptador: str) -> str:
        """Mesma consulta de consultar_detalhes_interface(), mas RETORNA texto
        em vez de fazer print() — necessário para mostrar o resultado na GUI
        (ver gerar_diagnostico_completo_texto para a mesma lógica aplicada
        ao diagnóstico geral)."""
        adaptador_limpo = sanitizar_texto(nome_adaptador)
        linhas = [f"INFORMAÇÕES DETALHADAS: {adaptador_limpo}", "─" * 50]

        try:
            cmd = f"Get-NetAdapter -Name \'{escapar_ps_string(adaptador_limpo)}\' | Select-Object MacAddress, LinkSpeed, Status | ConvertTo-Json"
            res = executar_powershell(cmd)
            if res.stdout.strip():
                detalhes = json.loads(res.stdout.strip())
                linhas.append(f"Endereço MAC: {detalhes.get('MacAddress', 'N/A')}")
                linhas.append(f"Velocidade: {detalhes.get('LinkSpeed', 'N/A')}")
                linhas.append(f"Status: {detalhes.get('Status', 'N/A')}")
        except Exception as e:
            linhas.append(f"[Aviso] Erro ao obter informações do adaptador: {e}")

        try:
            cmd = f"Get-NetIPAddress -InterfaceAlias \'{escapar_ps_string(adaptador_limpo)}\' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress, PrefixLength | ConvertTo-Json"
            res = executar_powershell(cmd)
            if res.stdout.strip():
                dados = json.loads(res.stdout.strip())
                if isinstance(dados, list): dados = dados[0]
                linhas.append(f"\nEndereço IP: {dados.get('IPAddress', 'N/A')}")
                linhas.append(f"Máscara de rede: /{dados.get('PrefixLength', 'N/A')}")
            else:
                linhas.append("\nEndereço IP: Desconectado / Não atribuído")
        except Exception as e:
            linhas.append(f"[Aviso] Erro ao obter IP: {e}")

        try:
            cmd = f"Get-NetRoute -InterfaceAlias \'{escapar_ps_string(adaptador_limpo)}\' -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop | ConvertTo-Json"
            res = executar_powershell(cmd)
            if res.stdout.strip():
                gw = json.loads(res.stdout.strip())
                if isinstance(gw, list): gw = gw[0]
                linhas.append(f"Gateway Padrão: {gw}")
            else:
                linhas.append("Gateway Padrão: Não encontrado")
        except Exception as e:
            linhas.append(f"[Aviso] Erro ao obter Gateway: {e}")

        try:
            cmd = f"Get-DnsClientServerAddress -InterfaceAlias \'{escapar_ps_string(adaptador_limpo)}\' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses | ConvertTo-Json"
            res = executar_powershell(cmd)
            if res.stdout.strip():
                dns_lista = json.loads(res.stdout.strip())
                if isinstance(dns_lista, str): dns_lista = [dns_lista]
                linhas.append("\nServidores DNS Configurados:")
                for ip in dns_lista:
                    ok, latencia = testar_servidor_dns(ip, timeout=2)
                    status = "OK" if ok else "FALHA"
                    lat_str = f" ({latencia:.0f}ms)" if ok else ""
                    linhas.append(f"   • {ip} [{status}]{lat_str}")
            else:
                linhas.append("\nDNS Configurado: Nenhum (DHCP)")
        except Exception as e:
            linhas.append(f"[Aviso] Erro ao obter DNS: {e}")

        linhas.append("\n" + "─" * 50)
        return "\n".join(linhas)

    @staticmethod
    def aplicar_dns(adaptador: str, ips: List[str], backup_anterior: bool = True) -> Tuple[bool, Optional[str]]:
        if not elevacao_sob_demanda("alterar DNS"):
            return False, "Operação cancelada (privilégio de administrador necessário)."
        adaptador_limpo = sanitizar_texto(adaptador)
        
        # Backup
        if backup_anterior:
            backup_path = ModuloRede._backup_manager.criar_backup(adaptador_limpo)
            if backup_path:
                print(f"{Cores.CINZA}💾 Backup criado: {backup_path}{Cores.RESET}")
        
        # Validação
        for ip in ips:
            valido, msg = validar_ip_estrito(ip)
            if not valido:
                return False, f"IP {ip} rejeitado: {msg}"
        
        # Rate limit
        try:
            verificar_rate_limit()
        except RuntimeError as e:
            return False, str(e)
        
        # Aplicar
        ips_fmt = ",".join([f'"{ip}"' for ip in ips])
        cmd = f"Set-DnsClientServerAddress -InterfaceAlias '{escapar_ps_string(adaptador_limpo)}' -ServerAddresses @({ips_fmt})"
        
        try:
            res = executar_powershell(cmd)
            if res.returncode == 0:
                cache_res = executar_powershell("Clear-DnsClientCache")
                if cache_res.returncode != 0:
                    logger.warning(f"DNS aplicado, mas falhou ao limpar cache: {cache_res.stderr.strip()}")
                registrar_log("REDE", "APLICAR_DNS", f"{adaptador_limpo} -> {ips}")
                
                # Testar conectividade
                time.sleep(0.5)
                print(f"\n{Cores.CIANO}Testando servidores DNS...{Cores.RESET}")
                for ip in ips:
                    ok, latencia = testar_servidor_dns(ip)
                    status = f"{Cores.VERDE}✓ Online ({latencia:.0f}ms){Cores.RESET}" if ok else f"{Cores.VERMELHO}✗ Sem resposta{Cores.RESET}"
                    print(f"  {ip}: {status}")
                
                return True, None
            else:
                return False, res.stderr.strip()
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def restaurar_dhcp(adaptador: str) -> bool:
        if not elevacao_sob_demanda("restaurar DNS via DHCP"):
            return False
        adaptador_limpo = sanitizar_texto(adaptador)
        cmd = f"Set-DnsClientServerAddress -InterfaceAlias '{escapar_ps_string(adaptador_limpo)}' -ResetServerAddresses"
        try:
            res = executar_powershell(cmd)
            if res.returncode == 0:
                cache_res = executar_powershell("Clear-DnsClientCache")
                if cache_res.returncode != 0:
                    logger.warning(f"DNS aplicado, mas falhou ao limpar cache: {cache_res.stderr.strip()}")
                registrar_log("REDE", "RESTAURAR_DHCP", adaptador_limpo)
                return True
            return False
        except Exception as e:
            logger.error(f"Erro ao restaurar DHCP: {e}")
            return False
    
    @staticmethod
    def configurar_ip_fixo(adaptador: str, ip: str, mascara: str, gateway: str) -> Tuple[bool, str]:
        """Configura IPv4 estático, máscara/prefixo e gateway na interface selecionada."""
        try:
            endereco = ipaddress.IPv4Address(ip.strip())
            gw = ipaddress.IPv4Address(gateway.strip())

            mascara = mascara.strip()
            if mascara.isdigit():
                prefixo = int(mascara)
                if not 0 <= prefixo <= 32:
                    return False, "Prefixo inválido. Informe um valor entre 0 e 32."
            else:
                try:
                    rede_tmp = ipaddress.IPv4Network(f"0.0.0.0/{mascara}", strict=False)
                    prefixo = rede_tmp.prefixlen
                except ValueError:
                    return False, "Máscara inválida. Use, por exemplo, 255.255.255.0 ou /24."

            rede = ipaddress.IPv4Network(f"{endereco}/{prefixo}", strict=False)
            if gw not in rede:
                return False, "O gateway não pertence à mesma rede do endereço IP informado."
            if endereco == rede.network_address or endereco == rede.broadcast_address:
                return False, "O endereço informado não pode ser o endereço de rede ou broadcast."

            alias = sanitizar_texto(adaptador)
            alias_ps = escapar_ps_string(alias)
            cmd = f"""
$alias = '{alias_ps}'
$existing = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }})
Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
foreach($item in $existing) {{
    Remove-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -IPAddress $item.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
}}
Get-NetRoute -InterfaceAlias $alias -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $alias -IPAddress '{endereco}' -PrefixLength {prefixo} -DefaultGateway '{gw}' -AddressFamily IPv4 -ErrorAction Stop | Out-Null
Write-Output 'OK'
"""
            res = executar_powershell(cmd, timeout=45)
            if res.returncode != 0:
                detalhe = res.stderr.strip() or res.stdout.strip() or "Falha desconhecida ao configurar o IP."
                return False, detalhe
            registrar_log("REDE", "CONFIGURAR_IP_FIXO", f"Interface: {alias}; IP: {endereco}/{prefixo}; Gateway: {gw}")
            return True, f"IP fixo configurado com sucesso: {endereco}/{prefixo} | Gateway: {gw}"
        except ValueError as e:
            return False, f"Dados de IP inválidos: {e}"
        except Exception as e:
            logger.error(f"Erro ao configurar IP fixo: {e}")
            return False, str(e)

    @staticmethod
    def renovar_ip_e_flush_dns() -> Tuple[bool, str]:
        comandos = [
            ("Limpar cache DNS", "ipconfig /flushdns"),
            ("Liberar endereço IP", "ipconfig /release"),
            ("Renovar endereço IP", "ipconfig /renew")
        ]
        erros = []
        print(f"\n{Cores.AMARELO}Executando operações de rede...{Cores.RESET}")
        for i, (descricao, cmd) in enumerate(comandos, 1):
            mostrar_progresso(i, len(comandos), "Processando", descricao)
            try:
                res = executar_powershell(cmd, timeout=60)
                if res.returncode != 0:
                    detalhe = res.stderr.strip() or res.stdout.strip() or "erro desconhecido"
                    erros.append(f"{descricao}: {detalhe}")
            except Exception as e:
                erros.append(f"{descricao}: {e}")
        if erros:
            msg = " | ".join(erros)
            logger.error(f"Falha ao renovar conexão: {msg}")
            return False, msg
        registrar_log("REDE", "RENOVAR_CONEXAO", "FlushDNS + Release/Renew concluído")
        return True, "Conexão renovada com sucesso."

# ==========================================
# MÓDULO DE SISTEMA
# ==========================================
class ModuloSistema:
    @staticmethod
    def obter_informacoes_sistema() -> Dict[str, Any]:
        script = '''
        try {
            $so = Get-CimInstance Win32_OperatingSystem
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name
            $mobo = Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product
            $bios = Get-CimInstance Win32_BIOS | Select-Object SerialNumber, Version
            $discos = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, @{N='SizeGB';E={[math]::Round($_.Size/1GB, 1)}}
            $particoes = Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystem, 
                @{N='SizeGB';E={[math]::Round($_.Size/1GB, 1)}}, 
                @{N='FreeGB';E={[math]::Round($_.SizeRemaining/1GB, 1)}},
                @{N='UsedGB';E={[math]::Round(($_.Size - $_.SizeRemaining)/1GB, 1)}}

            [PSCustomObject]@{
                HostName = $env:COMPUTERNAME
                Usuario = $env:USERNAME
                Dominio = $env:USERDOMAIN
                OS = $so.Caption + " (" + $so.OSArchitecture + ")"
                VersaoOS = $so.Version
                CPU = $cpu
                PlacaMae = "$($mobo.Manufacturer) $($mobo.Product)"
                BIOS = "$($bios.SerialNumber) / Ver: $($bios.Version)"
                RAMTotalGB = [math]::Round($so.TotalVisibleMemorySize / 1MB, 2)
                RAMLivreGB = [math]::Round($so.FreePhysicalMemory / 1MB, 2)
                DiscosFisicos = @($discos)
                Particoes = @($particoes)
                BootTime = $so.LastBootUpTime
            } | ConvertTo-Json -Depth 4
        } catch {
            ConvertTo-Json @{}
        }
        '''
        
        try:
            res = executar_powershell(script, timeout=20)
            if res.returncode == 0 and res.stdout.strip():
                return json.loads(res.stdout.strip())
        except Exception as e:
            logger.error(f"Erro ao obter info sistema: {e}")
        return {}
    
    @staticmethod
    def obter_hardware_detalhado() -> Dict[str, Any]:
        script = r"""
$ErrorActionPreference='Stop'
function TipoRam($t){switch([int]$t){20{'DDR'}21{'DDR2'}24{'DDR3'}26{'DDR4'}34{'DDR5'}default{'Desconhecido'}}}
$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1
$ram=@(Get-CimInstance Win32_PhysicalMemory|ForEach-Object{[PSCustomObject]@{Banco=$_.DeviceLocator;Fabricante=$_.Manufacturer;CapacidadeGB=[math]::Round($_.Capacity/1GB,2);Tipo=(TipoRam $_.SMBIOSMemoryType);VelocidadeMHz=$_.Speed;Modelo=$_.PartNumber.Trim()}})
$discos=@(Get-PhysicalDisk|ForEach-Object{[PSCustomObject]@{Nome=$_.FriendlyName;Tipo=$_.MediaType;Interface=$_.BusType;Saude=$_.HealthStatus;TamanhoGB=[math]::Round($_.Size/1GB,2)}})
[PSCustomObject]@{CPU=$cpu.Name.Trim();CPUFabricante=$cpu.Manufacturer;Nucleos=$cpu.NumberOfCores;ProcessadoresLogicos=$cpu.NumberOfLogicalProcessors;ClockMaxMHz=$cpu.MaxClockSpeed;RAM=$ram;Discos=$discos}|ConvertTo-Json -Depth 6 -Compress
"""
        try:
            r=executar_powershell(script, timeout=30)
            return json.loads(r.stdout) if r.returncode==0 and r.stdout.strip() else {}
        except Exception as e:
            logger.warning(f"Erro ao obter hardware detalhado: {e}")
            return {}

    @staticmethod
    def obter_sensores_hardware(
        dados_saude_armazenamento=None,
        progress_callback=None,
        cancel_callback=None,
    ) -> Dict[str, Any]:
        """Coleta telemetria local de hardware com fontes nativas do Windows.

        A rotina é estritamente de leitura e foi desenhada para executar em um
        Worker/QThread da GUI. Ela não instala drivers, não acessa APIs de
        terceiros, não escreve em SMART e não solicita elevação. Temperaturas
        de CPU/GPU e RPM de ventoinhas só são exibidos quando uma fonte nativa
        consegue expô-los com associação confiável; na maior parte dos PCs o
        Windows não disponibiliza esses sensores ao processo comum.

        ``dados_saude_armazenamento`` é um *snapshot* opcional já obtido pela
        tela Saúde de Armazenamento. Quando presente, a temperatura de disco é
        reaproveitada dele, sem disparar outra consulta SMART/reliability e sem
        alterar o fluxo de UAC isolado daquela tela.
        """

        def cancelada() -> bool:
            try:
                return bool(callable(cancel_callback) and cancel_callback())
            except Exception:
                return False

        def emitir(percentual: int, mensagem: str) -> None:
            if not callable(progress_callback):
                return
            try:
                progress_callback(max(0, min(100, int(percentual))), str(mensagem))
            except Exception:
                pass

        def texto(valor: Any) -> str:
            if valor is None:
                return ""
            return str(valor).strip()

        def numero(valor: Any) -> Optional[float]:
            if valor is None or isinstance(valor, bool):
                return None
            try:
                convertido = float(valor)
                return convertido if convertido == convertido else None
            except (TypeError, ValueError):
                return None

        def lista(valor: Any) -> List[Dict[str, Any]]:
            if isinstance(valor, list):
                return [item for item in valor if isinstance(item, dict)]
            if isinstance(valor, dict):
                return [valor]
            return []

        def tamanho_legivel(valor: Any) -> str:
            tamanho = numero(valor)
            if tamanho is None or tamanho < 0:
                return "—"
            unidades = ("B", "KiB", "MiB", "GiB", "TiB")
            indice = 0
            while tamanho >= 1024 and indice < len(unidades) - 1:
                tamanho /= 1024
                indice += 1
            if indice == 0:
                return f"{tamanho:.0f} {unidades[indice]}"
            return f"{tamanho:.1f} {unidades[indice]}"

        def percentual_legivel(valor: Any) -> str:
            quantidade = numero(valor)
            if quantidade is None:
                return "—"
            return f"{max(0.0, min(100.0, quantidade)):.1f}%"

        def estado_percentual(
            valor: Any, atencao: float, critico: float
        ) -> str:
            quantidade = numero(valor)
            if quantidade is None:
                return "Não disponível"
            if quantidade >= critico:
                return "Crítico"
            if quantidade >= atencao:
                return "Atenção"
            return "Normal"

        def temperatura_acpi(valor: Any) -> Optional[float]:
            bruto = numero(valor)
            # MSAcpi_ThermalZoneTemperature usa décimos de Kelvin. Faixas
            # fora deste intervalo são tratadas como ausência/fonte inválida,
            # jamais como 0 °C ou como uma temperatura estimada.
            if bruto is None or bruto < 2000 or bruto > 5000:
                return None
            convertido = (bruto / 10.0) - 273.15
            if convertido < -20 or convertido > 150:
                return None
            return round(convertido, 1)

        def temperatura_snapshot(valor: Any) -> Optional[float]:
            if isinstance(valor, (int, float)) and not isinstance(valor, bool):
                possivel = float(valor)
            else:
                correspondencia = re.search(
                    r"(-?\d+(?:[.,]\d+)?)", texto(valor)
                )
                if not correspondencia:
                    return None
                try:
                    possivel = float(correspondencia.group(1).replace(",", "."))
                except ValueError:
                    return None
            if possivel <= 0 or possivel > 150:
                return None
            return round(possivel, 1)

        def estado_bateria(carga: Any, carregando: bool) -> str:
            percentual = numero(carga)
            if percentual is None:
                return "Não disponível"
            if carregando:
                return "Normal"
            if percentual < 5:
                return "Crítico"
            if percentual < 15:
                return "Atenção"
            return "Normal"

        def estado_saude_bateria(valor: Any) -> str:
            percentual = numero(valor)
            if percentual is None:
                return "Não disponível"
            if percentual < 60:
                return "Crítico"
            if percentual < 80:
                return "Atenção"
            return "Normal"

        def log_evento(acao: str, detalhes: str, nivel="info") -> None:
            try:
                registrar_log("SISTEMA", acao, detalhes)
            except Exception:
                try:
                    getattr(logger, nivel)("[%s] %s", acao, detalhes)
                except Exception:
                    pass

        inicio = time.monotonic()
        medidas: List[Dict[str, Any]] = []
        componentes_indisponiveis = set()
        medidas_disponiveis = 0

        def adicionar(
            componente: str,
            medida: str,
            valor: str,
            estado: str,
            origem: str,
            limitacao: str = "",
            disponivel: bool = True,
        ) -> None:
            nonlocal medidas_disponiveis
            medidas.append(
                {
                    "Componente": str(componente),
                    "Medida": str(medida),
                    "Valor": str(valor or "—"),
                    "Estado": str(estado),
                    "Origem": str(origem),
                    "Limitacao": str(limitacao),
                    "Disponivel": bool(disponivel),
                }
            )
            if disponivel:
                medidas_disponiveis += 1
            else:
                componentes_indisponiveis.add(str(componente))

        def indisponivel(
            componente: str, medida: str, origem: str, limitacao: str
        ) -> None:
            adicionar(
                componente,
                medida,
                "Não disponível",
                "Não disponível",
                origem,
                limitacao,
                disponivel=False,
            )

        if cancelada():
            return {
                "Sucesso": False,
                "Cancelada": True,
                "Mensagem": "Atualização de sensores cancelada antes de iniciar.",
                "Componentes": [],
            }

        emitir(5, "Consultando fontes nativas de hardware...")

        # As classes Win32_PerfFormattedData_* são nomes técnicos estáveis e
        # não dependem dos nomes localizados de contadores do Windows PT-BR.
        # Cada consulta é somente leitura e classes ausentes são representadas
        # por coleção vazia, não por valores fictícios.
        script = r"""
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'

function Primeiro($colecao) {
    $itens = @($colecao)
    if ($itens.Count -gt 0) { return $itens[0] }
    return $null
}

$cpu = Primeiro (Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue)
$cpuPerf = Primeiro (
    Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq '_Total' }
)
$os = Primeiro (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue)

$gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue)
$gpuDetalhes = @(
    foreach ($gpu in $gpus) {
        $memoria = $null
        try {
            if ($null -ne $gpu.AdapterRAM -and [double]$gpu.AdapterRAM -gt 0) {
                $memoria = [double]$gpu.AdapterRAM
            }
        }
        catch {}
        [PSCustomObject]@{
            Nome = [string]$gpu.Name
            MemoriaDedicadaBytes = $memoria
            Driver = [string]$gpu.DriverVersion
        }
    }
)

$gpuMemoria = @()
try {
    $gpuMemoria = @(
        Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory -ErrorAction Stop
    )
}
catch {}
$gpuEngines = @()
try {
    $gpuEngines = @(
        Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction Stop
    )
}
catch {}

$dedicadaUsada = 0.0
$dedicadaEncontrada = $false
$compartilhadaUsada = 0.0
$compartilhadaEncontrada = $false
foreach ($contador in $gpuMemoria) {
    try {
        if ($null -ne $contador.DedicatedUsage -and [double]$contador.DedicatedUsage -ge 0) {
            $dedicadaUsada += [double]$contador.DedicatedUsage
            $dedicadaEncontrada = $true
        }
    }
    catch {}
    try {
        if ($null -ne $contador.SharedUsage -and [double]$contador.SharedUsage -ge 0) {
            $compartilhadaUsada += [double]$contador.SharedUsage
            $compartilhadaEncontrada = $true
        }
    }
    catch {}
}

$gpuUsoMaximo = $null
foreach ($engine in $gpuEngines) {
    try {
        if ($null -ne $engine.UtilizationPercentage) {
            $valor = [double]$engine.UtilizationPercentage
            if ($valor -ge 0 -and $valor -le 100) {
                if ($null -eq $gpuUsoMaximo -or $valor -gt $gpuUsoMaximo) {
                    $gpuUsoMaximo = $valor
                }
            }
        }
    }
    catch {}
}

$discosLogicos = @(
    Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue
)
$discosPerf = @(
    Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_LogicalDisk -ErrorAction SilentlyContinue
)
$discosDetalhes = @(
    foreach ($disco in $discosLogicos) {
        $perf = Primeiro @($discosPerf | Where-Object { [string]$_.Name -eq [string]$disco.DeviceID })
        [PSCustomObject]@{
            Unidade = [string]$disco.DeviceID
            TamanhoBytes = $disco.Size
            LivreBytes = $disco.FreeSpace
            LeituraBytesPorSegundo = if ($perf) { $perf.DiskReadBytesPerSec } else { $null }
            GravacaoBytesPorSegundo = if ($perf) { $perf.DiskWriteBytesPerSec } else { $null }
            AtividadePercentual = if ($perf) { $perf.PercentDiskTime } else { $null }
        }
    }
)

$zonasAcpi = @()
try {
    $zonasAcpi = @(
        Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop
    )
}
catch {}
$zonasDetalhes = @(
    foreach ($zona in $zonasAcpi) {
        [PSCustomObject]@{
            Nome = [string]$zona.InstanceName
            TemperaturaDeciKelvin = $zona.CurrentTemperature
        }
    }
)

$placaMae = Primeiro (Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue)
$chassis = Primeiro (Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue)

$baterias = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)
$bateriasDetalhes = @(
    foreach ($bateria in $baterias) {
        [PSCustomObject]@{
            Nome = [string]$bateria.Name
            Carga = $bateria.EstimatedChargeRemaining
            Status = $bateria.BatteryStatus
            CapacidadeProjeto = $bateria.DesignCapacity
            CapacidadeCargaCompleta = $bateria.FullChargeCapacity
        }
    }
)

[PSCustomObject]@{
    CPU = [PSCustomObject]@{
        Nome = if ($cpu) { [string]$cpu.Name } else { $null }
        UsoPercentual = if ($cpuPerf) { $cpuPerf.PercentProcessorTime } else { $null }
        ClockAtualMHz = if ($cpu) { $cpu.CurrentClockSpeed } else { $null }
        ClockMaxMHz = if ($cpu) { $cpu.MaxClockSpeed } else { $null }
    }
    RAM = [PSCustomObject]@{
        TotalKB = if ($os) { $os.TotalVisibleMemorySize } else { $null }
        LivreKB = if ($os) { $os.FreePhysicalMemory } else { $null }
    }
    GPUs = @($gpuDetalhes)
    GPUAgregada = [PSCustomObject]@{
        UsoMaximoEnginePercentual = $gpuUsoMaximo
        MemoriaDedicadaUsadaBytes = if ($dedicadaEncontrada) { $dedicadaUsada } else { $null }
        MemoriaCompartilhadaUsadaBytes = if ($compartilhadaEncontrada) { $compartilhadaUsada } else { $null }
    }
    Discos = @($discosDetalhes)
    ZonasTermicasACPI = @($zonasDetalhes)
    PlacaMae = [PSCustomObject]@{
        Fabricante = if ($placaMae) { [string]$placaMae.Manufacturer } else { $null }
        Produto = if ($placaMae) { [string]$placaMae.Product } else { $null }
    }
    Chassis = [PSCustomObject]@{
        Fabricante = if ($chassis) { [string]$chassis.Manufacturer } else { $null }
        Modelo = if ($chassis) { [string]$chassis.Model } else { $null }
    }
    Baterias = @($bateriasDetalhes)
} | ConvertTo-Json -Depth 8 -Compress
"""

        try:
            resposta = executar_powershell(script, timeout=35)
            if resposta.returncode != 0:
                log_evento(
                    "SENSOR_COLETA_FALHOU",
                    "etapa=powershell;tipo=CommandFailed",
                    nivel="warning",
                )
                try:
                    logger.warning(
                        "Falha controlada na consulta nativa de sensores (PowerShell)."
                    )
                except Exception:
                    pass
                return {
                    "Sucesso": False,
                    "Cancelada": False,
                    "Mensagem": (
                        "A consulta nativa de sensores falhou. Consulte "
                        "configurador_ti.log para o detalhe técnico."
                    ),
                    "Componentes": [],
                }
            bruto = json.loads((texto(resposta.stdout) or "{}").lstrip("\ufeff"))
            if not isinstance(bruto, dict):
                raise ValueError("A consulta nativa retornou JSON em formato inválido.")
        except Exception as exc:
            log_evento(
                "SENSOR_COLETA_FALHOU",
                f"etapa=normalizacao;tipo={type(exc).__name__}",
                nivel="warning",
            )
            try:
                logger.warning("Falha controlada na coleta de sensores: %s", exc)
            except Exception:
                pass
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": (
                    "Não foi possível processar a telemetria nativa de hardware. "
                    "Consulte configurador_ti.log."
                ),
                "Componentes": [],
            }

        if cancelada():
            return {
                "Sucesso": False,
                "Cancelada": True,
                "Mensagem": "Atualização de sensores cancelada após a consulta.",
                "Componentes": [],
            }

        emitir(55, "Organizando dados de CPU, memória e adaptadores...")

        cpu = bruto.get("CPU") if isinstance(bruto.get("CPU"), dict) else {}
        nome_cpu = texto(cpu.get("Nome"))
        if nome_cpu:
            adicionar(
                "CPU", "Modelo", nome_cpu, "Indeterminado", "Win32_Processor",
                "Identificação; não representa condição térmica ou de saúde.",
            )
        else:
            indisponivel(
                "CPU", "Modelo", "Win32_Processor",
                "O Windows não retornou um processador via CIM nesta sessão.",
            )

        uso_cpu = numero(cpu.get("UsoPercentual"))
        if uso_cpu is None:
            indisponivel(
                "CPU", "Uso total", "Win32_PerfFormattedData_PerfOS_Processor",
                "O contador nativo de uso total não foi exposto pelo Windows.",
            )
        else:
            adicionar(
                "CPU", "Uso total", percentual_legivel(uso_cpu),
                estado_percentual(uso_cpu, 85, 98),
                "Win32_PerfFormattedData_PerfOS_Processor",
                "Amostra instantânea; uso alto isolado não confirma problema.",
            )

        clock_atual = numero(cpu.get("ClockAtualMHz"))
        if clock_atual is None or clock_atual <= 0:
            indisponivel(
                "CPU", "Frequência atual", "Win32_Processor.CurrentClockSpeed",
                "Firmware ou driver não retornou uma frequência atual utilizável.",
            )
        else:
            adicionar(
                "CPU", "Frequência atual", f"{clock_atual:.0f} MHz", "Indeterminado",
                "Win32_Processor.CurrentClockSpeed",
                "Leitura instantânea; turbo e economia de energia podem alterá-la rapidamente.",
            )

        clock_maximo = numero(cpu.get("ClockMaxMHz"))
        if clock_maximo is None or clock_maximo <= 0:
            indisponivel(
                "CPU", "Frequência máxima conhecida", "Win32_Processor.MaxClockSpeed",
                "O firmware não retornou um valor máximo utilizável.",
            )
        else:
            adicionar(
                "CPU", "Frequência máxima conhecida", f"{clock_maximo:.0f} MHz",
                "Indeterminado", "Win32_Processor.MaxClockSpeed",
                "Valor divulgado pelo firmware; pode não refletir turbo dinâmico.",
            )

        # Não mapeamos uma zona ACPI genérica como "temperatura da CPU".
        indisponivel(
            "CPU", "Temperatura", "Firmware / ACPI",
            "O Windows não expôs um sensor térmico associado à CPU com segurança. "
            "Zonas ACPI genéricas, quando existirem, aparecem separadamente.",
        )

        ram = bruto.get("RAM") if isinstance(bruto.get("RAM"), dict) else {}
        ram_total = numero(ram.get("TotalKB"))
        ram_livre = numero(ram.get("LivreKB"))
        if ram_total is None or ram_total <= 0:
            indisponivel(
                "Memória RAM", "Uso", "Win32_OperatingSystem",
                "O Windows não retornou memória física total utilizável.",
            )
        else:
            ram_livre = max(0.0, min(ram_total, ram_livre or 0.0))
            ram_uso = (1 - (ram_livre / ram_total)) * 100.0
            adicionar(
                "Memória RAM", "Uso", percentual_legivel(ram_uso),
                estado_percentual(ram_uso, 90, 97), "Win32_OperatingSystem",
                "Uso da memória física visível ao Windows na amostra atual.",
            )
            adicionar(
                "Memória RAM", "Disponível", tamanho_legivel(ram_livre * 1024),
                "Indeterminado", "Win32_OperatingSystem",
                f"Total visível: {tamanho_legivel(ram_total * 1024)}.",
            )

        emitir(70, "Organizando telemetria de GPU, discos e plataforma...")

        gpus = lista(bruto.get("GPUs"))
        if not gpus:
            indisponivel(
                "GPU", "Adaptador", "Win32_VideoController",
                "O Windows não retornou adaptador de vídeo via CIM nesta sessão.",
            )
        for indice, gpu in enumerate(gpus, start=1):
            nome_gpu = texto(gpu.get("Nome")) or f"GPU {indice}"
            componente_gpu = nome_gpu
            adicionar(
                componente_gpu, "Adaptador", nome_gpu, "Indeterminado",
                "Win32_VideoController",
                "Identificação fornecida pelo driver; não representa condição térmica.",
            )
            memoria_gpu = numero(gpu.get("MemoriaDedicadaBytes"))
            if memoria_gpu is None or memoria_gpu <= 0:
                indisponivel(
                    componente_gpu, "Memória dedicada informada",
                    "Win32_VideoController.AdapterRAM",
                    "O driver não informou uma capacidade dedicada utilizável.",
                )
            else:
                adicionar(
                    componente_gpu, "Memória dedicada informada",
                    tamanho_legivel(memoria_gpu), "Indeterminado",
                    "Win32_VideoController.AdapterRAM",
                    "Capacidade informada pelo driver; não é uso instantâneo.",
                )
            indisponivel(
                componente_gpu, "Temperatura", "Driver / WMI nativo",
                "O Windows não expôs uma temperatura associada a esta GPU com segurança.",
            )

        gpu_agregada = (
            bruto.get("GPUAgregada")
            if isinstance(bruto.get("GPUAgregada"), dict)
            else {}
        )
        gpu_uso = numero(gpu_agregada.get("UsoMaximoEnginePercentual"))
        if gpu_uso is None:
            indisponivel(
                "GPU (agregada)", "Atividade de engine", 
                "Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine",
                "O contador nativo de engines não está disponível ou não pôde ser lido.",
            )
        else:
            adicionar(
                "GPU (agregada)", "Atividade de engine", percentual_legivel(gpu_uso),
                "Indeterminado",
                "Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine",
                "Maior atividade instantânea entre engines; não é atribuída a uma GPU específica.",
            )

        dedicada_usada = numero(gpu_agregada.get("MemoriaDedicadaUsadaBytes"))
        if dedicada_usada is None:
            indisponivel(
                "GPU (agregada)", "Memória dedicada em uso",
                "Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory",
                "O Windows não expôs contador agregado de memória dedicada.",
            )
        else:
            adicionar(
                "GPU (agregada)", "Memória dedicada em uso",
                tamanho_legivel(dedicada_usada), "Indeterminado",
                "Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory",
                "Soma dos adaptadores expostos; o Windows não garante associação com cada GPU listada.",
            )

        compartilhada_usada = numero(gpu_agregada.get("MemoriaCompartilhadaUsadaBytes"))
        if compartilhada_usada is None:
            indisponivel(
                "GPU (agregada)", "Memória compartilhada em uso",
                "Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory",
                "O Windows não expôs contador agregado de memória compartilhada.",
            )
        else:
            adicionar(
                "GPU (agregada)", "Memória compartilhada em uso",
                tamanho_legivel(compartilhada_usada), "Indeterminado",
                "Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory",
                "Soma dos adaptadores expostos; pode variar com memória compartilhada do sistema.",
            )

        discos = lista(bruto.get("Discos"))
        if not discos:
            indisponivel(
                "Discos", "Volumes locais", "Win32_LogicalDisk",
                "O Windows não retornou volumes fixos utilizáveis nesta sessão.",
            )
        for disco in discos:
            unidade = texto(disco.get("Unidade")) or "Volume local"
            tamanho = numero(disco.get("TamanhoBytes"))
            livre = numero(disco.get("LivreBytes"))
            if tamanho is None or tamanho <= 0 or livre is None:
                indisponivel(
                    f"Disco {unidade}", "Uso de espaço", "Win32_LogicalDisk",
                    "O Windows não retornou tamanho e espaço livre utilizáveis.",
                )
            else:
                livre = max(0.0, min(tamanho, livre))
                uso = (1 - (livre / tamanho)) * 100.0
                adicionar(
                    f"Disco {unidade}", "Uso de espaço", percentual_legivel(uso),
                    estado_percentual(uso, 90, 97), "Win32_LogicalDisk",
                    f"Disponível: {tamanho_legivel(livre)} de {tamanho_legivel(tamanho)}.",
                )

            for campo, titulo in (
                ("LeituraBytesPorSegundo", "Leitura instantânea"),
                ("GravacaoBytesPorSegundo", "Gravação instantânea"),
            ):
                valor_io = numero(disco.get(campo))
                if valor_io is None or valor_io < 0:
                    indisponivel(
                        f"Disco {unidade}", titulo,
                        "Win32_PerfFormattedData_PerfDisk_LogicalDisk",
                        "O contador nativo de I/O deste volume não foi exposto.",
                    )
                else:
                    adicionar(
                        f"Disco {unidade}", titulo,
                        f"{tamanho_legivel(valor_io)}/s", "Indeterminado",
                        "Win32_PerfFormattedData_PerfDisk_LogicalDisk",
                        "Amostra instantânea; atividade alta isolada não confirma falha.",
                    )

            atividade = numero(disco.get("AtividadePercentual"))
            if atividade is not None and atividade >= 0:
                adicionar(
                    f"Disco {unidade}", "Atividade instantânea",
                    percentual_legivel(atividade), "Indeterminado",
                    "Win32_PerfFormattedData_PerfDisk_LogicalDisk",
                    "Percentual instantâneo do contador do volume, sem diagnóstico automático.",
                )

        # A telemetria não executa uma segunda consulta SMART/reliability. A
        # temperatura dos discos é reaproveitada somente do último snapshot
        # obtido explicitamente pela Saúde de Armazenamento.
        snapshot_disponivel = isinstance(dados_saude_armazenamento, dict)
        snapshot_discos = (
            lista(dados_saude_armazenamento.get("Discos"))
            if snapshot_disponivel
            else []
        )
        temperaturas_reaproveitadas = 0
        for disco_saude in snapshot_discos:
            temperatura = temperatura_snapshot(disco_saude.get("Temperatura"))
            modelo = texto(disco_saude.get("Modelo"))
            numero_disco = texto(disco_saude.get("Numero"))
            identificador = " ".join(
                parte for parte in (f"Disco {numero_disco}" if numero_disco else "Disco", modelo) if parte
            )
            if temperatura is None:
                continue
            temperaturas_reaproveitadas += 1
            adicionar(
                identificador, "Temperatura", f"{temperatura:.1f} °C",
                "Indeterminado",
                "Saúde de Armazenamento (última análise)",
                "Valor reaproveitado de coleta somente leitura já concluída; não é uma nova consulta SMART. Não há limite térmico universal entre fabricantes.",
            )
        if temperaturas_reaproveitadas == 0:
            detalhe_temperatura = (
                "A última análise de Saúde de Armazenamento não expôs temperatura por disco."
                if snapshot_disponivel
                else "Execute Saúde de Armazenamento para reaproveitar temperaturas que o Windows/driver expuser."
            )
            indisponivel(
                "Discos", "Temperatura", "Saúde de Armazenamento",
                detalhe_temperatura,
            )

        zonas = lista(bruto.get("ZonasTermicasACPI"))
        zonas_validas = 0
        for indice, zona in enumerate(zonas, start=1):
            temperatura = temperatura_acpi(zona.get("TemperaturaDeciKelvin"))
            if temperatura is None:
                continue
            zonas_validas += 1
            nome_zona = texto(zona.get("Nome")) or f"Zona ACPI {indice}"
            identificador_zona = re.search(
                r"(?<![A-Za-z0-9])(TZ\d+)(?![A-Za-z0-9])",
                nome_zona,
                re.IGNORECASE,
            )
            nome_exibicao = (
                identificador_zona.group(1).upper()
                if identificador_zona else nome_zona
            )
            possivelmente_nao_utilizavel = 0 <= temperatura <= 5
            adicionar(
                "Chassis / ACPI", f"Zona térmica ACPI {nome_exibicao}",
                f"{temperatura:.1f} °C",
                (
                    "Possivelmente não utilizável"
                    if possivelmente_nao_utilizavel else "Indeterminado"
                ),
                "root\\wmi: MSAcpi_ThermalZoneTemperature",
                (
                    "Leitura próxima de 0 °C; pode representar um valor de firmware/ACPI "
                    "sem contexto térmico utilizável. Não é associada à CPU ou GPU e não gera alerta automático."
                    if possivelmente_nao_utilizavel
                    else "Zona térmica genérica ACPI; não é atribuída automaticamente à CPU ou GPU e não recebe limite térmico universal."
                ),
            )
        if zonas_validas == 0:
            indisponivel(
                "Chassis / ACPI", "Temperatura", 
                "root\\wmi: MSAcpi_ThermalZoneTemperature",
                "Firmware/ACPI não expôs uma zona térmica genérica utilizável.",
            )

        placa_mae = (
            bruto.get("PlacaMae") if isinstance(bruto.get("PlacaMae"), dict) else {}
        )
        placa_texto = " ".join(
            parte for parte in (texto(placa_mae.get("Fabricante")), texto(placa_mae.get("Produto"))) if parte
        )
        if placa_texto:
            adicionar(
                "Placa-mãe", "Identificação", placa_texto, "Indeterminado",
                "Win32_BaseBoard",
                "O Windows expõe identificação, mas não um sensor térmico/RPM confiável neste objeto.",
            )
        else:
            indisponivel(
                "Placa-mãe", "Identificação", "Win32_BaseBoard",
                "O Windows não retornou identificação de placa-mãe via CIM.",
            )
        indisponivel(
            "Ventoinhas", "RPM", "Win32_Fan / firmware",
            "O Windows não expôs RPM real de ventoinha. Win32_Fan pode representar velocidade desejada, não leitura física, e por isso não é usada.",
        )

        baterias = lista(bruto.get("Baterias"))
        if not baterias:
            indisponivel(
                "Bateria", "Carga / saúde", "Win32_Battery",
                "Nenhuma bateria foi exposta; em desktop isso é esperado.",
            )
        for indice, bateria in enumerate(baterias, start=1):
            nome_bateria = texto(bateria.get("Nome")) or f"Bateria {indice}"
            status_numero = numero(bateria.get("Status"))
            mapa_status = {
                1: "Descarregando", 2: "Conectada à rede", 3: "Totalmente carregada",
                4: "Baixa", 5: "Crítica", 6: "Carregando", 7: "Carregando (alta)",
                8: "Carregando (baixa)", 9: "Carregando (crítica)", 10: "Indefinida",
                11: "Parcialmente carregada",
            }
            status_bateria = mapa_status.get(int(status_numero), "Não informado") if status_numero is not None else "Não informado"
            carregando = status_numero in {2, 3, 6, 7, 8, 9}
            carga = numero(bateria.get("Carga"))
            if carga is None or carga < 0 or carga > 100:
                indisponivel(
                    nome_bateria, "Carga", "Win32_Battery",
                    "O firmware não retornou percentual de carga utilizável.",
                )
            else:
                adicionar(
                    nome_bateria, "Carga", percentual_legivel(carga),
                    estado_bateria(carga, carregando), "Win32_Battery",
                    f"Status nativo: {status_bateria}.",
                )
            adicionar(
                nome_bateria, "Status", status_bateria, "Indeterminado",
                "Win32_Battery", "Estado informado pelo firmware/driver.",
            )
            capacidade_projeto = numero(bateria.get("CapacidadeProjeto"))
            capacidade_cheia = numero(bateria.get("CapacidadeCargaCompleta"))
            if (
                capacidade_projeto is None or capacidade_cheia is None
                or capacidade_projeto <= 0 or capacidade_cheia <= 0
            ):
                indisponivel(
                    nome_bateria, "Saúde / capacidade", "Win32_Battery",
                    "O firmware não expôs capacidade de projeto e carga completa utilizáveis.",
                )
            else:
                saude = (capacidade_cheia / capacidade_projeto) * 100.0
                # Valores muito acima de 120% normalmente indicam unidade ou
                # firmware inconsistente; não apresentamos diagnóstico a partir
                # deles. Pequenas diferenças acima de 100% continuam visíveis.
                if saude <= 0 or saude > 120:
                    indisponivel(
                        nome_bateria, "Saúde / capacidade", "Win32_Battery",
                        "As capacidades retornadas pelo firmware são inconsistentes para cálculo seguro.",
                    )
                else:
                    adicionar(
                        nome_bateria, "Saúde / capacidade", percentual_legivel(saude),
                        estado_saude_bateria(saude), "Win32_Battery",
                        "Relação entre capacidade de carga completa e capacidade de projeto informadas pelo firmware.",
                    )

        if cancelada():
            return {
                "Sucesso": False,
                "Cancelada": True,
                "Mensagem": "Atualização de sensores cancelada durante a organização dos dados.",
                "Componentes": [],
            }

        emitir(100, "Telemetria de hardware atualizada")
        duracao_ms = int((time.monotonic() - inicio) * 1000)
        indisponiveis = sum(1 for item in medidas if not item.get("Disponivel"))
        fontes = {
            "CPU": bool(nome_cpu or uso_cpu is not None),
            "RAM": bool(ram_total and ram_total > 0),
            "GPU": bool(gpus),
            "Discos": bool(discos),
            "ACPI": zonas_validas > 0,
            "Bateria": bool(baterias),
            "TemperaturaDiscoReaproveitada": temperaturas_reaproveitadas > 0,
        }
        if componentes_indisponiveis:
            categorias_indisponiveis = set()
            for componente in componentes_indisponiveis:
                componente_normalizado = componente.casefold()
                if componente_normalizado.startswith("cpu"):
                    categorias_indisponiveis.add("CPU")
                elif componente_normalizado.startswith("gpu"):
                    categorias_indisponiveis.add("GPU")
                elif componente_normalizado.startswith("disco"):
                    categorias_indisponiveis.add("Discos")
                elif "memória" in componente_normalizado:
                    categorias_indisponiveis.add("RAM")
                elif "bateria" in componente_normalizado:
                    categorias_indisponiveis.add("Bateria")
                elif "ventoinha" in componente_normalizado:
                    categorias_indisponiveis.add("Ventoinhas")
                elif "placa" in componente_normalizado:
                    categorias_indisponiveis.add("PlacaMae")
                else:
                    categorias_indisponiveis.add("Plataforma")
            log_evento(
                "SENSOR_INDISPONIVEL",
                "categorias=" + ",".join(sorted(categorias_indisponiveis)),
            )
        log_evento(
            "SENSORES_ATUALIZADOS",
            (
                f"medidas_disponiveis={medidas_disponiveis};"
                f"medidas_indisponiveis={indisponiveis};"
                f"fontes={sum(1 for valor in fontes.values() if valor)};"
                f"duracao_ms={duracao_ms}"
            ),
        )
        return {
            "Sucesso": True,
            "Cancelada": False,
            "Mensagem": (
                f"Telemetria atualizada: {medidas_disponiveis} medida(s) disponível(is) "
                f"e {indisponiveis} não disponível(is)."
            ),
            "Componentes": medidas,
            "Fontes": fontes,
            "DuracaoMs": duracao_ms,
            "ColetadoEm": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "Limitacoes": [
                "Temperaturas de CPU/GPU e RPM só aparecem se o Windows/firmware as expuser com associação confiável.",
                "Não há limite térmico universal aplicado a zonas ACPI ou discos: as especificações variam por fabricante e a telemetria não afirma superaquecimento.",
                "Temperatura de disco é reaproveitada apenas da última Saúde de Armazenamento já concluída.",
                "Estados de uso e I/O são informativos; uma amostra isolada não substitui diagnóstico do fabricante.",
            ],
        }

    @staticmethod
    @_serializar_coleta_saude_armazenamento
    def obter_saude_armazenamento(
        progress_callback=None, cancel_callback=None
    ) -> Dict[str, Any]:
        """Consulta somente leitura a saúde/reliability dos discos visíveis.

        A consulta prioriza os objetos do módulo Storage do Windows e só usa
        'MSStorageDriver_FailurePredictStatus' quando a associação com o disco
        do sistema operacional é única. Não interpreta
        'MSStorageDriver_FailurePredictData': seus bytes são dependentes do
        fabricante e não devem ser transformados em diagnóstico genérico.

        Não solicita UAC, não grava em SMART e não altera disco, volume,
        firmware ou política de armazenamento.
        """

        def cancelada() -> bool:
            try:
                return bool(callable(cancel_callback) and cancel_callback())
            except Exception:
                return False

        def emitir(percentual: int, mensagem: str) -> None:
            if not callable(progress_callback):
                return
            try:
                progress_callback(max(0, min(100, int(percentual))), str(mensagem))
            except Exception:
                pass

        def texto(valor: Any) -> str:
            if valor is None:
                return ""
            if isinstance(valor, (list, tuple, set)):
                return ", ".join(
                    parte for parte in (texto(item) for item in valor) if parte
                )
            return str(valor).strip()

        def numero(valor: Any) -> Optional[float]:
            if valor is None or isinstance(valor, bool):
                return None
            try:
                convertido = float(valor)
                return None if convertido != convertido else convertido
            except (TypeError, ValueError):
                return None

        def booleano(valor: Any) -> Optional[bool]:
            if isinstance(valor, bool):
                return valor
            if valor is None:
                return None
            normalizado = texto(valor).casefold()
            if normalizado in {"true", "1", "sim", "yes"}:
                return True
            if normalizado in {"false", "0", "não", "nao", "no"}:
                return False
            return None

        def capacidade_legivel(valor: Any) -> str:
            tamanho = numero(valor)
            if tamanho is None or tamanho < 0:
                return "—"
            if tamanho >= 1000 ** 4:
                return f"{tamanho / (1000 ** 4):.2f} TB"
            if tamanho >= 1000 ** 3:
                return f"{tamanho / (1000 ** 3):.1f} GB"
            return f"{tamanho:.0f} B"

        def contagem_legivel(valor: Any, sufixo: str = "") -> str:
            quantidade = numero(valor)
            if quantidade is None or quantidade < 0:
                return "—"
            if quantidade.is_integer():
                return f"{int(quantidade)}{sufixo}"
            return f"{quantidade:.1f}{sufixo}"

        def temperatura_valida(valor: Any) -> Optional[float]:
            temperatura = numero(valor)
            # Zero é normalmente o valor padrão de driver sem sensor, não uma
            # temperatura física plausível. Não o exibimos como dado real.
            if temperatura is None or temperatura <= 0 or temperatura > 150:
                return None
            return temperatura

        def log_reliability(
            status: str, discos: int = 0, fonte: str = "Get-StorageReliabilityCounter",
            tipo: str = ""
        ) -> None:
            detalhes = (
                "SAUDE_ARMAZENAMENTO_RELIABILITY "
                f"fonte={fonte or 'Get-StorageReliabilityCounter'} "
                f"status={status} discos={max(0, int(discos))}"
            )
            if tipo:
                detalhes += f" tipo={tipo}"
            try:
                logger.info(detalhes)
            except Exception:
                pass

        def tipo_normalizado(
            media: str, barramento: str, modelo: str
        ) -> str:
            origem = " ".join((media, barramento, modelo)).casefold()
            media_normalizada = media.casefold()
            if "nvme" in origem:
                return "NVMe SSD"
            if "ssd" in media_normalizada or "solid state" in media_normalizada:
                return "SSD"
            if (
                "hdd" in media_normalizada
                or "hard disk" in media_normalizada
                or "fixed hard" in media_normalizada
            ):
                return "HDD"
            if "usb" in barramento.casefold():
                return "Unidade USB (tipo não informado)"
            return "Não informado"

        inicio = time.monotonic()
        if cancelada():
            log_reliability("cancelado", tipo="AntesDaConsulta")
            return {
                "Sucesso": False,
                "Cancelada": True,
                "Mensagem": "Análise de saúde de armazenamento cancelada.",
                "Discos": [],
            }

        emitir(5, "Consultando dados nativos de armazenamento...")

        # A consulta é propositalmente consolidada: reduz a quantidade de
        # subprocessos e mantém todas as operações em Get-* / Get-CimInstance.
        # Get-Disk é a base para mapear letras de unidade; Get-PhysicalDisk
        # enriquece o estado; Win32_DiskDrive complementa identificação; e
        # Get-StorageReliabilityCounter fornece apenas contadores que o
        # Windows/driver realmente expõe.
        script = r"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Texto($valor) {
    if ($null -eq $valor) { return $null }
    return [string]$valor
}

function TextoStatus($valor) {
    if ($null -eq $valor) { return $null }
    return (@($valor) | ForEach-Object { [string]$_ }) -join ', '
}

function NormalizarIdentificador($valor) {
    if ($null -eq $valor) { return '' }
    return (([string]$valor) -replace '[^A-Za-z0-9]', '').ToUpperInvariant()
}

function ContadoresDisponiveis($contador) {
    if ($null -eq $contador) { return $false }
    foreach ($nome in @(
        'Temperature', 'PowerOnHours', 'StartStopCycleCount', 'Wear',
        'ReadErrorsTotal', 'ReadErrorsUncorrected', 'WriteErrorsTotal',
        'WriteErrorsUncorrected', 'UnsafeShutdownCount', 'MediaErrors'
    )) {
        $propriedade = $contador.PSObject.Properties[$nome]
        if ($null -ne $propriedade -and $null -ne $propriedade.Value) {
            return $true
        }
    }
    return $false
}

function TipoErroReliability($erro) {
    if ($null -eq $erro) { return 'CommandFailed' }

    # CategoryInfo.Category é a evidência estruturada preferencial. Mantemos
    # também o texto completo de CategoryInfo porque algumas versões do
    # PowerShell/CIM o materializam de forma diferente.
    $categoria = ''
    $categoriaInfo = ''
    try {
        $categoriaInfo = [string]$erro.CategoryInfo
        if ($null -ne $erro.CategoryInfo) {
            $categoria = [string]$erro.CategoryInfo.Category
        }
    }
    catch {}

    $fullyQualifiedErrorId = [string]$erro.FullyQualifiedErrorId
    $tipoExcecao = [string]$erro.Exception.GetType().FullName
    $mensagemExcecao = [string]$erro.Exception.Message
    $textoErro = @(
        $categoria,
        $categoriaInfo,
        $fullyQualifiedErrorId,
        $tipoExcecao,
        $mensagemExcecao
    ) -join ' '

    # MI RESULT 2 é o código CIM padronizado para acesso negado. Uma
    # CimException isolada continua genérica; ela só entra aqui se vier
    # acompanhada de Category/FQID/código/mensagem que comprove permissão.
    $acessoNegado = (
        $categoria -match '(?i)^PermissionDenied$' -or
        $categoriaInfo -match '(?i)(?:^|[\s,:])PermissionDenied(?:$|[\s,:])' -or
        $fullyQualifiedErrorId -match '(?i)(?:^|[\s,:])PermissionDenied(?:$|[\s,:])' -or
        $textoErro -match '(?i)(?:^|[\s,:])AccessDenied(?:$|[\s,:])|(?:^|[\s,:])UnauthorizedAccess(?:Exception)?(?:$|[\s,:])|Access\s+is\s+denied|Acesso\s+negado|0x80070005' -or
        $textoErro -match '(?i)MI\s+RESULT\s+2(?:\b|,)' -or
        $mensagemExcecao -match '(?i)Acesso\s+a\s+um\s+recurso\s+CIM\s+n[aã]o\s+estava\s+dispon[ií]vel\s+para\s+o\s+cliente'
    )
    if ($acessoNegado) {
        return 'AccessDenied'
    }
    if ($textoErro -match '(?i)CommandNotFound|not recognized|não.*reconhecid') {
        return 'CmdletUnavailable'
    }
    if ($textoErro -match '(?i)timed out|timeout|tempo limite') {
        return 'Timeout'
    }
    return 'CommandFailed'
}

function TentarContadoresReliability($alvo, $origem) {
    $retorno = [ordered]@{
        Contadores = $null
        Status = 'vazio'
        Fonte = $origem
        TipoErro = $null
    }
    if ($null -eq $alvo) { return [PSCustomObject]$retorno }
    try {
        $contador = @(
            $alvo | Get-StorageReliabilityCounter -ErrorAction Stop |
                Select-Object -First 1
        )[0]
        $retorno.Contadores = $contador
        if (ContadoresDisponiveis $contador) {
            $retorno.Status = 'ok'
        }
        elseif ($null -ne $contador) {
            $retorno.TipoErro = 'ObjetoSemDados'
        }
        else {
            $retorno.TipoErro = 'RetornoVazio'
        }
    }
    catch {
        $retorno.Status = 'erro'
        $retorno.TipoErro = TipoErroReliability $_
    }
    return [PSCustomObject]$retorno
}

function ConsultarContadoresReliability($disco, $fisico, $mapeamentoFisico) {
    if (-not $script:cmdletReliabilityDisponivel) {
        return [PSCustomObject]@{
            Contadores = $null
            Status = 'cmdlet_indisponivel'
            Fonte = 'Get-StorageReliabilityCounter'
            TipoErro = 'CmdletUnavailable'
        }
    }

    # Mantém a consulta aprovada da 1C-E-R1 como primeira tentativa.
    $primeira = TentarContadoresReliability $disco 'Get-Disk'
    if ($primeira.Status -eq 'ok') { return $primeira }

    # Uma única segunda tentativa, pela associação PhysicalDisk nativa.
    if ($null -ne $fisico) {
        $segunda = TentarContadoresReliability $fisico 'Get-PhysicalDisk'
        if ($segunda.Status -eq 'ok') { return $segunda }
        if ($segunda.TipoErro -eq 'AccessDenied') {
            $segunda.Status = 'acesso_negado'
        }
        elseif ($segunda.TipoErro -eq 'Timeout') {
            $segunda.Status = 'timeout'
        }
        return $segunda
    }

    if ([string]$mapeamentoFisico -like 'ambiguo*') {
        $primeira.Status = 'mapeamento_ambiguo'
        $primeira.TipoErro = 'MappingAmbiguous'
    }
    elseif ([string]$mapeamentoFisico -like 'inconsistente*') {
        $primeira.Status = 'mapeamento_inconsistente'
        $primeira.TipoErro = 'MappingMismatch'
    }
    elseif ($primeira.TipoErro -eq 'AccessDenied') {
        $primeira.Status = 'acesso_negado'
    }
    elseif ($primeira.TipoErro -eq 'Timeout') {
        $primeira.Status = 'timeout'
    }
    return $primeira
}

$erros = @()
$discos = @()
$fisicos = @()
$wmiDiscos = @()
$statusPreditivos = @()
$cmdletReliabilityDisponivel = [bool](
    Get-Command Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
)

try { $discos = @(Get-Disk -ErrorAction Stop) }
catch { $erros += 'Get-Disk indisponível' }

try { $fisicos = @(Get-PhysicalDisk -ErrorAction Stop) }
catch { $erros += 'Get-PhysicalDisk indisponível' }

try { $wmiDiscos = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop) }
catch { $erros += 'Win32_DiskDrive indisponível' }

try {
    $statusPreditivos = @(
        Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop
    )
}
catch { $erros += 'Status preditivo SMART indisponível' }

$resultado = @()
foreach ($disco in $discos) {
    $numero = [int]$disco.Number
    $wmiCandidatos = @($wmiDiscos | Where-Object { [string]$_.Index -eq [string]$numero })
    $wmi = if ($wmiCandidatos.Count -eq 1) { $wmiCandidatos[0] } else { $null }

    $fisico = $null
    $mapeamentoFisico = 'ausente'
    $serialDisco = NormalizarIdentificador (Texto $disco.SerialNumber)
    $porDeviceId = @(
        $fisicos | Where-Object {
            $null -ne $_.DeviceId -and [string]$_.DeviceId -eq [string]$numero
        }
    )
    if ($porDeviceId.Count -eq 1) {
        $candidatoFisico = $porDeviceId[0]
        $serialCandidato = NormalizarIdentificador (Texto $candidatoFisico.SerialNumber)
        if (
            $serialDisco.Length -gt 3 -and $serialCandidato.Length -gt 3 -and
            $serialDisco -ne $serialCandidato
        ) {
            $mapeamentoFisico = 'inconsistente_deviceid_serial'
        }
        else {
            $fisico = $candidatoFisico
            $mapeamentoFisico = 'ok_deviceid'
        }
    }
    elseif ($porDeviceId.Count -gt 1) {
        $mapeamentoFisico = 'ambiguo_deviceid'
    }

    if ($null -eq $fisico) {
        if ($serialDisco.Length -gt 3) {
            $porSerial = @(
                $fisicos | Where-Object {
                    (NormalizarIdentificador (Texto $_.SerialNumber)) -eq $serialDisco
                }
            )
            if ($porSerial.Count -eq 1) {
                $fisico = $porSerial[0]
                $mapeamentoFisico = 'ok_serial'
            }
            elseif ($porSerial.Count -gt 1) {
                $mapeamentoFisico = 'ambiguo_serial'
            }
        }
    }

    $consultaReliability = ConsultarContadoresReliability $disco $fisico $mapeamentoFisico
    $contadores = $consultaReliability.Contadores

    $statusPreditivo = $null
    $statusPreditivoDisponivel = $false
    if ($null -ne $wmi -and -not [string]::IsNullOrWhiteSpace([string]$wmi.PNPDeviceID)) {
        $pnpNormalizado = NormalizarIdentificador $wmi.PNPDeviceID
        if ($pnpNormalizado.Length -gt 8) {
            $candidatos = @(
                $statusPreditivos | Where-Object {
                    $instancia = NormalizarIdentificador $_.InstanceName
                    $instancia.Length -gt 8 -and (
                        $instancia.Contains($pnpNormalizado) -or
                        $pnpNormalizado.Contains($instancia)
                    )
                }
            )
            # Sem correspondência única, o resultado é deixado indisponível
            # para não atribuir o SMART de um disco a outro disco idêntico.
            if ($candidatos.Count -eq 1) {
                $statusPreditivo = $candidatos[0]
                $statusPreditivoDisponivel = $true
            }
        }
    }

    $unidades = @()
    try {
        $particoes = @(Get-Partition -DiskNumber $numero -ErrorAction Stop)
        foreach ($particao in $particoes) {
            if ($particao.DriveLetter) {
                $unidades += ([string]$particao.DriveLetter + ':')
            }
        }
    }
    catch {}

    $modelo = Texto $disco.FriendlyName
    if ([string]::IsNullOrWhiteSpace($modelo) -and $null -ne $wmi) {
        $modelo = Texto $wmi.Model
    }
    if ([string]::IsNullOrWhiteSpace($modelo) -and $null -ne $fisico) {
        $modelo = Texto $fisico.FriendlyName
    }

    $resultado += [PSCustomObject]@{
        Numero = $numero
        Modelo = $modelo
        Fabricante = if ($null -ne $fisico) { Texto $fisico.Manufacturer } elseif ($null -ne $wmi) { Texto $wmi.Manufacturer } else { $null }
        Serial = if ($null -ne $fisico -and $fisico.SerialNumber) { Texto $fisico.SerialNumber } elseif ($null -ne $wmi -and $wmi.SerialNumber) { Texto $wmi.SerialNumber } else { Texto $disco.SerialNumber }
        Firmware = if ($null -ne $fisico -and $fisico.FirmwareVersion) { Texto $fisico.FirmwareVersion } elseif ($null -ne $wmi -and $wmi.FirmwareRevision) { Texto $wmi.FirmwareRevision } else { Texto $disco.FirmwareVersion }
        CapacidadeBytes = [Int64]$disco.Size
        MediaType = if ($null -ne $fisico -and $fisico.MediaType) { Texto $fisico.MediaType } else { Texto $disco.MediaType }
        BusType = if ($null -ne $fisico -and $fisico.BusType) { Texto $fisico.BusType } elseif ($disco.BusType) { Texto $disco.BusType } elseif ($null -ne $wmi) { Texto $wmi.InterfaceType } else { $null }
        HealthStatus = if ($null -ne $fisico -and $fisico.HealthStatus) { Texto $fisico.HealthStatus } else { Texto $disco.HealthStatus }
        OperationalStatus = if ($null -ne $fisico -and $fisico.OperationalStatus) { TextoStatus $fisico.OperationalStatus } else { TextoStatus $disco.OperationalStatus }
        TemperaturaC = if ($null -ne $contadores) { $contadores.Temperature } else { $null }
        HorasLigado = if ($null -ne $contadores) { $contadores.PowerOnHours } else { $null }
        PowerCycles = if ($null -ne $contadores) { $contadores.StartStopCycleCount } else { $null }
        Wear = if ($null -ne $contadores) { $contadores.Wear } else { $null }
        ReadErrors = if ($null -ne $contadores) { $contadores.ReadErrorsTotal } else { $null }
        ReadErrorsUncorrected = if ($null -ne $contadores) { $contadores.ReadErrorsUncorrected } else { $null }
        WriteErrors = if ($null -ne $contadores) { $contadores.WriteErrorsTotal } else { $null }
        WriteErrorsUncorrected = if ($null -ne $contadores) { $contadores.WriteErrorsUncorrected } else { $null }
        UnsafeShutdowns = if ($null -ne $contadores) { $contadores.UnsafeShutdownCount } else { $null }
        MediaErrors = if ($null -ne $contadores) { $contadores.MediaErrors } else { $null }
        ConfiabilidadeDisponivel = ContadoresDisponiveis $contadores
        ReliabilityStatus = Texto $consultaReliability.Status
        ReliabilityFonte = Texto $consultaReliability.Fonte
        ReliabilityErroTipo = Texto $consultaReliability.TipoErro
        MapeamentoFisico = $mapeamentoFisico
        StatusPreditivoDisponivel = [bool]$statusPreditivoDisponivel
        SmartAtivo = if ($null -ne $statusPreditivo) { [bool]$statusPreditivo.Active } else { $null }
        PredictiveFailure = if ($null -ne $statusPreditivo) { [bool]$statusPreditivo.PredictFailure } else { $null }
        Unidades = @($unidades)
    }
}

# Em controladoras/Storage Spaces o Windows pode expor somente
# Get-PhysicalDisk. Esse fallback mantém a identificação disponível sem
# inventar letras de unidade ou número de disco lógico.
if ($resultado.Count -eq 0 -and $fisicos.Count -gt 0) {
    foreach ($fisico in $fisicos) {
        $consultaReliability = ConsultarContadoresReliability $null $fisico 'somente_physicaldisk'
        $contadores = $consultaReliability.Contadores
        $resultado += [PSCustomObject]@{
            Numero = $null
            Modelo = Texto $fisico.FriendlyName
            Fabricante = Texto $fisico.Manufacturer
            Serial = Texto $fisico.SerialNumber
            Firmware = Texto $fisico.FirmwareVersion
            CapacidadeBytes = [Int64]$fisico.Size
            MediaType = Texto $fisico.MediaType
            BusType = Texto $fisico.BusType
            HealthStatus = Texto $fisico.HealthStatus
            OperationalStatus = TextoStatus $fisico.OperationalStatus
            TemperaturaC = if ($null -ne $contadores) { $contadores.Temperature } else { $null }
            HorasLigado = if ($null -ne $contadores) { $contadores.PowerOnHours } else { $null }
            PowerCycles = if ($null -ne $contadores) { $contadores.StartStopCycleCount } else { $null }
            Wear = if ($null -ne $contadores) { $contadores.Wear } else { $null }
            ReadErrors = if ($null -ne $contadores) { $contadores.ReadErrorsTotal } else { $null }
            ReadErrorsUncorrected = if ($null -ne $contadores) { $contadores.ReadErrorsUncorrected } else { $null }
            WriteErrors = if ($null -ne $contadores) { $contadores.WriteErrorsTotal } else { $null }
            WriteErrorsUncorrected = if ($null -ne $contadores) { $contadores.WriteErrorsUncorrected } else { $null }
            UnsafeShutdowns = if ($null -ne $contadores) { $contadores.UnsafeShutdownCount } else { $null }
            MediaErrors = if ($null -ne $contadores) { $contadores.MediaErrors } else { $null }
            ConfiabilidadeDisponivel = ContadoresDisponiveis $contadores
            ReliabilityStatus = Texto $consultaReliability.Status
            ReliabilityFonte = Texto $consultaReliability.Fonte
            ReliabilityErroTipo = Texto $consultaReliability.TipoErro
            MapeamentoFisico = 'somente_physicaldisk'
            StatusPreditivoDisponivel = $false
            SmartAtivo = $null
            PredictiveFailure = $null
            Unidades = @()
        }
    }
}

[PSCustomObject]@{
    Discos = @($resultado)
    Fontes = [PSCustomObject]@{
        GetDisk = [bool]($discos.Count -gt 0)
        GetPhysicalDisk = [bool]($fisicos.Count -gt 0)
        Win32DiskDrive = [bool]($wmiDiscos.Count -gt 0)
        StatusPreditivo = [bool]($statusPreditivos.Count -gt 0)
        ReliabilityCmdlet = [bool]$cmdletReliabilityDisponivel
    }
    Limitacoes = @($erros)
} | ConvertTo-Json -Depth 8 -Compress
"""

        try:
            resposta = executar_powershell(script, timeout=45)
            if cancelada():
                log_reliability("cancelado", tipo="AposConsulta")
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Análise de saúde de armazenamento cancelada.",
                    "Discos": [],
                }
            if resposta.returncode != 0 or not resposta.stdout.strip():
                raise RuntimeError("A consulta nativa de armazenamento não retornou JSON válido.")
            bruto = json.loads(resposta.stdout.strip())
            if not isinstance(bruto, dict):
                raise ValueError("Formato inesperado da consulta de armazenamento.")
        except Exception as exc:
            causa = getattr(exc, "__cause__", None)
            if isinstance(exc, subprocess.TimeoutExpired) or isinstance(
                causa, subprocess.TimeoutExpired
            ):
                status_falha = "timeout"
                tipo_falha = "TimeoutExpired"
            else:
                status_falha = "erro"
                tipo_falha = type(exc).__name__
            log_reliability(status_falha, tipo=tipo_falha)
            try:
                registrar_log(
                    "SISTEMA",
                    "SAUDE_ARMAZENAMENTO_FALHA",
                    f"tipo={type(exc).__name__}",
                )
            except Exception:
                pass
            try:
                logger.warning(
                    "SAUDE_ARMAZENAMENTO_FALHA | tipo=%s", type(exc).__name__
                )
            except Exception:
                pass
            return {
                "Sucesso": False,
                "Mensagem": (
                    "Não foi possível concluir a leitura nativa de saúde "
                    "dos discos. Consulte configurador_ti.log."
                ),
                "Discos": [],
            }

        itens_brutos = bruto.get("Discos") or []
        if isinstance(itens_brutos, dict):
            itens_brutos = [itens_brutos]
        elif not isinstance(itens_brutos, list):
            itens_brutos = []

        diagnosticos_reliability = {}
        for item_bruto in itens_brutos:
            if not isinstance(item_bruto, dict):
                continue
            status = texto(item_bruto.get("ReliabilityStatus"))
            if not status:
                status = (
                    "ok"
                    if bool(item_bruto.get("ConfiabilidadeDisponivel"))
                    else "vazio"
                )
            fonte = texto(item_bruto.get("ReliabilityFonte")) or (
                "Get-StorageReliabilityCounter"
            )
            tipo = texto(item_bruto.get("ReliabilityErroTipo"))
            chave = (status, fonte, tipo)
            diagnosticos_reliability[chave] = (
                diagnosticos_reliability.get(chave, 0) + 1
            )
        if not diagnosticos_reliability:
            log_reliability("vazio")
        else:
            for (status, fonte, tipo), quantidade in sorted(
                diagnosticos_reliability.items()
            ):
                log_reliability(status, quantidade, fonte, tipo)

        emitir(70, "Normalizando informações de confiabilidade...")
        discos_normalizados = []
        for item in itens_brutos:
            if cancelada():
                log_reliability("cancelado", tipo="DuranteNormalizacao")
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Análise de saúde de armazenamento cancelada.",
                    "Discos": [],
                }
            if not isinstance(item, dict):
                continue

            numero_disco = item.get("Numero")
            numero_texto = (
                str(int(numero_disco))
                if numero(numero_disco) is not None
                else "—"
            )
            modelo = texto(item.get("Modelo")) or (
                f"Disco {numero_texto}" if numero_texto != "—" else "Disco físico"
            )
            fabricante = texto(item.get("Fabricante")) or "—"
            serial = texto(item.get("Serial")) or "—"
            firmware = texto(item.get("Firmware")) or "—"
            media = texto(item.get("MediaType")) or "Não informado"
            barramento = texto(item.get("BusType")) or "Não informado"
            tipo = tipo_normalizado(media, barramento, modelo)
            health_status = texto(item.get("HealthStatus")) or "Não disponível"
            operational_status = texto(item.get("OperationalStatus")) or "Não disponível"
            unidades = [texto(unidade) for unidade in (item.get("Unidades") or [])]
            unidades = [unidade for unidade in unidades if unidade] or []

            temperatura = temperatura_valida(item.get("TemperaturaC"))
            horas_ligado = numero(item.get("HorasLigado"))
            power_cycles = numero(item.get("PowerCycles"))
            wear = numero(item.get("Wear"))
            read_errors = numero(item.get("ReadErrors"))
            read_uncorrected = numero(item.get("ReadErrorsUncorrected"))
            write_errors = numero(item.get("WriteErrors"))
            write_uncorrected = numero(item.get("WriteErrorsUncorrected"))
            unsafe_shutdowns = numero(item.get("UnsafeShutdowns"))
            media_errors = numero(item.get("MediaErrors"))
            predictive_failure = booleano(item.get("PredictiveFailure"))
            smart_ativo = booleano(item.get("SmartAtivo"))
            status_preditivo_disponivel = bool(item.get("StatusPreditivoDisponivel"))
            confiabilidade_disponivel = bool(item.get("ConfiabilidadeDisponivel"))
            reliability_status = texto(item.get("ReliabilityStatus")) or (
                "ok" if confiabilidade_disponivel else "vazio"
            )
            reliability_fonte = texto(item.get("ReliabilityFonte")) or (
                "Get-StorageReliabilityCounter"
            )
            reliability_erro_tipo = texto(item.get("ReliabilityErroTipo"))
            mapeamento_fisico = texto(item.get("MapeamentoFisico")) or "não informado"

            health_normalizado = health_status.casefold()
            operacional_normalizado = operational_status.casefold()
            motivos = []
            critico = False
            atencao = False

            if predictive_failure is True:
                critico = True
                motivos.append("O Windows reportou falha preditiva para este disco.")
            if "unhealthy" in health_normalizado or "unhealthy" in operacional_normalizado:
                critico = True
                motivos.append("O Windows reportou estado não saudável.")
            if temperatura is not None:
                if temperatura >= 70:
                    critico = True
                    motivos.append(
                        f"Temperatura elevada reportada: {temperatura:.0f} °C."
                    )
                elif temperatura >= 60:
                    atencao = True
                    motivos.append(
                        f"Temperatura de atenção reportada: {temperatura:.0f} °C."
                    )
            if (read_uncorrected or 0) > 0 or (write_uncorrected or 0) > 0:
                atencao = True
                motivos.append("Há erros de leitura/gravação não corrigidos reportados.")
            if (media_errors or 0) > 0:
                atencao = True
                motivos.append("Há erros de mídia/dados reportados pelo controlador.")
            if "warning" in health_normalizado or "warning" in operacional_normalizado:
                atencao = True
                motivos.append("O Windows reportou estado de atenção.")
            if (
                operational_status != "Não disponível"
                and not any(
                    termo in operacional_normalizado
                    for termo in ("ok", "online", "healthy", "unknown")
                )
            ):
                atencao = True
                motivos.append(
                    f"Estado operacional informado pelo Windows: {operational_status}."
                )

            evidencia_confiabilidade = (
                confiabilidade_disponivel
                or (status_preditivo_disponivel and smart_ativo is True)
            )
            if critico:
                saude = "Crítico"
            elif atencao:
                saude = "Atenção"
            elif "healthy" in health_normalizado and evidencia_confiabilidade:
                saude = "Saudável"
                motivos.append(
                    "O Windows reportou Healthy com fonte de confiabilidade sem alerta."
                )
            elif (
                health_status == "Não disponível"
                and not confiabilidade_disponivel
                and not status_preditivo_disponivel
            ):
                saude = "Não disponível"
                motivos.append(
                    "O Windows não expôs status de saúde ou contadores confiáveis."
                )
            else:
                saude = "Indeterminado"
                if "healthy" in health_normalizado and not evidencia_confiabilidade:
                    motivos.append(
                        "HealthStatus foi reportado, mas SMART/contadores de "
                        "confiabilidade não estavam disponíveis para confirmar a leitura."
                    )
                else:
                    motivos.append(
                        "Os dados disponíveis não permitem classificar a condição "
                        "física com segurança."
                    )

            if predictive_failure is True:
                smart_resumo = "Falha preditiva detectada"
            elif status_preditivo_disponivel and smart_ativo is False:
                smart_resumo = "Status preditivo inativo"
            elif status_preditivo_disponivel:
                smart_resumo = "Status preditivo disponível (sem falha reportada)"
            elif confiabilidade_disponivel:
                smart_resumo = "Contadores de confiabilidade disponíveis"
            else:
                smart_resumo = "Não disponível"

            limitacoes = []
            origem = " ".join((barramento, modelo)).casefold()
            if "usb" in origem:
                limitacoes.append(
                    "Dispositivos USB podem não repassar SMART ao Windows."
                )
            if "raid" in origem or "virtual" in origem:
                limitacoes.append(
                    "Controladora/armazenamento virtual pode ocultar dados por disco."
                )
            if not evidencia_confiabilidade:
                limitacoes.append(
                    "Não foram expostos SMART ou contadores de confiabilidade por este driver."
                )
                mensagens_reliability = {
                    "cmdlet_indisponivel": (
                        "O cmdlet nativo Get-StorageReliabilityCounter não está disponível."
                    ),
                    "acesso_negado": (
                        "Dados SMART/reliability avançados requerem privilégio "
                        "administrativo nesta máquina."
                    ),
                    "vazio": (
                        "A consulta nativa concluiu, mas retornou um objeto sem "
                        "contadores utilizáveis."
                    ),
                    "mapeamento_ambiguo": (
                        "A associação entre Disk e PhysicalDisk ficou ambígua; "
                        "nenhum contador foi atribuído por segurança."
                    ),
                    "mapeamento_inconsistente": (
                        "A associação entre Disk e PhysicalDisk apresentou "
                        "identificadores incompatíveis; nenhum contador foi "
                        "atribuído por segurança."
                    ),
                    "timeout": (
                        "A consulta de contadores excedeu o tempo disponível."
                    ),
                    "erro": (
                        "A consulta nativa de contadores falhou; consulte o log técnico."
                    ),
                }
                mensagem_reliability = mensagens_reliability.get(reliability_status)
                if mensagem_reliability:
                    limitacoes.append(mensagem_reliability)

            discos_normalizados.append(
                {
                    "Numero": numero_texto,
                    "Modelo": modelo,
                    "Fabricante": fabricante,
                    "Serial": serial,
                    "Firmware": firmware,
                    "Capacidade": capacidade_legivel(item.get("CapacidadeBytes")),
                    "Tipo": tipo,
                    "MediaType": media,
                    "BusType": barramento,
                    "HealthStatus": health_status,
                    "OperationalStatus": operational_status,
                    "Saude": saude,
                    "Temperatura": (
                        f"{temperatura:.0f} °C" if temperatura is not None else "—"
                    ),
                    "HorasLigado": contagem_legivel(horas_ligado, " h"),
                    "PowerCycles": contagem_legivel(power_cycles),
                    "Wear": (
                        contagem_legivel(wear, "%")
                        if wear is not None and 0 <= wear <= 100
                        else "—"
                    ),
                    "ReadErrors": contagem_legivel(read_errors),
                    "ReadErrorsUncorrected": contagem_legivel(read_uncorrected),
                    "WriteErrors": contagem_legivel(write_errors),
                    "WriteErrorsUncorrected": contagem_legivel(write_uncorrected),
                    "UnsafeShutdowns": contagem_legivel(unsafe_shutdowns),
                    "MediaErrors": contagem_legivel(media_errors),
                    "PredictiveFailure": (
                        "Sim"
                        if predictive_failure is True
                        else "Não"
                        if predictive_failure is False
                        else "Não disponível"
                    ),
                    "SMART": smart_resumo,
                    "ReliabilityStatus": reliability_status,
                    "ReliabilityFonte": reliability_fonte,
                    "ReliabilityErroTipo": reliability_erro_tipo or "—",
                    "MapeamentoFisico": mapeamento_fisico,
                    "RequerAdminReliability": reliability_status == "acesso_negado",
                    "Unidades": ", ".join(unidades) if unidades else "—",
                    "Motivos": motivos,
                    "Limitacoes": limitacoes,
                }
            )

        fontes = bruto.get("Fontes") if isinstance(bruto.get("Fontes"), dict) else {}
        limitacoes_brutas = bruto.get("Limitacoes") or []
        if isinstance(limitacoes_brutas, str):
            limitacoes_brutas = [limitacoes_brutas]
        elif not isinstance(limitacoes_brutas, list):
            limitacoes_brutas = []
        limitacoes_globais = [
            texto(limite) for limite in limitacoes_brutas if texto(limite)
        ]
        if not discos_normalizados:
            fontes_disponiveis = any(bool(valor) for valor in fontes.values())
            if not fontes_disponiveis and limitacoes_globais:
                try:
                    registrar_log(
                        "SISTEMA",
                        "SAUDE_ARMAZENAMENTO_FALHA",
                        "nenhuma fonte nativa disponível",
                    )
                except Exception:
                    pass
                return {
                    "Sucesso": False,
                    "Mensagem": (
                        "O Windows não disponibilizou fontes nativas de "
                        "armazenamento nesta estação. Consulte configurador_ti.log."
                    ),
                    "Discos": [],
                }
            mensagem = "Nenhum disco físico foi retornado pelo Windows."
        else:
            mensagem = (
                f"{len(discos_normalizados)} disco(s) analisado(s) em modo somente leitura."
            )

        requer_admin_reliability = any(
            bool(disco.get("RequerAdminReliability"))
            for disco in discos_normalizados
        )
        if requer_admin_reliability:
            mensagem += (
                " Dados SMART/reliability avançados requerem privilégio "
                "administrativo nesta máquina."
            )

        duracao_ms = int((time.monotonic() - inicio) * 1000)
        resumo_estados = ", ".join(
            f"{disco['Numero']}={disco['Saude']}" for disco in discos_normalizados
        ) or "sem discos"
        try:
            registrar_log(
                "SISTEMA",
                "SAUDE_ARMAZENAMENTO_COLETADA",
                (
                    f"discos={len(discos_normalizados)}; estados={resumo_estados}; "
                    f"duracao_ms={duracao_ms}"
                ),
            )
        except Exception:
            pass
        emitir(100, "Análise de saúde concluída")
        return {
            "Sucesso": True,
            "Mensagem": mensagem,
            "Discos": discos_normalizados,
            "Fontes": fontes,
            "Limitacoes": limitacoes_globais,
            "DuracaoMs": duracao_ms,
            "RequerAdminReliability": requer_admin_reliability,
            "ColetaElevada": False,
        }

    @staticmethod
    def obter_saude_armazenamento_elevada(
        progress_callback=None, cancel_callback=None
    ) -> Dict[str, Any]:
        """Solicita UAC somente para uma coleta Storage auxiliar e limitada."""

        def cancelada() -> bool:
            try:
                return bool(callable(cancel_callback) and cancel_callback())
            except Exception:
                return False

        def emitir(percentual: int, mensagem: str) -> None:
            if not callable(progress_callback):
                return
            try:
                progress_callback(max(0, min(100, int(percentual))), mensagem)
            except Exception:
                pass

        if not sys.platform.startswith("win"):
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": "A coleta SMART elevada está disponível somente no Windows.",
                "Discos": [],
            }
        if cancelada():
            registrar_log(
                "SISTEMA",
                "SAUDE_ARMAZENAMENTO_ELEVADA_CANCELADA",
                "etapa=antes_uac",
            )
            return {
                "Sucesso": False,
                "Cancelada": True,
                "Mensagem": "Coleta avançada cancelada antes da solicitação UAC.",
                "Discos": [],
            }

        registrar_log(
            "SISTEMA",
            "SAUDE_ARMAZENAMENTO_ELEVADA_SOLICITADA",
            "origem=acao_explicita;escopo=reliability",
        )
        emitir(5, "Preparando coleta avançada protegida...")

        pasta_coleta = None
        caminho_resultado = None
        try:
            raiz = _raiz_temporaria_saude_armazenamento_elevada()
            raiz.mkdir(parents=True, exist_ok=True)
            restringir_acl_arquivo(str(raiz))
            pasta_coleta = Path(
                tempfile.mkdtemp(prefix="coleta_", dir=str(raiz))
            )
            restringir_acl_arquivo(str(pasta_coleta))
            descritor, nome_resultado = tempfile.mkstemp(
                prefix="resultado_", suffix=".json", dir=str(pasta_coleta)
            )
            os.close(descritor)
            caminho_resultado = Path(nome_resultado)
            restringir_acl_arquivo(str(caminho_resultado))
            _validar_destino_saude_armazenamento_elevada(caminho_resultado)

            nonce = secrets.token_urlsafe(32)
            argumentos_modo = [
                MODO_SAUDE_ARMAZENAMENTO_ELEVADA,
                ARG_RESULTADO_SAUDE_ELEVADA,
                str(caminho_resultado),
                ARG_NONCE_SAUDE_ELEVADA,
                nonce,
            ]
            if getattr(sys, "frozen", False):
                executavel = str(Path(sys.executable).resolve())
                argumentos_processo = argumentos_modo
            else:
                executavel = _executavel_reinicio_gui()
                argumentos_processo = [str(Path(__file__).resolve()), *argumentos_modo]

            emitir(15, "Aguardando autorização do Windows...")
            processo = executar_auxiliar_elevado_aguardando(
                executavel,
                argumentos_processo,
                str(DIRETORIO_BASE),
                timeout=90,
                cancel_callback=cancel_callback,
            )
            status = str(processo.get("Status") or "erro")
            if status == "uac_cancelado":
                registrar_log(
                    "SISTEMA",
                    "SAUDE_ARMAZENAMENTO_ELEVADA_CANCELADA",
                    "etapa=uac",
                )
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "UacCancelado": True,
                    "Mensagem": (
                        "UAC cancelado. Os dados básicos já coletados foram preservados."
                    ),
                    "Discos": [],
                }
            if status == "cancelado":
                registrar_log(
                    "SISTEMA",
                    "SAUDE_ARMAZENAMENTO_ELEVADA_CANCELADA",
                    "etapa=execucao",
                )
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Coleta avançada cancelada.",
                    "Discos": [],
                }
            if status == "timeout":
                raise TimeoutError("O auxiliar elevado excedeu 90 segundos.")
            if status != "ok":
                raise RuntimeError(
                    "Não foi possível iniciar o auxiliar elevado "
                    f"({processo.get('Tipo') or status})."
                )
            if int(processo.get("CodigoSaida", -1)) != 0:
                raise RuntimeError(
                    "O auxiliar elevado terminou sem entregar um resultado válido."
                )
            if cancelada():
                registrar_log(
                    "SISTEMA",
                    "SAUDE_ARMAZENAMENTO_ELEVADA_CANCELADA",
                    "etapa=apos_execucao",
                )
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Coleta avançada cancelada.",
                    "Discos": [],
                }

            emitir(80, "Validando resultado da coleta elevada...")
            caminho_validado = _validar_destino_saude_armazenamento_elevada(
                caminho_resultado
            )
            tamanho = caminho_validado.stat().st_size
            if tamanho <= 0 or tamanho > 4 * 1024 * 1024:
                raise ValueError("Arquivo de resultado ausente, vazio ou excessivo.")
            with caminho_validado.open("r", encoding="utf-8") as arquivo:
                envelope = json.load(arquivo)
            resultado = _validar_envelope_saude_armazenamento_elevada(
                envelope, nonce
            )
            resultado = dict(resultado)
            resultado["ColetaElevada"] = True
            discos = resultado.get("Discos") or []
            if not resultado.get("Sucesso") or not discos:
                tipo = "ColetaSemDiscos" if not discos else "ColetaNativaFalhou"
                registrar_log(
                    "SISTEMA",
                    "SAUDE_ARMAZENAMENTO_ELEVADA_FALHOU",
                    f"tipo={tipo}",
                )
                resultado.setdefault(
                    "Mensagem",
                    "A coleta elevada não retornou dados de disco utilizáveis.",
                )
                return resultado

            reliability_ok = sum(
                1
                for disco in discos
                if isinstance(disco, dict)
                and disco.get("ReliabilityStatus") == "ok"
            )
            resultado["Mensagem"] = (
                f"Coleta avançada concluída: {len(discos)} disco(s), "
                f"reliability disponível em {reliability_ok}."
            )
            registrar_log(
                "SISTEMA",
                "SAUDE_ARMAZENAMENTO_ELEVADA_OK",
                f"discos={len(discos)};reliability_ok={reliability_ok}",
            )
            emitir(100, "Coleta avançada concluída")
            return resultado
        except Exception as exc:
            registrar_log(
                "SISTEMA",
                "SAUDE_ARMAZENAMENTO_ELEVADA_FALHOU",
                f"tipo={type(exc).__name__}",
            )
            try:
                logger.exception("Falha na coleta elevada de saúde de armazenamento")
            except Exception:
                pass
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": (
                    "Não foi possível concluir a coleta SMART elevada. "
                    "Os dados básicos anteriores foram preservados; consulte o log."
                ),
                "Discos": [],
                "TipoFalha": type(exc).__name__,
            }
        finally:
            falhas_cleanup = []
            if caminho_resultado is not None:
                try:
                    caminho_resultado.unlink(missing_ok=True)
                except Exception as exc:
                    falhas_cleanup.append(type(exc).__name__)
            if pasta_coleta is not None:
                try:
                    pasta_coleta.rmdir()
                except Exception as exc:
                    falhas_cleanup.append(type(exc).__name__)
            if falhas_cleanup:
                try:
                    logger.warning(
                        "SAUDE_ARMAZENAMENTO_ELEVADA_CLEANUP status=parcial tipos=%s",
                        ",".join(falhas_cleanup),
                    )
                except Exception:
                    pass

    @staticmethod
    def consolidar_planos_energia_visual(
        planos: Any,
    ) -> List[Dict[str, Any]]:
        """Consolida somente clones visuais inequívocos de planos padrão.

        A identidade técnica do plano permanece no GUID do representante. Não
        há remoção nem alteração de esquemas: nomes com qualquer evidência
        adicional de customização/OEM/corporação ficam fora desta consolidação.
        """
        aliases_padrao = {
            "equilibrado": "Equilibrado",
            "balanced": "Equilibrado",
            "alto desempenho": "Alto desempenho",
            "high performance": "Alto desempenho",
            "economia de energia": "Economia de energia",
            "power saver": "Economia de energia",
        }

        def texto_normalizado(valor: Any) -> str:
            texto = normalizar_texto_console(str(valor or ""))
            return re.sub(r"\s+", " ", texto).strip().casefold()

        def esta_ativo(plano: Dict[str, Any]) -> bool:
            return bool(
                plano.get("ativo")
                or plano.get("Ativo")
                or plano.get("active")
            )

        if isinstance(planos, dict):
            planos = [planos]
        if not isinstance(planos, (list, tuple)):
            return []

        # Primeiro, combina repetições textuais do mesmo GUID sem perder a
        # marca ativa. Depois, somente nomes padrão exatos são consolidados.
        por_guid: List[Dict[str, Any]] = []
        indices_por_guid: Dict[str, int] = {}
        for plano_bruto in planos:
            if not isinstance(plano_bruto, dict):
                continue
            plano = dict(plano_bruto)
            guid = str(plano.get("guid", plano.get("GUID", ""))).strip().casefold()
            if guid and guid in indices_por_guid:
                existente = por_guid[indices_por_guid[guid]]
                existente["ativo"] = esta_ativo(existente) or esta_ativo(plano)
                continue
            if guid:
                indices_por_guid[guid] = len(por_guid)
            por_guid.append(plano)

        consolidados: List[Dict[str, Any]] = []
        indices_padrao: Dict[str, int] = {}
        for plano in por_guid:
            nome_original = plano.get("nome", plano.get("Nome", plano.get("name", "Plano")))
            nome_padrao = aliases_padrao.get(texto_normalizado(nome_original))
            if not nome_padrao:
                # Nome customizado/OEM/corporativo ou não reconhecido: mantém
                # a instância distinta, ainda que coincida textualmente.
                consolidados.append(plano)
                continue
            plano["nome"] = nome_padrao
            chave = nome_padrao.casefold()
            if chave not in indices_padrao:
                indices_padrao[chave] = len(consolidados)
                consolidados.append(plano)
                continue
            indice_existente = indices_padrao[chave]
            existente = consolidados[indice_existente]
            # Preferência explícita: plano ativo; na ausência dele, primeiro
            # da ordem de `powercfg /L`, preservando estabilidade visual.
            if esta_ativo(plano) and not esta_ativo(existente):
                consolidados[indice_existente] = plano

        return consolidados

    @staticmethod
    def obter_planos_energia() -> Tuple[bool, List[Dict[str, str]], str]:
        """Lista todos os planos disponíveis e recria os planos padrão ausentes."""
        try:
            padroes = [
                ("381b4222-f694-41f0-9685-ff5bb260df2e", "Equilibrado"),
                ("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "Alto desempenho"),
                ("a1841308-3541-4fab-bc81-f71556f20b4a", "Economia de energia"),
            ]

            # Em algumas instalações do Windows apenas o plano ativo fica visível.
            # Recria os planos padrão ausentes sem alterar o plano atualmente ativo.
            bruto = subprocess.run(["powercfg", "/L"], capture_output=True, text=False, timeout=15)
            saida = ""
            for codec in ("utf-8", "cp850", "cp1252", "latin-1"):
                try:
                    saida = bruto.stdout.decode(codec)
                    break
                except UnicodeDecodeError:
                    continue
            if not saida:
                saida = bruto.stdout.decode("utf-8", errors="replace")

            # ``/duplicatescheme`` devolve um GUID novo. Portanto, conferir
            # apenas o GUID canônico do plano-padrão faria a mesma rotina
            # recriar cópias a cada consulta posterior. A presença é avaliada
            # pelo nome normalizado do esquema já listado; a deduplicação da
            # resposta final continua sendo feita pelo GUID real.
            nomes_padrao = {
                "Equilibrado": {"equilibrado", "balanced"},
                "Alto desempenho": {"alto desempenho", "high performance"},
                "Economia de energia": {"economia de energia", "power saver"},
            }
            nomes_existentes = set()
            for linha in saida.splitlines():
                correspondencia = re.search(
                    r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}",
                    linha,
                )
                if not correspondencia:
                    continue
                resto = linha[correspondencia.end():].strip()
                nome_match = re.search(r"\((.*?)\)", resto)
                nome = nome_match.group(1).strip() if nome_match else resto.replace("*", "").strip()
                if nome:
                    nomes_existentes.add(normalizar_texto_console(nome).casefold())

            for guid, nome_padrao in padroes:
                aliases = nomes_padrao.get(nome_padrao, {nome_padrao.casefold()})
                if not any(alias in nomes_existentes for alias in aliases):
                    subprocess.run(["powercfg", "/duplicatescheme", guid], capture_output=True, timeout=15)

            bruto = subprocess.run(["powercfg", "/L"], capture_output=True, text=False, timeout=15)
            if bruto.returncode != 0:
                erro = bruto.stderr.decode("cp850", errors="replace") if bruto.stderr else "Não foi possível consultar os planos de energia."
                return False, [], normalizar_texto_console(erro).strip()

            for codec in ("utf-8", "cp850", "cp1252", "latin-1"):
                try:
                    texto = bruto.stdout.decode(codec)
                    break
                except UnicodeDecodeError:
                    texto = ""
            if not texto:
                texto = bruto.stdout.decode("utf-8", errors="replace")

            planos = []
            indices_por_guid = {}
            for linha in texto.splitlines():
                m = re.search(r"([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})", linha)
                if not m:
                    continue
                guid = m.group(1)
                resto = linha[m.end():].strip()
                nome_match = re.search(r"\((.*?)\)", resto)
                nome = nome_match.group(1).strip() if nome_match else resto.replace("*", "").strip()
                if not nome:
                    nome = next((nome_padrao for guid_padrao, nome_padrao in padroes if guid.lower() == guid_padrao.lower()), guid)
                chave = guid.lower()
                if chave in indices_por_guid:
                    # Uma repetição textual do mesmo GUID não representa um
                    # novo plano. Mantemos a primeira posição e não perdemos
                    # a marca de plano ativo, se ela vier em outra linha.
                    planos[indices_por_guid[chave]]["ativo"] |= "*" in linha
                    continue
                indices_por_guid[chave] = len(planos)
                planos.append({"guid": guid, "nome": normalizar_texto_console(nome), "ativo": "*" in linha})

            return True, ModuloSistema.consolidar_planos_energia_visual(planos), "OK"
        except Exception as e:
            logger.error(f"Erro ao consultar planos de energia: {e}")
            return False, [], str(e)

    @staticmethod
    def ajustar_plano_energia(guid: str) -> Tuple[bool, str]:
        try:
            r = subprocess.run(["powercfg", "/S", guid], capture_output=True, text=False, timeout=15)
            if r.returncode == 0:
                registrar_log("SISTEMA", "PLANO_ENERGIA", f"Plano de energia ativado: {guid}")
                return True, "Plano de energia alterado com sucesso."
            erro = (r.stderr or r.stdout or b"Falha ao alterar o plano de energia.").decode("cp850", errors="replace")
            return False, normalizar_texto_console(erro).strip()
        except Exception as e:
            logger.error(f"Erro ao alterar plano de energia: {e}")
            return False, str(e)

    @staticmethod
    def executar_windows_update(
        progress_callback=None, cancel_callback=None
    ) -> Tuple[bool, str]:
        """Pesquisa, baixa e instala cada atualização individualmente.

        Isso evita que uma atualização problemática bloqueie o lote inteiro.
        Também produz eventos PROGRESSO|... que a GUI transforma em barra visual.
        """
        if not verificar_admin():
            if (
                os.environ.get("CONFIGURADOR_TI_GUI_MODE") != "1"
                and not confirmar_acao(
                    "Deseja solicitar UAC somente para o Windows Update?", True
                )
            ):
                return False, "Operação cancelada antes da solicitação UAC."
            return _executar_windows_update_elevado_isolado(
                progress_callback=progress_callback,
                cancel_callback=cancel_callback,
            )

        script = r"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Emitir-Progresso([int]$Percentual, [string]$Mensagem) {
    Write-Output ("PROGRESSO|{0}|{1}" -f $Percentual, $Mensagem)
}

try {
    try { [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new() } catch {}

    Emitir-Progresso 5 "Conectando ao Windows Update..."
    $session=New-Object -ComObject Microsoft.Update.Session
    $searcher=$session.CreateUpdateSearcher()

    Emitir-Progresso 10 "Procurando atualizações disponíveis..."
    $result=$searcher.Search("IsInstalled=0 and IsHidden=0")
    $total=[int]$result.Updates.Count

    if($total -eq 0){
        Emitir-Progresso 100 "Nenhuma atualização pendente encontrada."
        Write-Output "RESULTADO|Nenhuma atualização pendente encontrada."
        exit 0
    }

    Write-Output ("INFO|Encontradas {0} atualização(ões), incluindo opcionais/drivers quando o Windows Update os disponibilizar." -f $total)

    $ok=0; $falha=0; $naoAlterada=0; $reboot=$false; $i=0

    foreach($u in $result.Updates){
        $i++
        $titulo=[string]$u.Title
        if([string]::IsNullOrWhiteSpace($titulo)){ $titulo="Atualização sem título" }
        if($titulo.Length -gt 120){ $titulo=$titulo.Substring(0,117)+"..." }

        $inicio=15+[int](($i-1)*80/$total)
        if($inicio -gt 94){$inicio=94}
        Emitir-Progresso $inicio ("Atualização {0}/{1}: {2}" -f $i,$total,$titulo)

        try {
            if(-not $u.EulaAccepted){
                try { $u.AcceptEula() } catch {
                    $falha++
                    Write-Output ("UPDATE_ERRO|{0}|{1}|EULA|{2}" -f $i,$titulo,$_.Exception.Message)
                    continue
                }
            }

            $one=New-Object -ComObject Microsoft.Update.UpdateColl
            [void]$one.Add($u)

            Emitir-Progresso ([Math]::Min(96,$inicio+8)) ("Baixando: {0}" -f $titulo)
            $downloader=$session.CreateUpdateDownloader()
            $downloader.Updates=$one
            $dr=$downloader.Download()

            if([int]$dr.ResultCode -eq 4){
                $falha++
                Write-Output ("UPDATE_ERRO|{0}|{1}|DOWNLOAD|Código={2}" -f $i,$titulo,$dr.ResultCode)
                continue
            }

            Emitir-Progresso ([Math]::Min(98,$inicio+12)) ("Instalando: {0}" -f $titulo)
            $installer=$session.CreateUpdateInstaller()
            $installer.Updates=$one
            $ir=$installer.Install()
            if($ir.RebootRequired){$reboot=$true}

            switch([int]$ir.ResultCode){
                2 {
                    $ok++
                    Write-Output ("UPDATE_OK|{0}|{1}|Instalado|Reiniciar={2}" -f $i,$titulo,$ir.RebootRequired)
                }
                3 {
                    $ok++
                    Write-Output ("UPDATE_OK|{0}|{1}|Instalado com observações|Reiniciar={2}" -f $i,$titulo,$ir.RebootRequired)
                }
                4 {
                    $falha++
                    Write-Output ("UPDATE_ERRO|{0}|{1}|INSTALACAO|Código={2}" -f $i,$titulo,$ir.ResultCode)
                }
                default {
                    $naoAlterada++
                    Write-Output ("UPDATE_INFO|{0}|{1}|Resultado={2}" -f $i,$titulo,$ir.ResultCode)
                }
            }
        }
        catch {
            $falha++
            Write-Output ("UPDATE_ERRO|{0}|{1}|EXCECAO|{2}" -f $i,$titulo,$_.Exception.Message)
        }

        $fim=15+[int]($i*80/$total)
        if($fim -gt 99){$fim=99}
        Emitir-Progresso $fim ("Processamento {0}/{1} concluído" -f $i,$total)
    }

    Emitir-Progresso 100 "Windows Update concluído."
    Write-Output ("RESULTADO|Total={0}; Instaladas/processadas={1}; Falhas={2}; Não alteradas={3}; Reinicialização necessária={4}" -f $total,$ok,$falha,$naoAlterada,$reboot)
}
catch {
    Write-Output ("ERRO_WU|" + $_.Exception.Message)
    exit 1
}
"""
        try:
            return executar_windows_update_com_progresso(
                script, progress_callback, cancel_callback
            )
        except Exception as e:
            logger.error(f"Erro no Windows Update: {e}")
            return False, str(e)

    @staticmethod
    def obter_versao_windows() -> Dict[str, Any]:
        script = r"""
$os=Get-CimInstance Win32_OperatingSystem
$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$display = if($cv.DisplayVersion){$cv.DisplayVersion}elseif($cv.ReleaseId){$cv.ReleaseId}else{'N/A'}
$build = if($cv.CurrentBuild){$cv.CurrentBuild}else{$os.BuildNumber}
$ubr = if($null -ne $cv.UBR){$cv.UBR}else{0}
[PSCustomObject]@{
    Nome=$cv.ProductName
    Edicao=$cv.EditionID
    DisplayVersion=$display
    BuildCompleta=("{0}.{1}" -f $build,$ubr)
    Build=$build
    VersaoTecnica=$os.Version
    Arquitetura=$os.OSArchitecture
    Instalacao=$cv.InstallationType
}|ConvertTo-Json -Compress
"""
        try:
            r=executar_powershell(script, timeout=20)
            return json.loads(r.stdout) if r.returncode==0 and r.stdout.strip() else {}
        except Exception as e:
            logger.error(f"Erro ao obter versão do Windows: {e}")
            return {}

    @staticmethod
    def renomear_computador(novo_nome: str) -> Tuple[bool, str]:
        """Renomeia o computador. O Windows aplicará completamente a alteração após reinicialização."""
        nome = novo_nome.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,14}", nome):
            return False, "Nome inválido. Use até 15 caracteres: letras, números e hífen; não comece com hífen."
        if not elevacao_sob_demanda("renomear o computador"):
            return False, "Operação cancelada (privilégio de administrador necessário)."
        try:
            atual = os.environ.get("COMPUTERNAME", "")
            if nome.upper() == atual.upper():
                return False, "O computador já possui esse nome."
            res = executar_powershell(f"Rename-Computer -NewName '{escapar_ps_string(nome)}' -Force", timeout=30)
            if res.returncode != 0:
                detalhe = res.stderr.strip() or res.stdout.strip() or "Falha desconhecida ao renomear o computador."
                return False, detalhe
            registrar_log("SISTEMA", "RENOMEAR_COMPUTADOR", f"{atual} -> {nome}; reinicialização necessária")
            return True, f"Computador renomeado para '{nome}'. Reinicie o Windows para concluir a alteração."
        except Exception as e:
            logger.error(f"Erro ao renomear computador: {e}")
            return False, str(e)

    @staticmethod
    def abrir_gerenciador_tarefas() -> Tuple[bool, str]:
        """Gerenciador avançado sem psutil, baseado em PowerShell/CIM e ferramentas nativas."""
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox
        except Exception as exc:
            return False, f"O Tkinter não está disponível: {exc}"
        root=tk.Tk(); root.title("Configurador TI - Gerenciador de Tarefas"); root.geometry("1180x740"); root.minsize(950,600)
        status=tk.StringVar(value="Inicializando..."); filtro=tk.StringVar(); auto=tk.BooleanVar(value=True); intervalo=tk.StringVar(value="2")
        jobs={"update":None,"filter":None}; fechar={"v":False}
        nb=ttk.Notebook(root); nb.pack(fill="both",expand=True,padx=10,pady=10)
        tabs={n:ttk.Frame(nb,padding=8) for n in ("📋 Processos","📈 Desempenho","🚀 Inicialização","⚙️ Serviços","🔎 Detalhes")}
        for n,f in tabs.items(): nb.add(f,text=n)
        def psj(cmd,timeout=30):
            r=executar_powershell(cmd,timeout=timeout)
            if r.returncode: raise RuntimeError(r.stderr.strip() or r.stdout.strip() or "Falha no Windows")
            x=json.loads(r.stdout.strip() or "[]"); return x if isinstance(x,list) else [x]
        # processos
        pf=ttk.Frame(tabs["📋 Processos"]); pf.pack(fill="x"); ttk.Label(pf,text="Pesquisar:").pack(side="left"); ttk.Entry(pf,textvariable=filtro,width=40).pack(side="left",padx=6)
        cols=("PID","Nome","CPU","Memória","Handles")
        pt=ttk.Treeview(tabs["📋 Processos"],columns=cols,show="headings")
        for c,w in zip(cols,(80,380,90,140,100)): pt.heading(c,text=c); pt.column(c,width=w,anchor="center" if c!="Nome" else "w")
        pt.pack(fill="both",expand=True,pady=8)
        # desempenho
        pv={k:tk.StringVar(value="Carregando...") for k in ("CPU","RAM","DISCO","REDE")}; bars={}
        for k,t in (("CPU","Processador"),("RAM","Memória"),("DISCO","Discos"),("REDE","Rede")):
            box=ttk.LabelFrame(tabs["📈 Desempenho"],text=t,padding=10); box.pack(fill="x",pady=5); ttk.Label(box,textvariable=pv[k]).pack(anchor="w")
            if k in bars or k in ("CPU","RAM"): bars[k]=ttk.Progressbar(box,maximum=100); bars[k].pack(fill="x",pady=6)
        # inicializacao
        ic=("Nome","Comando","Local","Status"); it=ttk.Treeview(tabs["🚀 Inicialização"],columns=ic,show="headings")
        for c,w in zip(ic,(220,450,300,100)): it.heading(c,text=c); it.column(c,width=w)
        it.pack(fill="both",expand=True)
        # servicos
        sc=("Nome","Descrição","Status","Inicialização"); st=ttk.Treeview(tabs["⚙️ Serviços"],columns=sc,show="headings")
        for c,w in zip(sc,(200,450,130,150)): st.heading(c,text=c); st.column(c,width=w)
        st.pack(fill="both",expand=True)
        # detalhes
        dt=tk.Text(tabs["🔎 Detalhes"],font=("Consolas",10),wrap="word"); dt.pack(fill="both",expand=True)
        def carregar_processos():
            cmd="$ErrorActionPreference='Stop'; Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | ? {$_.IDProcess -gt 0 -and $_.Name -notin @('Idle','_Total')} | % {[pscustomobject]@{PID=[int]$_.IDProcess;Nome=$_.Name;CPU=[double]$_.PercentProcessorTime;Memoria=[int64]$_.WorkingSetPrivate;Handles=[int]$_.HandleCount}} | ConvertTo-Json -Depth 3 -Compress"
            dados=psj(cmd); f=filtro.get().lower().strip(); pt.delete(*pt.get_children())
            for x in sorted(dados,key=lambda z:z.get('Memoria',0),reverse=True):
                if f and f not in str(x.get('Nome','')).lower() and f not in str(x.get('PID','')): continue
                pt.insert('', 'end', values=(x.get('PID'),x.get('Nome'),f"{float(x.get('CPU',0)):.1f}%",f"{float(x.get('Memoria',0))/1048576:.1f} MB",x.get('Handles')))
        def carregar_desempenho():
            d=psj("$os=Get-CimInstance Win32_OperatingSystem;$cpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor|? Name -eq '_Total'|select -First 1;$p=Get-CimInstance Win32_Processor|select -First 1 Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed;$disks=Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|% {$_.DeviceID+': '+[math]::Round((1-($_.FreeSpace/$_.Size))*100)+'% usado'};[pscustomobject]@{CPU=$cpu.PercentProcessorTime;Total=[int64]$os.TotalVisibleMemorySize*1KB;Livre=[int64]$os.FreePhysicalMemory*1KB;Proc=$p;Discos=$disks}|ConvertTo-Json -Depth 4 -Compress")[0]
            cpu=float(d.get('CPU',0)); total=float(d.get('Total',0)); usada=max(0,total-float(d.get('Livre',0))); ram=usada/total*100 if total else 0; p=d.get('Proc') or {}
            bars['CPU']['value']=cpu; bars['RAM']['value']=ram; pv['CPU'].set(f"{p.get('Name','CPU')} | {cpu:.1f}% | {p.get('NumberOfCores','?')} núcleos | {p.get('NumberOfLogicalProcessors','?')} lógicos"); pv['RAM'].set(f"{ram:.1f}% | {usada/1024**3:.2f} de {total/1024**3:.2f} GB"); pv['DISCO'].set(' | '.join(d.get('Discos') or [])); pv['REDE'].set('Monitoramento disponível pelas interfaces do Windows')
        def carregar_ini():
            it.delete(*it.get_children()); cmd=r"$a=@();$paths=@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run');foreach($p in $paths){if(Test-Path $p){$q=Get-ItemProperty $p;$q.PSObject.Properties|? {$_.Name -notlike 'PS*'}|% {$a+=[pscustomobject]@{Nome=$_.Name;Comando=[string]$_.Value;Local=$p;Status='Ativado'}}}};$a|ConvertTo-Json -Compress"
            for x in psj(cmd): it.insert('', 'end', values=(x.get('Nome'),x.get('Comando'),x.get('Local'),x.get('Status')))
        def carregar_serv():
            st.delete(*st.get_children())
            for x in psj("Get-CimInstance Win32_Service|select Name,DisplayName,State,StartMode|sort DisplayName|ConvertTo-Json -Compress",40): st.insert('', 'end', values=(x.get('Name'),x.get('DisplayName'),x.get('State'),x.get('StartMode')))
        def detalhes(*_):
            sel=pt.selection()
            if not sel:return
            pid=int(pt.item(sel[0],'values')[0]); x=psj(f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}'|select ProcessId,Name,ExecutablePath,CommandLine,Priority,CreationDate|ConvertTo-Json -Compress")
            dt.delete('1.0','end'); dt.insert('end',json.dumps(x[0] if x else {},ensure_ascii=False,indent=2,default=str)); nb.select(tabs['🔎 Detalhes'])
        def matar(force=False):
            sel=pt.selection()
            if not sel:return messagebox.showwarning('Atenção','Selecione um processo.',parent=root)
            v=pt.item(sel[0],'values'); pid=int(v[0]); nome=v[1]
            if pid==os.getpid(): return messagebox.showwarning('Protegido','O Configurador não pode encerrar a si próprio.',parent=root)
            if not messagebox.askyesno('Confirmar',f'Encerrar {nome} (PID {pid})?',parent=root): return
            r=subprocess.run(['taskkill.exe','/PID',str(pid),'/T']+(['/F'] if force else []),capture_output=True)
            if r.returncode: messagebox.showerror('Erro',(r.stderr or r.stdout).decode('mbcs',errors='replace'),parent=root)
            else: registrar_log('SISTEMA','FINALIZAR_PROCESSO',f'{nome} PID {pid}'); atualizar()
        def serv(acao):
            sel=st.selection()
            if not sel:return messagebox.showwarning('Atenção','Selecione um serviço.',parent=root)
            nome=st.item(sel[0],'values')[0]; m={'start':'Start-Service','stop':'Stop-Service','restart':'Restart-Service'}[acao]; extra=' -Force' if acao!='start' else ''
            try:
                r=executar_powershell(f"{m} -Name '{escapar_ps_string(nome)}'{extra}",timeout=30)
                if r.returncode: raise RuntimeError(r.stderr.strip() or r.stdout.strip() or 'Falha no serviço')
                carregar_serv(); registrar_log('SISTEMA','SERVICO_'+acao.upper(),nome)
            except Exception as e: messagebox.showerror('Erro',str(e),parent=root)
        atualizando = {'v': False}
        def atualizar():
            if fechar['v'] or atualizando['v']:
                return
            atualizando['v'] = True
            try:
                if jobs.get('update') is not None:
                    try: root.after_cancel(jobs['update'])
                    except tk.TclError: pass
                    jobs['update'] = None
                carregar_processos(); carregar_desempenho()
                if not fechar['v']:
                    status.set(f"Atualizado: {datetime.now().strftime('%H:%M:%S')} | {len(pt.get_children())} processos")
            except Exception as e:
                if not fechar['v']: status.set(f'Erro: {e}')
                logger.error(f'Gerenciador: {e}')
            finally:
                atualizando['v'] = False
            if auto.get() and not fechar['v'] and root.winfo_exists():
                try:
                    jobs['update'] = root.after(max(1,int(intervalo.get() or 2))*1000, atualizar)
                except tk.TclError:
                    jobs['update'] = None
        bf=ttk.Frame(tabs['📋 Processos']); bf.pack(fill='x'); ttk.Button(bf,text='🔄 Atualizar',command=atualizar).pack(side='right',padx=3); ttk.Button(bf,text='❌ Encerrar',command=lambda:matar()).pack(side='right',padx=3); ttk.Button(bf,text='⚠️ Forçar',command=lambda:matar(True)).pack(side='right',padx=3)
        bs=ttk.Frame(tabs['⚙️ Serviços']); bs.pack(fill='x',pady=5); [ttk.Button(bs,text=t,command=lambda a=a:serv(a)).pack(side='left',padx=3) for t,a in [('▶ Iniciar','start'),('■ Parar','stop'),('🔄 Reiniciar','restart')]]; ttk.Button(bs,text='↻ Atualizar',command=carregar_serv).pack(side='left',padx=3)
        rod=ttk.Frame(root,padding=8); rod.pack(fill='x'); ttk.Label(rod,textvariable=status).pack(side='left'); ttk.Checkbutton(rod,text='Auto',variable=auto).pack(side='right')
        pt.bind('<Double-1>',detalhes); filtro.trace_add('write',lambda *_: atualizar())
        carregar_ini(); carregar_serv(); registrar_log('SISTEMA','GERENCIADOR_TAREFAS','Gerenciador avançado sem psutil'); atualizar()
        def onclose():
            # Cancela TODOS os callbacks pendentes antes de destruir a janela.
            # Isto evita o erro Tcl: "invalid command name ... atualizar".
            fechar['v'] = True
            auto.set(False)
            for chave, job_id in list(jobs.items()):
                if job_id is not None:
                    try:
                        root.after_cancel(job_id)
                    except tk.TclError:
                        pass
                    jobs[chave] = None
            try:
                root.update_idletasks()
            except tk.TclError:
                pass
            try:
                root.destroy()
            except tk.TclError:
                pass
        root.protocol('WM_DELETE_WINDOW', onclose)
        root.mainloop()
        return True,'Gerenciador de tarefas fechado.'

    @staticmethod
    def exibir_diagnostico_completo():
        print(f"\n{Cores.AZUL_CLARO}Coletando informações do sistema...{Cores.RESET}\n")
        dados = ModuloSistema.obter_informacoes_sistema()
        
        if not dados:
            print(f"{Cores.VERMELHO}❌ Não foi possível obter os dados do sistema.{Cores.RESET}")
            return
        
        # Cabeçalho
        print(f"{Cores.MAGENTA}{Cores.NEGRITO}{'═' * 60}{Cores.RESET}")
        print(f"{Cores.MAGENTA}{Cores.NEGRITO}  DIAGNÓSTICO COMPLETO DO SISTEMA{Cores.RESET}")
        print(f"{Cores.MAGENTA}{Cores.NEGRITO}{'═' * 60}{Cores.RESET}\n")
        
        # Informações básicas
        print(f"💻 {Cores.NEGRITO}Computador:{Cores.RESET} {dados.get('HostName', 'N/A')} ({dados.get('Usuario', 'N/A')})")
        print(f"🏢 {Cores.NEGRITO}Domínio:{Cores.RESET} {dados.get('Dominio', 'N/A')}")
        print(f"🪟 {Cores.NEGRITO}Sistema Operacional:{Cores.RESET} {Cores.CIANO}{dados.get('OS', 'N/A')}{Cores.RESET}")
        print(f"🔢 {Cores.NEGRITO}Versão:{Cores.RESET} {dados.get('VersaoOS', 'N/A')}")
        print(f"⚡ {Cores.NEGRITO}Processador:{Cores.RESET} {Cores.VERDE}{dados.get('CPU', 'N/A')}{Cores.RESET}")
        hw = ModuloSistema.obter_hardware_detalhado()
        if hw:
            print(f"   Fabricante: {hw.get('CPUFabricante','N/A')} | Núcleos: {hw.get('Nucleos','N/A')} | Lógicos: {hw.get('ProcessadoresLogicos','N/A')} | Clock máx.: {hw.get('ClockMaxMHz','N/A')} MHz")
        print(f"🧱 {Cores.NEGRITO}Placa-Mãe:{Cores.RESET} {dados.get('PlacaMae', 'N/A')}")
        print(f"🔌 {Cores.NEGRITO}BIOS:{Cores.RESET} {dados.get('BIOS', 'N/A')}")
        
        # Tempo de atividade
        try:
            boot_time = dados.get('BootTime')
            if boot_time:
                from datetime import datetime
                boot = datetime.fromisoformat(boot_time.replace('Z', '+00:00'))
                uptime = datetime.now() - boot.replace(tzinfo=None)
                dias = uptime.days
                horas, resto = divmod(uptime.seconds, 3600)
                minutos = resto // 60
                print(f"⏱️  {Cores.NEGRITO}Tempo de atividade:{Cores.RESET} {dias}d {horas}h {minutos}m")
        except:
            pass
        
        # Memória RAM
        ram_total = dados.get('RAMTotalGB', 0)
        ram_livre = dados.get('RAMLivreGB', 0)
        ram_usada = round(ram_total - ram_livre, 2)
        pct_ram = round((ram_usada / ram_total) * 100, 1) if ram_total > 0 else 0
        
        cor_ram = Cores.VERDE if pct_ram < 80 else (Cores.AMARELO if pct_ram < 90 else Cores.VERMELHO)
        barra_ram = '█' * int(pct_ram / 5) + '░' * (20 - int(pct_ram / 5))
        
        print(f"\n🧠 {Cores.NEGRITO}Memória RAM:{Cores.RESET}")
        print(f"   [{cor_ram}{barra_ram}{Cores.RESET}] {cor_ram}{pct_ram}%{Cores.RESET}")
        print(f"   Total: {ram_total} GB | Usada: {ram_usada} GB | Livre: {ram_livre} GB")
        
        if hw:
            modulos = hw.get('RAM', []) or []
            if isinstance(modulos, dict): modulos=[modulos]
            for i,m in enumerate(modulos,1):
                print(f"   Módulo {i}: {m.get('CapacidadeGB','?')} GB {m.get('Tipo','Desconhecido')} | {m.get('Fabricante','N/A')} | {m.get('VelocidadeMHz','?')} MHz | {m.get('Modelo','N/A')}")

        # Discos
        print(f"\n💾 {Cores.NEGRITO}Armazenamento Físico:{Cores.RESET}")
        discos = dados.get('DiscosFisicos', [])
        if isinstance(discos, dict):
            discos = [discos]
        for d in discos:
            tipo = d.get('MediaType', 'Desconhecido')
            health = d.get('HealthStatus', 'Unknown')
            cor_health = Cores.VERDE if health == 'Healthy' else Cores.VERMELHO
            print(f"   • {d.get('FriendlyName')} ({Cores.AMARELO}{tipo}{Cores.RESET}) - {d.get('SizeGB')} GB [{cor_health}{health}{Cores.RESET}]")
        if hw:
            hdiscos=hw.get('Discos',[]) or []
            if isinstance(hdiscos,dict): hdiscos=[hdiscos]
            for d in hdiscos:
                print(f"   Detalhe: {d.get('Nome','N/A')} | Interface: {d.get('Interface','N/A')} | Tipo: {d.get('Tipo','N/A')} | {d.get('TamanhoGB','?')} GB | Saúde: {d.get('Saude','N/A')}")
        
        # Partições
        print(f"\n📂 {Cores.NEGRITO}Volumes / Partições:{Cores.RESET}")
        vols = dados.get('Particoes', [])
        if isinstance(vols, dict):
            vols = [vols]
        for v in vols:
            letra = v.get('DriveLetter')
            total = v.get('SizeGB', 0)
            livre = v.get('FreeGB', 0)
            usado = v.get('UsedGB', round(total - livre, 1))
            pct = round((usado / total) * 100, 1) if total > 0 else 0
            cor_disc = Cores.VERDE if pct < 70 else (Cores.AMARELO if pct < 85 else Cores.VERMELHO)
            barra = '█' * int(pct / 5) + '░' * (20 - int(pct / 5))
            print(f"   [{letra}:] [{cor_disc}{barra}{Cores.RESET}] {cor_disc}{pct}%{Cores.RESET} | {usado}GB / {total}GB | Livre: {livre}GB")
        
        print(f"\n{Cores.MAGENTA}{Cores.NEGRITO}{'═' * 60}{Cores.RESET}")

    @staticmethod
    def gerar_diagnostico_completo_texto() -> str:
        """Mesma coleta de exibir_diagnostico_completo(), mas RETORNA o texto
        em vez de fazer print(). Existe porque exibir_diagnostico_completo()
        só imprime no console — e no app gráfico (--noconsole) não existe
        console nenhum pra receber esse texto, então o resultado nunca
        aparecia em lugar nenhum para quem usava a GUI. Esta versão devolve
        uma string simples (sem códigos de cor ANSI) para ser mostrada numa
        janela/diálogo da interface gráfica."""
        linhas: List[str] = []
        dados = ModuloSistema.obter_informacoes_sistema()
        if not dados:
            return "Não foi possível obter os dados do sistema."

        linhas.append("═" * 60)
        linhas.append("  DIAGNÓSTICO COMPLETO DO SISTEMA")
        linhas.append("═" * 60)
        linhas.append("")
        linhas.append(f"Computador: {dados.get('HostName', 'N/A')} ({dados.get('Usuario', 'N/A')})")
        linhas.append(f"Domínio: {dados.get('Dominio', 'N/A')}")
        linhas.append(f"Sistema Operacional: {dados.get('OS', 'N/A')}")
        linhas.append(f"Versão: {dados.get('VersaoOS', 'N/A')}")
        linhas.append(f"Processador: {dados.get('CPU', 'N/A')}")
        hw = ModuloSistema.obter_hardware_detalhado()
        if hw:
            linhas.append(f"   Fabricante: {hw.get('CPUFabricante','N/A')} | Núcleos: {hw.get('Nucleos','N/A')} | Lógicos: {hw.get('ProcessadoresLogicos','N/A')} | Clock máx.: {hw.get('ClockMaxMHz','N/A')} MHz")
        linhas.append(f"Placa-Mãe: {dados.get('PlacaMae', 'N/A')}")
        linhas.append(f"BIOS: {dados.get('BIOS', 'N/A')}")

        try:
            boot_time = dados.get('BootTime')
            if boot_time:
                boot = datetime.fromisoformat(boot_time.replace('Z', '+00:00'))
                uptime = datetime.now() - boot.replace(tzinfo=None)
                dias = uptime.days
                horas, resto = divmod(uptime.seconds, 3600)
                minutos = resto // 60
                linhas.append(f"Tempo de atividade: {dias}d {horas}h {minutos}m")
        except Exception:
            pass

        ram_total = dados.get('RAMTotalGB', 0)
        ram_livre = dados.get('RAMLivreGB', 0)
        ram_usada = round(ram_total - ram_livre, 2)
        pct_ram = round((ram_usada / ram_total) * 100, 1) if ram_total > 0 else 0
        barra_ram = '█' * int(pct_ram / 5) + '░' * (20 - int(pct_ram / 5))
        linhas.append("")
        linhas.append("Memória RAM:")
        linhas.append(f"   [{barra_ram}] {pct_ram}%")
        linhas.append(f"   Total: {ram_total} GB | Usada: {ram_usada} GB | Livre: {ram_livre} GB")
        if hw:
            modulos = hw.get('RAM', []) or []
            if isinstance(modulos, dict): modulos = [modulos]
            for i, m in enumerate(modulos, 1):
                linhas.append(f"   Módulo {i}: {m.get('CapacidadeGB','?')} GB {m.get('Tipo','Desconhecido')} | {m.get('Fabricante','N/A')} | {m.get('VelocidadeMHz','?')} MHz | {m.get('Modelo','N/A')}")

        linhas.append("")
        linhas.append("Armazenamento Físico:")
        discos = dados.get('DiscosFisicos', [])
        if isinstance(discos, dict): discos = [discos]
        for d in discos:
            linhas.append(f"   • {d.get('FriendlyName')} ({d.get('MediaType', 'Desconhecido')}) - {d.get('SizeGB')} GB [{d.get('HealthStatus', 'Unknown')}]")
        if hw:
            hdiscos = hw.get('Discos', []) or []
            if isinstance(hdiscos, dict): hdiscos = [hdiscos]
            for d in hdiscos:
                linhas.append(f"   Detalhe: {d.get('Nome','N/A')} | Interface: {d.get('Interface','N/A')} | Tipo: {d.get('Tipo','N/A')} | {d.get('TamanhoGB','?')} GB | Saúde: {d.get('Saude','N/A')}")

        linhas.append("")
        linhas.append("Volumes / Partições:")
        vols = dados.get('Particoes', [])
        if isinstance(vols, dict): vols = [vols]
        for v in vols:
            letra = v.get('DriveLetter')
            total = v.get('SizeGB', 0)
            livre = v.get('FreeGB', 0)
            usado = v.get('UsedGB', round(total - livre, 1))
            pct = round((usado / total) * 100, 1) if total > 0 else 0
            barra = '█' * int(pct / 5) + '░' * (20 - int(pct / 5))
            linhas.append(f"   [{letra}:] [{barra}] {pct}% | {usado}GB / {total}GB | Livre: {livre}GB")

        linhas.append("")
        linhas.append("═" * 60)
        return "\n".join(linhas)

    @staticmethod
    def _resolver_caminho_limpeza(caminho) -> Optional[Path]:
        """Normaliza um caminho sem exigir que o item ainda exista."""
        if not caminho:
            return None
        try:
            return Path(caminho).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError):
            return None

    @staticmethod
    def _caminho_esta_em_ou_sob(caminho, raiz) -> bool:
        """Confirma contenção após resolver links, junções e diferenças de caixa."""
        caminho_resolvido = ModuloSistema._resolver_caminho_limpeza(caminho)
        raiz_resolvida = ModuloSistema._resolver_caminho_limpeza(raiz)
        if caminho_resolvido is None or raiz_resolvida is None:
            return False
        try:
            caminho_texto = os.path.normcase(str(caminho_resolvido))
            raiz_texto = os.path.normcase(str(raiz_resolvida))
            caminho_comum = os.path.normcase(
                os.path.commonpath((caminho_texto, raiz_texto))
            )
            return caminho_comum == raiz_texto
        except (OSError, TypeError, ValueError):
            # Drives diferentes no Windows, ou um caminho inválido, nunca
            # constituem autorização para excluir o item.
            return False

    @staticmethod
    def _runtime_pyinstaller_ancestral(item, raiz) -> Optional[Path]:
        """Localiza uma árvore ``_MEI`` que contenha o item dentro da raiz.

        O prefixo é usado somente para PRESERVAR, nunca para autorizar uma
        exclusão. A contenção resolvida continua obrigatória, impedindo que um
        link ou uma junção com esse nome torne um caminho externo elegível.
        """
        raiz_resolvida = ModuloSistema._resolver_caminho_limpeza(raiz)
        if raiz_resolvida is None:
            return None
        try:
            caminho_lexico = Path(os.path.abspath(str(Path(item).expanduser())))
            relativo = caminho_lexico.relative_to(raiz_resolvida)
        except (OSError, RuntimeError, TypeError, ValueError):
            return None

        for indice, parte in enumerate(relativo.parts):
            if not parte.casefold().startswith("_mei"):
                continue
            candidato = raiz_resolvida.joinpath(*relativo.parts[:indice + 1])
            candidato_resolvido = ModuloSistema._resolver_caminho_limpeza(
                candidato
            )
            if candidato_resolvido is None:
                return None
            if not ModuloSistema._caminho_esta_em_ou_sob(
                candidato_resolvido, raiz_resolvida
            ):
                return None
            try:
                if candidato.is_dir() or candidato.is_symlink():
                    return candidato_resolvido
            except OSError:
                return None
        return None

    @staticmethod
    def _caminhos_protegidos_limpeza_temporarios(raizes) -> List[Path]:
        """Obtém caminhos da instância atual que não podem ser limpos.

        A proteção do runtime PyInstaller usa o valor real de ``sys._MEIPASS``;
        não depende do nome ``_MEI``. A política conservadora adicional para
        outras árvores ``_MEI`` é aplicada durante o percurso da limpeza.
        """
        raizes_resolvidas = [
            resolvida
            for raiz in raizes
            if (resolvida := ModuloSistema._resolver_caminho_limpeza(raiz))
            is not None
        ]
        protegidos = []
        chaves = set()

        def adicionar(caminho, permitir_raiz=False):
            resolvido = ModuloSistema._resolver_caminho_limpeza(caminho)
            if resolvido is None:
                return
            no_escopo = any(
                ModuloSistema._caminho_esta_em_ou_sob(resolvido, raiz)
                for raiz in raizes_resolvidas
            )
            if not no_escopo:
                return
            if not permitir_raiz and any(
                resolvido == raiz for raiz in raizes_resolvidas
            ):
                # Se o executável estiver diretamente na raiz de %TEMP%,
                # protege os arquivos conhecidos abaixo sem desativar toda a
                # limpeza desse diretório.
                return
            chave = os.path.normcase(str(resolvido))
            if chave not in chaves:
                chaves.add(chave)
                protegidos.append(resolvido)

        # O diretório exato da extração onefile atual. ``permitir_raiz`` é uma
        # defesa conservadora para configurações incomuns de runtime-tmpdir.
        adicionar(getattr(sys, "_MEIPASS", None), permitir_raiz=True)

        # Arquivos efetivamente usados pela instância. São protegidos apenas
        # quando estiverem dentro de uma das duas raízes já limpas pela versão
        # anterior; nenhum caminho de exclusão novo é criado aqui.
        for arquivo in (
            sys.executable,
            __file__,
            sys.argv[0] if sys.argv else None,
            ARQUIVO_LOG,
            ARQUIVO_PERFIS,
            ARQUIVO_CONFIG,
            ARQUIVO_CENTRAL,
        ):
            adicionar(arquivo)

        # Diretórios de dados da aplicação. Normalmente ficam fora de %TEMP%;
        # os fallbacks do log e de backups, porém, podem ficar sob essa raiz.
        diretorios_aplicacao = [
            DIRETORIO_BASE,
            Path(ARQUIVO_LOG).parent,
            PASTA_BACKUP,
            PASTA_COLETAS,
            Path(DIRETORIO_BASE) / ".ps_tmp",
        ]
        modulo_rede = globals().get("ModuloRede")
        gerenciador_backup = getattr(modulo_rede, "_backup_manager", None)
        if gerenciador_backup is not None:
            diretorios_aplicacao.append(
                getattr(gerenciador_backup, "pasta_backup", None)
            )
        for diretorio in diretorios_aplicacao:
            adicionar(diretorio)

        return protegidos

    @staticmethod
    def _item_temporario_elegivel(item, raiz, protegidos) -> bool:
        """Autoriza somente descendentes da raiz e fora de áreas protegidas."""
        item_resolvido = ModuloSistema._resolver_caminho_limpeza(item)
        raiz_resolvida = ModuloSistema._resolver_caminho_limpeza(raiz)
        if item_resolvido is None or raiz_resolvida is None:
            return False
        if item_resolvido == raiz_resolvida:
            return False
        if not ModuloSistema._caminho_esta_em_ou_sob(
            item_resolvido, raiz_resolvida
        ):
            return False
        return not any(
            ModuloSistema._caminho_esta_em_ou_sob(item_resolvido, protegido)
            for protegido in protegidos
        )

    @staticmethod
    def limpar_arquivos_temporarios() -> Tuple[int, str, int]:
        pastas = [os.environ.get('TEMP'), r"C:\Windows\Temp"]
        arquivos_removidos = 0
        falhas_controladas = 0
        raizes_processadas = 0

        raizes = []
        chaves_raizes = set()
        for pasta in pastas:
            raiz = ModuloSistema._resolver_caminho_limpeza(pasta)
            if raiz is None or not raiz.is_dir():
                continue
            chave = os.path.normcase(str(raiz))
            if chave not in chaves_raizes:
                chaves_raizes.add(chave)
                raizes.append(raiz)

        protegidos = ModuloSistema._caminhos_protegidos_limpeza_temporarios(
            raizes
        )
        runtime_atual = ModuloSistema._resolver_caminho_limpeza(
            getattr(sys, "_MEIPASS", None)
        )
        runtimes_pyinstaller_protegidos = {}
        for protegido in protegidos:
            chave_protegida = os.path.normcase(str(protegido))
            if (
                runtime_atual is not None
                and chave_protegida == os.path.normcase(str(runtime_atual))
            ):
                runtimes_pyinstaller_protegidos[chave_protegida] = protegido
                logger.info(
                    'RUNTIME_PYINSTALLER_PROTEGIDO | caminho="%s" | '
                    'motivo="atual" | pid="%s"',
                    _valor_log_instancia(protegido),
                    os.getpid(),
                )
            else:
                logger.info(
                    "Caminho da aplicação preservado na limpeza de temporários: %s",
                    protegido,
                )

        for raiz in raizes:
            diretorios = []
            try:
                for item in raiz.rglob('*'):
                    if not ModuloSistema._item_temporario_elegivel(
                        item, raiz, protegidos
                    ):
                        continue
                    runtime_pyinstaller = (
                        ModuloSistema._runtime_pyinstaller_ancestral(item, raiz)
                    )
                    if runtime_pyinstaller is not None:
                        chave_runtime = os.path.normcase(
                            str(runtime_pyinstaller)
                        )
                        if chave_runtime not in runtimes_pyinstaller_protegidos:
                            runtimes_pyinstaller_protegidos[chave_runtime] = (
                                runtime_pyinstaller
                            )
                            logger.info(
                                'RUNTIME_PYINSTALLER_PROTEGIDO | caminho="%s" | '
                                'motivo="politica_conservadora" | pid="%s"',
                                _valor_log_instancia(runtime_pyinstaller),
                                os.getpid(),
                            )
                        # Não tenta arquivos internos: um primeiro unlink bem
                        # sucedido poderia desmontar parcialmente um runtime
                        # antes de um lock posterior revelar que ele está ativo.
                        continue
                    try:
                        # Links são removidos como links, nunca seguidos para
                        # excluir um alvo. Links cujo destino escapa da raiz já
                        # foram rejeitados pela validação de elegibilidade.
                        if item.is_symlink() or item.is_file():
                            item.unlink()
                            arquivos_removidos += 1
                        elif item.is_dir():
                            diretorios.append(item)
                    except (PermissionError, OSError) as exc:
                        falhas_controladas += 1
                        logger.warning(
                            "Item temporário não removido (falha controlada): %s | %s",
                            item,
                            exc,
                        )

                # Um ancestral que contenha runtime protegido também deve
                # permanecer; tentar removê-lo produziria uma falsa falha por
                # "pasta não vazia" mesmo sem tocar no runtime.
                diretorios = [
                    diretorio
                    for diretorio in diretorios
                    if not any(
                        ModuloSistema._caminho_esta_em_ou_sob(
                            runtime, diretorio
                        )
                        for runtime in runtimes_pyinstaller_protegidos.values()
                    )
                ]

                # rglob normalmente encontra a pasta antes dos filhos. A
                # remoção em ordem inversa evita classificar uma pasta apenas
                # como "em uso" quando ela ainda continha filhos elegíveis.
                for diretorio in sorted(
                    diretorios,
                    key=lambda caminho: len(caminho.parts),
                    reverse=True,
                ):
                    try:
                        diretorio.rmdir()
                    except (PermissionError, OSError) as exc:
                        falhas_controladas += 1
                        logger.warning(
                            "Diretório temporário não removido (falha controlada): %s | %s",
                            diretorio,
                            exc,
                        )
                raizes_processadas += 1
            except Exception as exc:
                logger.warning("Erro ao percorrer %s: %s", raiz, exc)

        if not raizes_processadas:
            raise RuntimeError(
                "Nenhuma pasta temporária válida pôde ser processada. "
                "Consulte configurador_ti.log."
            )

        detalhes = (
            f"Arquivos removidos: {arquivos_removidos}; "
            f"falhas controladas: {falhas_controladas}; "
            f"caminhos protegidos: {len(protegidos)}; "
            "runtimes PyInstaller protegidos: "
            f"{len(runtimes_pyinstaller_protegidos)}"
        )
        registrar_log("SISTEMA", "LIMPEZA_TEMP", detalhes)
        mensagem = (
            f"Limpeza concluída. Aproximadamente {arquivos_removidos} "
            "arquivos removidos."
        )
        if runtimes_pyinstaller_protegidos:
            mensagem += (
                f" {len(runtimes_pyinstaller_protegidos)} runtime(s) "
                "PyInstaller foram preservados."
            )
        if falhas_controladas:
            mensagem += (
                f" {falhas_controladas} itens em uso ou protegidos não puderam "
                "ser removidos; consulte o log."
            )
        return 0, mensagem, arquivos_removidos

    # ------------------------------------------------------------------
    # Limpeza segura e saúde do sistema (Fase 1C-F)
    # ------------------------------------------------------------------
    # O fluxo abaixo não substitui a rotina legada acima, que foi preservada
    # por compatibilidade e contém a proteção específica aprovada para o
    # runtime PyInstaller. A interface nova usa exclusivamente estes métodos:
    # primeiro analisa, depois exige seleção/confirmação para excluir somente
    # itens dentro de categorias conhecidas e revalida cada item antes do unlink.

    @staticmethod
    def _cancelamento_manutencao_solicitado(cancel_callback) -> bool:
        try:
            return bool(callable(cancel_callback) and cancel_callback())
        except Exception:
            return False

    @staticmethod
    def _emitir_progresso_manutencao(progress_callback, percentual, mensagem):
        if not callable(progress_callback):
            return
        try:
            progress_callback(max(0, min(100, int(percentual))), str(mensagem))
        except Exception:
            pass

    @staticmethod
    def _formatar_bytes_manutencao(valor) -> str:
        try:
            tamanho = max(0, int(valor or 0))
        except (TypeError, ValueError):
            return "Não disponível"
        unidades = ("B", "KB", "MB", "GB", "TB")
        convertido = float(tamanho)
        for unidade in unidades:
            if convertido < 1024 or unidade == unidades[-1]:
                if unidade == "B":
                    return f"{int(convertido)} {unidade}"
                return f"{convertido:.1f} {unidade}"
            convertido /= 1024
        return f"{tamanho} B"

    @staticmethod
    def _categorias_limpeza_segura() -> List[Dict[str, Any]]:
        """Retorna somente categorias explícitas e conservadoras.

        Nenhuma categoria inclui Downloads, Documentos, Área de Trabalho,
        navegador, e-mail, OneDrive ou dados persistentes do Configurador.
        """
        temp_usuario = os.environ.get("TEMP") or os.environ.get("TMP")
        local_app_data = os.environ.get("LOCALAPPDATA")
        diretorio_windows = os.environ.get("WINDIR") or r"C:\Windows"
        explorer = (
            Path(local_app_data) / "Microsoft" / "Windows" / "Explorer"
            if local_app_data else None
        )
        return [
            {
                "Codigo": "temporarios_usuario",
                "Categoria": "Temporários do usuário",
                "Descricao": "Arquivos temporários do perfil atual (%TEMP%).",
                "Raizes": [temp_usuario] if temp_usuario else [],
                "Padroes": (),
                "Recursivo": True,
                "Avancada": False,
                "SelecionadaPadrao": True,
                "Tipo": "arquivos",
            },
            {
                "Codigo": "cache_miniaturas",
                "Categoria": "Cache de miniaturas",
                "Descricao": "Arquivos thumbcache do Windows; não inclui navegador.",
                "Raizes": [explorer] if explorer else [],
                "Padroes": ("thumbcache*.db",),
                "Recursivo": False,
                "Avancada": False,
                "SelecionadaPadrao": True,
                "Tipo": "arquivos",
            },
            {
                "Codigo": "temporarios_windows",
                "Categoria": "Temporários seguros do Windows",
                "Descricao": "C:\\Windows\\Temp. Pode conter arquivos em uso e fica desmarcado por padrão.",
                "Raizes": [Path(diretorio_windows) / "Temp"],
                "Padroes": (),
                "Recursivo": True,
                "Avancada": True,
                "SelecionadaPadrao": False,
                "Tipo": "arquivos",
            },
            {
                "Codigo": "lixeira",
                "Categoria": "Lixeira do usuário",
                "Descricao": "Esvazia a Lixeira somente após seleção e confirmação explícita.",
                "Raizes": [],
                "Padroes": (),
                "Recursivo": False,
                "Avancada": True,
                "SelecionadaPadrao": False,
                "Tipo": "lixeira",
            },
        ]

    @staticmethod
    def _selecionar_categorias_limpeza(categorias=None) -> List[Dict[str, Any]]:
        disponiveis = ModuloSistema._categorias_limpeza_segura()
        por_codigo = {item["Codigo"]: item for item in disponiveis}
        if categorias is None:
            return disponiveis
        if isinstance(categorias, str):
            categorias = [categorias]
        if not isinstance(categorias, (list, tuple, set)):
            return []
        selecionadas = []
        vistas = set()
        for codigo in categorias:
            codigo = str(codigo or "").strip()
            if codigo in por_codigo and codigo not in vistas:
                selecionadas.append(por_codigo[codigo])
                vistas.add(codigo)
        return selecionadas

    @staticmethod
    def _eh_ponto_reparse_limpeza(caminho) -> bool:
        """Detecta links, junctions e outros reparse points sem segui-los."""
        try:
            dados = os.lstat(caminho)
            atributos = getattr(dados, "st_file_attributes", 0)
            mascara_reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            return bool(os.path.islink(caminho) or atributos & mascara_reparse)
        except (OSError, TypeError, ValueError):
            # Um item que não pode ser inspecionado nunca é elegível para remoção.
            return True

    @staticmethod
    def _caminho_e_raiz_de_unidade(caminho) -> bool:
        try:
            absoluto = Path(os.path.abspath(str(caminho))).expanduser()
            ancora = Path(absoluto.anchor) if absoluto.anchor else None
            return bool(ancora and absoluto == ancora)
        except (OSError, RuntimeError, TypeError, ValueError):
            return True

    @staticmethod
    def _caminhos_protegidos_manutencao(raizes) -> List[Path]:
        """Lista dados da aplicação que jamais podem entrar na nova limpeza."""
        raizes_validas = [
            raiz for raiz in raizes
            if ModuloSistema._resolver_caminho_limpeza(raiz) is not None
        ]
        protegidos = []
        chaves = set()

        def adicionar(caminho):
            resolvido = ModuloSistema._resolver_caminho_limpeza(caminho)
            if resolvido is None:
                return
            if not any(
                ModuloSistema._caminho_esta_em_ou_sob(resolvido, raiz)
                for raiz in raizes_validas
            ):
                return
            chave = os.path.normcase(str(resolvido))
            if chave not in chaves:
                chaves.add(chave)
                protegidos.append(resolvido)

        # Mantém expressamente a proteção do runtime da instância atual da R3.
        candidatos = [
            DIRETORIO_BASE,
            getattr(sys, "_MEIPASS", None),
            sys.executable,
            __file__,
            sys.argv[0] if sys.argv else None,
            ARQUIVO_LOG,
            ARQUIVO_PERFIS,
            ARQUIVO_CONFIG,
            ARQUIVO_CENTRAL,
            PASTA_BACKUP,
            PASTA_COLETAS,
            Path(DIRETORIO_BASE) / ".ps_tmp",
            globals().get("ARQUIVO_EMPRESA"),
            globals().get("ARQUIVO_INVENTARIO"),
        ]
        try:
            candidatos.extend(
                handler.baseFilename
                for handler in getattr(logger, "handlers", [])
                if getattr(handler, "baseFilename", None)
            )
        except Exception:
            pass
        for candidato in candidatos:
            adicionar(candidato)

        # Reaproveita a lista conservadora já aprovada na R3 para os cenários
        # de log/backups em fallback dentro de TEMP, sem alterar sua política.
        try:
            for protegido in ModuloSistema._caminhos_protegidos_limpeza_temporarios(
                raizes_validas
            ):
                adicionar(protegido)
        except Exception:
            pass
        return protegidos

    @staticmethod
    def _raiz_limpeza_segura_elegivel(raiz, protegidos) -> Tuple[bool, str, Optional[Path]]:
        """Valida a raiz antes de varrer qualquer item nela contido."""
        if not raiz:
            return False, "Caminho não disponível.", None
        try:
            raiz_lexica = Path(os.path.abspath(str(raiz))).expanduser()
        except (OSError, RuntimeError, TypeError, ValueError):
            return False, "Caminho inválido.", None
        if ModuloSistema._caminho_e_raiz_de_unidade(raiz_lexica):
            return False, "Raiz de unidade protegida.", None
        if ModuloSistema._eh_ponto_reparse_limpeza(raiz_lexica):
            return False, "Link ou junction não é elegível.", None
        if not raiz_lexica.is_dir():
            return False, "Pasta não disponível.", None
        raiz_resolvida = ModuloSistema._resolver_caminho_limpeza(raiz_lexica)
        if raiz_resolvida is None:
            return False, "Não foi possível normalizar a pasta.", None
        if any(
            ModuloSistema._caminho_esta_em_ou_sob(raiz_resolvida, protegido)
            for protegido in protegidos
        ):
            return False, "Pasta da aplicação protegida.", None
        return True, "OK", raiz_resolvida

    @staticmethod
    def _item_limpeza_segura_elegivel(item, raiz, protegidos) -> Tuple[bool, str, Optional[Path]]:
        """Autoriza arquivo regular apenas se continuar dentro do escopo seguro."""
        try:
            raiz_lexica = Path(os.path.abspath(str(raiz))).expanduser()
            item_lexico = Path(os.path.abspath(str(item))).expanduser()
            relativo = item_lexico.relative_to(raiz_lexica)
        except (OSError, RuntimeError, TypeError, ValueError):
            return False, "fora_escopo", None

        # A nova limpeza não toca em árvores _MEI. A correção específica da R3
        # segue intacta na rotina legada; aqui a regra é somente preservativa.
        if any(parte.casefold().startswith("_mei") for parte in relativo.parts):
            return False, "runtime_pyinstaller", None
        if ModuloSistema._eh_ponto_reparse_limpeza(item_lexico):
            return False, "reparse", None
        item_resolvido = ModuloSistema._resolver_caminho_limpeza(item_lexico)
        raiz_resolvida = ModuloSistema._resolver_caminho_limpeza(raiz_lexica)
        if item_resolvido is None or raiz_resolvida is None:
            return False, "normalizacao", None
        if item_resolvido == raiz_resolvida or not ModuloSistema._caminho_esta_em_ou_sob(
            item_resolvido, raiz_resolvida
        ):
            return False, "fora_escopo", None
        if any(
            ModuloSistema._caminho_esta_em_ou_sob(item_resolvido, protegido)
            for protegido in protegidos
        ):
            return False, "protegido", None
        return True, "OK", item_resolvido

    @staticmethod
    def _varrer_categoria_limpeza_segura(
        categoria, protegidos, cancel_callback=None,
        processar_arquivo=None, processar_diretorio=None,
    ) -> Dict[str, Any]:
        """Varre sem seguir links e, opcionalmente, processa itens elegíveis.

        ``processar_arquivo`` recebe (Path, raiz, tamanho). A varredura nunca
        expõe nomes de arquivos no resultado ou nos logs informativos.
        """
        metricas = {
            "EncontradoBytes": 0,
            "EncontradoQuantidade": 0,
            "Ignorados": 0,
            "IgnoradosReparse": 0,
            "IgnoradosProtegidos": 0,
            "Falhas": 0,
            "RaizesProcessadas": 0,
            "Cancelada": False,
        }
        diretorios = []
        padroes = tuple(
            str(padrao).casefold() for padrao in categoria.get("Padroes", ())
        )

        for raiz_configurada in categoria.get("Raizes", []):
            if ModuloSistema._cancelamento_manutencao_solicitado(cancel_callback):
                metricas["Cancelada"] = True
                break
            ok, _, raiz = ModuloSistema._raiz_limpeza_segura_elegivel(
                raiz_configurada, protegidos
            )
            if not ok or raiz is None:
                continue
            metricas["RaizesProcessadas"] += 1
            pendentes = [raiz]

            while pendentes:
                if ModuloSistema._cancelamento_manutencao_solicitado(cancel_callback):
                    metricas["Cancelada"] = True
                    break
                atual = pendentes.pop()
                # Revalida cada diretório imediatamente antes de abri-lo. Isso
                # evita atravessar um link/junction que tenha surgido depois de
                # ele ter sido encontrado no diretório pai.
                if atual == raiz:
                    seguro, _, atual_validado = (
                        ModuloSistema._raiz_limpeza_segura_elegivel(
                            atual, protegidos
                        )
                    )
                else:
                    seguro, motivo_atual, atual_validado = (
                        ModuloSistema._item_limpeza_segura_elegivel(
                            atual, raiz, protegidos
                        )
                    )
                    if not seguro and motivo_atual in {
                        "protegido", "runtime_pyinstaller"
                    }:
                        metricas["IgnoradosProtegidos"] += 1
                    elif not seguro and motivo_atual == "reparse":
                        metricas["IgnoradosReparse"] += 1
                if not seguro or atual_validado is None:
                    metricas["Ignorados"] += 1
                    continue
                try:
                    with os.scandir(atual_validado) as entradas:
                        for entrada in entradas:
                            if ModuloSistema._cancelamento_manutencao_solicitado(
                                cancel_callback
                            ):
                                metricas["Cancelada"] = True
                                break
                            item = Path(entrada.path)
                            try:
                                dados = os.lstat(item)
                            except (OSError, TypeError, ValueError):
                                metricas["Falhas"] += 1
                                continue
                            if ModuloSistema._eh_ponto_reparse_limpeza(item):
                                metricas["Ignorados"] += 1
                                metricas["IgnoradosReparse"] += 1
                                continue
                            elegivel, motivo, resolvido = (
                                ModuloSistema._item_limpeza_segura_elegivel(
                                    item, raiz, protegidos
                                )
                            )
                            if not elegivel or resolvido is None:
                                metricas["Ignorados"] += 1
                                if motivo in {"protegido", "runtime_pyinstaller"}:
                                    metricas["IgnoradosProtegidos"] += 1
                                elif motivo == "reparse":
                                    metricas["IgnoradosReparse"] += 1
                                continue
                            if stat.S_ISDIR(dados.st_mode):
                                if categoria.get("Recursivo", False):
                                    pendentes.append(resolvido)
                                    if callable(processar_diretorio):
                                        diretorios.append((resolvido, raiz))
                                continue
                            if not stat.S_ISREG(dados.st_mode):
                                metricas["Ignorados"] += 1
                                continue
                            if padroes and not any(
                                fnmatch.fnmatch(
                                    resolvido.name.casefold(), padrao
                                ) for padrao in padroes
                            ):
                                continue
                            tamanho = max(0, int(dados.st_size or 0))
                            metricas["EncontradoBytes"] += tamanho
                            metricas["EncontradoQuantidade"] += 1
                            if callable(processar_arquivo):
                                try:
                                    processar_arquivo(resolvido, raiz, tamanho)
                                except Exception:
                                    metricas["Falhas"] += 1
                except (OSError, TypeError, ValueError):
                    metricas["Falhas"] += 1
                if metricas["Cancelada"]:
                    break
            if metricas["Cancelada"]:
                break

        if callable(processar_diretorio) and not metricas["Cancelada"]:
            for diretorio, raiz in sorted(
                diretorios, key=lambda dado: len(dado[0].parts), reverse=True
            ):
                if ModuloSistema._cancelamento_manutencao_solicitado(cancel_callback):
                    metricas["Cancelada"] = True
                    break
                try:
                    processar_diretorio(diretorio, raiz)
                except Exception:
                    metricas["Falhas"] += 1
        return metricas

    @staticmethod
    def _analisar_lixeira_segura(cancel_callback=None) -> Dict[str, Any]:
        """Consulta a Lixeira do usuário sem listar nomes ou excluir dados."""
        resultado = {
            "EncontradoBytes": 0,
            "EncontradoQuantidade": 0,
            "Ignorados": 0,
            "IgnoradosReparse": 0,
            "IgnoradosProtegidos": 0,
            "Falhas": 0,
            "RaizesProcessadas": 0,
            "Cancelada": False,
            "EstimativaDisponivel": False,
            "Status": "Não disponível",
        }
        if ModuloSistema._cancelamento_manutencao_solicitado(cancel_callback):
            resultado["Cancelada"] = True
            resultado["Status"] = "Cancelada"
            return resultado
        script = r"""
$ErrorActionPreference='Stop'
try {
    $shell = New-Object -ComObject Shell.Application
    $lixeira = $shell.Namespace(0xA)
    $itens = @($lixeira.Items())
    [Int64]$total = 0
    foreach ($item in $itens) {
        try { $total += [Int64]$item.Size } catch {}
    }
    [PSCustomObject]@{
        Disponivel = $true
        Quantidade = [int]$itens.Count
        TamanhoBytes = $total
    } | ConvertTo-Json -Compress
}
catch {
    [PSCustomObject]@{ Disponivel = $false } | ConvertTo-Json -Compress
}
"""
        try:
            resposta = executar_powershell(script, timeout=25)
            dados = json.loads(resposta.stdout.strip() or "{}")
            if resposta.returncode == 0 and isinstance(dados, dict) and dados.get("Disponivel"):
                resultado["EncontradoQuantidade"] = max(
                    0, int(dados.get("Quantidade") or 0)
                )
                resultado["EncontradoBytes"] = max(
                    0, int(dados.get("TamanhoBytes") or 0)
                )
                resultado["EstimativaDisponivel"] = True
                resultado["Status"] = "OK"
            else:
                resultado["Falhas"] = 1
        except Exception:
            resultado["Falhas"] = 1
        return resultado

    @staticmethod
    def _resultado_categoria_limpeza(categoria, metricas) -> Dict[str, Any]:
        tamanho = max(0, int(metricas.get("EncontradoBytes") or 0))
        if metricas.get("Status"):
            status = metricas["Status"]
        elif metricas.get("Cancelada"):
            status = "Cancelada"
        elif metricas.get("Falhas"):
            status = "Parcial"
        elif metricas.get("RaizesProcessadas"):
            status = "OK"
        else:
            status = "Não disponível"
        return {
            "Codigo": categoria["Codigo"],
            "Categoria": categoria["Categoria"],
            "Descricao": categoria["Descricao"],
            "Avancada": bool(categoria.get("Avancada")),
            "SelecionadaPadrao": bool(categoria.get("SelecionadaPadrao")),
            "Elegivel": bool(metricas.get("RaizesProcessadas") or categoria.get("Tipo") == "lixeira"),
            "Status": status,
            "TamanhoBytes": tamanho,
            "TamanhoLegivel": ModuloSistema._formatar_bytes_manutencao(tamanho),
            "Quantidade": max(0, int(metricas.get("EncontradoQuantidade") or 0)),
            "Ignorados": max(0, int(metricas.get("Ignorados") or 0)),
            "Falhas": max(0, int(metricas.get("Falhas") or 0)),
            "EstimativaDisponivel": metricas.get("EstimativaDisponivel", True),
        }

    @staticmethod
    def analisar_limpeza_segura(
        categorias=None, progress_callback=None, cancel_callback=None
    ) -> Dict[str, Any]:
        """Faz dry-run de categorias autorizadas; não exclui qualquer arquivo."""
        inicio = time.monotonic()
        selecionadas = ModuloSistema._selecionar_categorias_limpeza(categorias)
        if not selecionadas:
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": "Nenhuma categoria de limpeza válida foi selecionada.",
                "Categorias": [],
            }

        raizes = [
            raiz for categoria in selecionadas
            for raiz in categoria.get("Raizes", []) if raiz
        ]
        protegidos = ModuloSistema._caminhos_protegidos_manutencao(raizes)
        resultados = []
        total_bytes = 0
        total_itens = 0
        total_falhas = 0
        for indice, categoria in enumerate(selecionadas, start=1):
            if ModuloSistema._cancelamento_manutencao_solicitado(cancel_callback):
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Análise de limpeza cancelada.",
                    "Categorias": resultados,
                }
            percentual = int((indice - 1) * 100 / len(selecionadas))
            ModuloSistema._emitir_progresso_manutencao(
                progress_callback, percentual,
                f"Analisando: {categoria['Categoria']}..."
            )
            if categoria.get("Tipo") == "lixeira":
                metricas = ModuloSistema._analisar_lixeira_segura(cancel_callback)
            else:
                metricas = ModuloSistema._varrer_categoria_limpeza_segura(
                    categoria, protegidos, cancel_callback
                )
            if metricas.get("Cancelada"):
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Análise de limpeza cancelada.",
                    "Categorias": resultados,
                }
            item = ModuloSistema._resultado_categoria_limpeza(categoria, metricas)
            resultados.append(item)
            total_bytes += item["TamanhoBytes"]
            total_itens += item["Quantidade"]
            total_falhas += item["Falhas"]

        duracao = round(time.monotonic() - inicio, 2)
        detalhes = (
            f"categorias={len(resultados)}; itens={total_itens}; "
            f"bytes={total_bytes}; falhas={total_falhas}; duracao_s={duracao}"
        )
        logger.info("LIMPEZA_ANALISADA | %s", detalhes)
        registrar_log("SISTEMA", "LIMPEZA_ANALISADA", detalhes)
        ModuloSistema._emitir_progresso_manutencao(
            progress_callback, 100, "Análise de limpeza concluída."
        )
        return {
            "Sucesso": True,
            "Cancelada": False,
            "Mensagem": "Análise concluída. Nenhum arquivo foi removido.",
            "Categorias": resultados,
            "TotalEncontradoBytes": total_bytes,
            "TotalEncontradoLegivel": ModuloSistema._formatar_bytes_manutencao(
                total_bytes
            ),
            "TotalEncontradoQuantidade": total_itens,
            "TotalFalhas": total_falhas,
            "DuracaoSegundos": duracao,
        }

    @staticmethod
    def _executar_lixeira_segura(analise, cancel_callback=None) -> Dict[str, Any]:
        """Esvazia apenas a Lixeira do usuário já selecionada pela GUI."""
        if ModuloSistema._cancelamento_manutencao_solicitado(cancel_callback):
            return {"Cancelada": True}
        try:
            resposta = executar_powershell(
                "Clear-RecycleBin -Force -ErrorAction Stop", timeout=60
            )
            if resposta.returncode != 0:
                return {
                    "Sucesso": False,
                    "Falhas": 1,
                    "Mensagem": "O Windows não confirmou a limpeza da Lixeira.",
                }
            return {
                "Sucesso": True,
                "RemovidoBytes": int(analise.get("TamanhoBytes") or 0),
                "RemovidoQuantidade": int(analise.get("Quantidade") or 0),
                "Estimado": bool(analise.get("EstimativaDisponivel")),
            }
        except Exception:
            return {
                "Sucesso": False,
                "Falhas": 1,
                "Mensagem": "Não foi possível limpar a Lixeira pelo Windows.",
            }

    @staticmethod
    def executar_limpeza_segura(
        categorias, progress_callback=None, cancel_callback=None
    ) -> Dict[str, Any]:
        """Executa limpeza selecionada após uma nova análise interna (dry-run)."""
        inicio = time.monotonic()
        selecionadas = ModuloSistema._selecionar_categorias_limpeza(categorias)
        if not selecionadas:
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": "Selecione ao menos uma categoria de limpeza.",
                "Categorias": [],
            }

        def progresso_analise(percentual, mensagem):
            ModuloSistema._emitir_progresso_manutencao(
                progress_callback, int(percentual * 0.45), mensagem
            )

        analise = ModuloSistema.analisar_limpeza_segura(
            [categoria["Codigo"] for categoria in selecionadas],
            progress_callback=progresso_analise,
            cancel_callback=cancel_callback,
        )
        if analise.get("Cancelada"):
            return {
                "Sucesso": False,
                "Cancelada": True,
                "Mensagem": "Limpeza cancelada durante a análise prévia.",
                "Categorias": analise.get("Categorias", []),
            }
        if not analise.get("Sucesso"):
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": analise.get("Mensagem") or "A análise prévia falhou.",
                "Categorias": analise.get("Categorias", []),
            }

        analises = {
            item.get("Codigo"): item for item in analise.get("Categorias", [])
            if isinstance(item, dict)
        }
        raizes = [
            raiz for categoria in selecionadas
            for raiz in categoria.get("Raizes", []) if raiz
        ]
        protegidos = ModuloSistema._caminhos_protegidos_manutencao(raizes)
        resultados = []
        totais = {
            "EncontradoBytes": 0, "EncontradoQuantidade": 0,
            "RemovidoBytes": 0, "RemovidoQuantidade": 0,
            "NaoRemovidoBytes": 0, "NaoRemovidoQuantidade": 0,
            "Falhas": 0,
        }

        for indice, categoria in enumerate(selecionadas, start=1):
            if ModuloSistema._cancelamento_manutencao_solicitado(cancel_callback):
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Limpeza cancelada. O resultado parcial foi preservado.",
                    "Categorias": resultados,
                    **totais,
                }
            percentual = 45 + int((indice - 1) * 50 / len(selecionadas))
            ModuloSistema._emitir_progresso_manutencao(
                progress_callback, percentual,
                f"Limpando: {categoria['Categoria']}..."
            )
            analise_categoria = analises.get(categoria["Codigo"], {})
            resultado_categoria = {
                "Codigo": categoria["Codigo"],
                "Categoria": categoria["Categoria"],
                "Descricao": categoria["Descricao"],
                "EncontradoBytes": 0,
                "EncontradoQuantidade": 0,
                "RemovidoBytes": 0,
                "RemovidoQuantidade": 0,
                "NaoRemovidoBytes": 0,
                "NaoRemovidoQuantidade": 0,
                "Falhas": 0,
                "Estimado": False,
            }
            if categoria.get("Tipo") == "lixeira":
                lixeira = ModuloSistema._executar_lixeira_segura(
                    analise_categoria, cancel_callback
                )
                if lixeira.get("Cancelada"):
                    return {
                        "Sucesso": False,
                        "Cancelada": True,
                        "Mensagem": "Limpeza cancelada. O resultado parcial foi preservado.",
                        "Categorias": resultados,
                        **totais,
                    }
                resultado_categoria["EncontradoBytes"] = int(
                    analise_categoria.get("TamanhoBytes") or 0
                )
                resultado_categoria["EncontradoQuantidade"] = int(
                    analise_categoria.get("Quantidade") or 0
                )
                resultado_categoria["RemovidoBytes"] = int(
                    lixeira.get("RemovidoBytes") or 0
                )
                resultado_categoria["RemovidoQuantidade"] = int(
                    lixeira.get("RemovidoQuantidade") or 0
                )
                resultado_categoria["Falhas"] = int(lixeira.get("Falhas") or 0)
                resultado_categoria["Estimado"] = bool(lixeira.get("Estimado"))
                resultado_categoria["NaoRemovidoBytes"] = max(
                    0, resultado_categoria["EncontradoBytes"]
                    - resultado_categoria["RemovidoBytes"]
                )
                resultado_categoria["NaoRemovidoQuantidade"] = max(
                    0, resultado_categoria["EncontradoQuantidade"]
                    - resultado_categoria["RemovidoQuantidade"]
                )
            else:
                def remover_arquivo(item, raiz, tamanho):
                    elegivel, _, atual = ModuloSistema._item_limpeza_segura_elegivel(
                        item, raiz, protegidos
                    )
                    if not elegivel or atual is None:
                        resultado_categoria["NaoRemovidoBytes"] += tamanho
                        resultado_categoria["NaoRemovidoQuantidade"] += 1
                        return
                    try:
                        dados_atuais = os.lstat(atual)
                        if (
                            ModuloSistema._eh_ponto_reparse_limpeza(atual)
                            or not stat.S_ISREG(dados_atuais.st_mode)
                        ):
                            resultado_categoria["NaoRemovidoBytes"] += tamanho
                            resultado_categoria["NaoRemovidoQuantidade"] += 1
                            return
                        atual.unlink()
                        resultado_categoria["RemovidoBytes"] += tamanho
                        resultado_categoria["RemovidoQuantidade"] += 1
                    except FileNotFoundError:
                        # Um item removido por outro processo não é sucesso falso.
                        resultado_categoria["NaoRemovidoBytes"] += tamanho
                        resultado_categoria["NaoRemovidoQuantidade"] += 1
                    except (PermissionError, OSError):
                        resultado_categoria["Falhas"] += 1
                        resultado_categoria["NaoRemovidoBytes"] += tamanho
                        resultado_categoria["NaoRemovidoQuantidade"] += 1

                def remover_diretorio(item, raiz):
                    elegivel, _, atual = ModuloSistema._item_limpeza_segura_elegivel(
                        item, raiz, protegidos
                    )
                    if not elegivel or atual is None:
                        return
                    try:
                        if not ModuloSistema._eh_ponto_reparse_limpeza(atual):
                            atual.rmdir()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        # Diretório não vazio por item protegido/novo não torna
                        # a limpeza inteira uma falha; arquivos bloqueados já são
                        # contabilizados individualmente acima.
                        pass

                metricas = ModuloSistema._varrer_categoria_limpeza_segura(
                    categoria,
                    protegidos,
                    cancel_callback=cancel_callback,
                    processar_arquivo=remover_arquivo,
                    processar_diretorio=remover_diretorio,
                )
                if metricas.get("Cancelada"):
                    return {
                        "Sucesso": False,
                        "Cancelada": True,
                        "Mensagem": "Limpeza cancelada. O resultado parcial foi preservado.",
                        "Categorias": resultados,
                        **totais,
                    }
                resultado_categoria["EncontradoBytes"] = int(
                    metricas.get("EncontradoBytes") or 0
                )
                resultado_categoria["EncontradoQuantidade"] = int(
                    metricas.get("EncontradoQuantidade") or 0
                )
                resultado_categoria["Falhas"] += int(metricas.get("Falhas") or 0)
                # Item que não chegou ao callback é conservadoramente reportado
                # como não removido, nunca contado como sucesso.
                diferenca = max(
                    0,
                    resultado_categoria["EncontradoQuantidade"]
                    - resultado_categoria["RemovidoQuantidade"]
                    - resultado_categoria["NaoRemovidoQuantidade"],
                )
                if diferenca:
                    resultado_categoria["NaoRemovidoQuantidade"] += diferenca

            for chave in totais:
                if chave in resultado_categoria:
                    totais[chave] += int(resultado_categoria[chave] or 0)
            resultados.append(resultado_categoria)

        duracao = round(time.monotonic() - inicio, 2)
        encontrou = totais["EncontradoQuantidade"] > 0
        removeu = totais["RemovidoQuantidade"] > 0
        parcial = bool(
            totais["Falhas"] or totais["NaoRemovidoQuantidade"]
        )
        if encontrou and not removeu:
            sucesso = False
            mensagem = "Nenhum item encontrado pôde ser removido."
        elif parcial:
            sucesso = True
            mensagem = "Limpeza concluída parcialmente; alguns itens permaneceram protegidos ou em uso."
        elif encontrou:
            sucesso = True
            mensagem = "Limpeza concluída."
        else:
            sucesso = True
            mensagem = "Nenhum item removível foi encontrado nas categorias selecionadas."
        detalhes = (
            f"categorias={len(resultados)}; encontrados={totais['EncontradoQuantidade']}; "
            f"bytes_encontrados={totais['EncontradoBytes']}; removidos={totais['RemovidoQuantidade']}; "
            f"bytes_removidos={totais['RemovidoBytes']}; nao_removidos={totais['NaoRemovidoQuantidade']}; "
            f"falhas={totais['Falhas']}; duracao_s={duracao}"
        )
        logger.info("LIMPEZA_EXECUTADA | %s", detalhes)
        registrar_log("SISTEMA", "LIMPEZA_EXECUTADA", detalhes)
        ModuloSistema._emitir_progresso_manutencao(
            progress_callback, 100,
            "Limpeza concluída." if sucesso else "Limpeza não concluída."
        )
        return {
            "Sucesso": sucesso,
            "Cancelada": False,
            "Parcial": parcial,
            "Mensagem": mensagem,
            "Categorias": resultados,
            "DuracaoSegundos": duracao,
            **totais,
        }

    @staticmethod
    def _consultar_sinais_saude_sistema() -> Dict[str, Any]:
        """Consulta nativa, somente leitura, sem instalar nem alterar serviços."""
        script = r"""
$ErrorActionPreference='Stop'
$dados = [ordered]@{
    UpdateDisponivel = $false
    AtualizacoesPendentes = $null
    DefenderDisponivel = $false
    AntivirusEnabled = $null
    RealTimeProtectionEnabled = $null
    AMServiceEnabled = $null
    ReinicioDisponivel = $false
    ReinicioPendente = $null
    UptimeDisponivel = $false
    UptimeHoras = $null
    InicializacaoDisponivel = $false
    ItensInicializacao = $null
}
try {
    $sessao = New-Object -ComObject Microsoft.Update.Session
    $buscador = $sessao.CreateUpdateSearcher()
    $resultado = $buscador.Search('IsInstalled=0 and IsHidden=0')
    $dados.UpdateDisponivel = $true
    $dados.AtualizacoesPendentes = [int]$resultado.Updates.Count
} catch {}
try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $dados.DefenderDisponivel = $true
    $dados.AntivirusEnabled = [bool]$defender.AntivirusEnabled
    $dados.RealTimeProtectionEnabled = [bool]$defender.RealTimeProtectionEnabled
    $dados.AMServiceEnabled = [bool]$defender.AMServiceEnabled
} catch {}
try {
    $pendente = $false
    $pendente = $pendente -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    $pendente = $pendente -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    try {
        $sessao = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        $pendente = $pendente -or ($null -ne $sessao.PendingFileRenameOperations)
    } catch {}
    $dados.ReinicioDisponivel = $true
    $dados.ReinicioPendente = [bool]$pendente
} catch {}
try {
    $so = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $inicio = [datetime]$so.LastBootUpTime
    $dados.UptimeDisponivel = $true
    $dados.UptimeHoras = [math]::Round(((Get-Date) - $inicio).TotalHours, 1)
} catch {}
try {
    $dados.ItensInicializacao = [int]@(
        Get-CimInstance Win32_StartupCommand -ErrorAction Stop
    ).Count
    $dados.InicializacaoDisponivel = $true
} catch {}
[PSCustomObject]$dados | ConvertTo-Json -Compress
"""
        try:
            resposta = executar_powershell(script, timeout=45)
            if resposta.returncode != 0 or not resposta.stdout.strip():
                return {}
            dados = json.loads(resposta.stdout.strip())
            return dados if isinstance(dados, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def obter_saude_sistema(
        progress_callback=None, cancel_callback=None
    ) -> Dict[str, Any]:
        """Consolida leituras já disponíveis e produz apenas recomendações."""
        inicio = time.monotonic()
        itens = []
        recomendacoes = []

        def cancelada():
            return ModuloSistema._cancelamento_manutencao_solicitado(cancel_callback)

        def adicionar(nome, estado, detalhe, recomendacao=""):
            itens.append({
                "Item": nome,
                "Estado": estado,
                "Detalhe": detalhe,
                "Recomendacao": recomendacao,
            })
            if recomendacao:
                recomendacoes.append(recomendacao)

        if cancelada():
            return {"Sucesso": False, "Cancelada": True, "Itens": []}
        ModuloSistema._emitir_progresso_manutencao(
            progress_callback, 5, "Verificando espaço da unidade do sistema..."
        )
        unidade_sistema = os.environ.get("SystemDrive")
        if unidade_sistema and len(unidade_sistema) == 2 and unidade_sistema[1] == ":":
            unidade_sistema += "\\"
        if not unidade_sistema:
            unidade_sistema = Path.home().anchor or str(Path.home())
        try:
            uso = shutil.disk_usage(unidade_sistema)
            percentual_livre = (uso.free * 100 / uso.total) if uso.total else 0
            detalhe = (
                f"{ModuloSistema._formatar_bytes_manutencao(uso.free)} livres de "
                f"{ModuloSistema._formatar_bytes_manutencao(uso.total)} "
                f"({percentual_livre:.0f}% livre)."
            )
            if percentual_livre < 10:
                adicionar(
                    "Espaço da unidade do sistema", "Ação recomendada", detalhe,
                    "Libere espaço na unidade do sistema após revisar as categorias de limpeza."
                )
            elif percentual_livre < 20:
                adicionar(
                    "Espaço da unidade do sistema", "Atenção", detalhe,
                    "Acompanhe o espaço livre e revise temporários removíveis."
                )
            else:
                adicionar("Espaço da unidade do sistema", "OK", detalhe)
        except Exception:
            adicionar(
                "Espaço da unidade do sistema", "Não disponível",
                "Não foi possível consultar a unidade do sistema."
            )

        if cancelada():
            return {"Sucesso": False, "Cancelada": True, "Itens": itens}
        ModuloSistema._emitir_progresso_manutencao(
            progress_callback, 20, "Estimando temporários seguros..."
        )
        try:
            limpeza = ModuloSistema.analisar_limpeza_segura(
                ["temporarios_usuario", "cache_miniaturas"],
                cancel_callback=cancel_callback,
            )
            if limpeza.get("Cancelada"):
                return {"Sucesso": False, "Cancelada": True, "Itens": itens}
            bytes_limpeza = int(limpeza.get("TotalEncontradoBytes") or 0)
            itens_limpeza = int(limpeza.get("TotalEncontradoQuantidade") or 0)
            detalhe = (
                f"{ModuloSistema._formatar_bytes_manutencao(bytes_limpeza)} em "
                f"{itens_limpeza} item(ns) de categorias rápidas."
            )
            if bytes_limpeza >= 1024 ** 3:
                adicionar(
                    "Temporários removíveis", "Ação recomendada", detalhe,
                    "Analise a limpeza segura e selecione somente as categorias desejadas."
                )
            elif bytes_limpeza > 0:
                adicionar(
                    "Temporários removíveis", "Atenção", detalhe,
                    "Há temporários que podem ser revisados pela limpeza segura."
                )
            else:
                adicionar("Temporários removíveis", "OK", detalhe)
        except Exception:
            adicionar(
                "Temporários removíveis", "Não disponível",
                "Não foi possível estimar os temporários seguros."
            )

        if cancelada():
            return {"Sucesso": False, "Cancelada": True, "Itens": itens}
        ModuloSistema._emitir_progresso_manutencao(
            progress_callback, 42, "Resumindo a saúde de armazenamento..."
        )
        try:
            armazenamento = ModuloSistema.obter_saude_armazenamento(
                cancel_callback=cancel_callback
            )
            if armazenamento.get("Cancelada"):
                return {"Sucesso": False, "Cancelada": True, "Itens": itens}
            discos = armazenamento.get("Discos") or []
            estados = [
                str(disco.get("Saude") or "").casefold()
                for disco in discos if isinstance(disco, dict)
            ]
            if not estados:
                adicionar(
                    "Saúde de armazenamento", "Não disponível",
                    "Nenhum estado de disco foi retornado pelo Windows."
                )
            elif any("crít" in estado for estado in estados):
                adicionar(
                    "Saúde de armazenamento", "Ação recomendada",
                    "Há disco(s) com estado crítico.",
                    "Revise o painel Saúde de armazenamento e faça backup conforme a política da empresa."
                )
            elif any("aten" in estado for estado in estados):
                adicionar(
                    "Saúde de armazenamento", "Atenção",
                    "Há disco(s) que requerem acompanhamento.",
                    "Revise os detalhes SMART/confiabilidade no painel de armazenamento."
                )
            elif all("saud" in estado for estado in estados):
                adicionar(
                    "Saúde de armazenamento", "OK",
                    f"{len(estados)} disco(s) retornaram estado saudável."
                )
            else:
                adicionar(
                    "Saúde de armazenamento", "Não disponível",
                    "O Windows não expôs um estado conclusivo para todos os discos."
                )
        except Exception:
            adicionar(
                "Saúde de armazenamento", "Não disponível",
                "Não foi possível resumir a saúde de armazenamento."
            )

        if cancelada():
            return {"Sucesso": False, "Cancelada": True, "Itens": itens}
        ModuloSistema._emitir_progresso_manutencao(
            progress_callback, 68, "Consultando sinais nativos do Windows..."
        )
        sinais = ModuloSistema._consultar_sinais_saude_sistema()
        if sinais.get("UpdateDisponivel"):
            pendentes = int(sinais.get("AtualizacoesPendentes") or 0)
            if pendentes:
                adicionar(
                    "Windows Update", "Ação recomendada",
                    f"{pendentes} atualização(ões) pendente(s) identificada(s).",
                    "Revise e execute o Windows Update somente quando apropriado."
                )
            else:
                adicionar("Windows Update", "OK", "Nenhuma atualização pendente identificada.")
        else:
            adicionar(
                "Windows Update", "Não disponível",
                "A consulta nativa de atualizações não está disponível neste momento."
            )

        if sinais.get("DefenderDisponivel"):
            protegido = all(
                sinais.get(chave) is True for chave in (
                    "AntivirusEnabled", "RealTimeProtectionEnabled", "AMServiceEnabled"
                )
            )
            if protegido:
                adicionar(
                    "Microsoft Defender", "OK",
                    "Antivírus, proteção em tempo real e serviço reportados como ativos."
                )
            else:
                adicionar(
                    "Microsoft Defender", "Ação recomendada",
                    "O Windows reportou proteção do Defender incompleta ou desativada.",
                    "Revise a política de segurança antes de alterar a proteção."
                )
        else:
            adicionar(
                "Microsoft Defender", "Não disponível",
                "O status nativo do Defender não pôde ser consultado."
            )

        if sinais.get("ReinicioDisponivel"):
            if sinais.get("ReinicioPendente"):
                adicionar(
                    "Reinicialização pendente", "Ação recomendada",
                    "O Windows indicou que uma reinicialização pode estar pendente.",
                    "Programe uma reinicialização em janela apropriada."
                )
            else:
                adicionar("Reinicialização pendente", "OK", "Nenhum sinal de reinicialização pendente.")
        else:
            adicionar(
                "Reinicialização pendente", "Não disponível",
                "Não foi possível consultar os indicadores de reinicialização."
            )

        if sinais.get("UptimeDisponivel"):
            horas = float(sinais.get("UptimeHoras") or 0)
            if horas >= 24 * 7:
                adicionar(
                    "Tempo ligado", "Atenção",
                    f"Sistema ligado há aproximadamente {horas / 24:.1f} dia(s).",
                    "Considere uma reinicialização programada se isso for compatível com a operação."
                )
            else:
                adicionar(
                    "Tempo ligado", "OK",
                    f"Sistema ligado há aproximadamente {horas:.1f} hora(s)."
                )
        else:
            adicionar("Tempo ligado", "Não disponível", "Não foi possível obter o último boot.")

        if sinais.get("InicializacaoDisponivel"):
            quantidade = int(sinais.get("ItensInicializacao") or 0)
            adicionar(
                "Itens de inicialização", "OK",
                f"Inventário disponível: {quantidade} item(ns) de inicialização.",
            )
        else:
            adicionar(
                "Itens de inicialização", "Não disponível",
                "O inventário de inicialização não está disponível."
            )

        duracao = round(time.monotonic() - inicio, 2)
        detalhes_log = (
            f"itens={len(itens)}; recomendacoes={len(recomendacoes)}; "
            f"duracao_s={duracao}"
        )
        logger.info("SAUDE_SISTEMA_ATUALIZADA | %s", detalhes_log)
        registrar_log("SISTEMA", "SAUDE_SISTEMA_ATUALIZADA", detalhes_log)
        ModuloSistema._emitir_progresso_manutencao(
            progress_callback, 100, "Saúde do sistema atualizada."
        )
        return {
            "Sucesso": True,
            "Cancelada": False,
            "Mensagem": (
                f"Saúde do sistema atualizada com {len(recomendacoes)} recomendação(ões)."
                if recomendacoes else "Saúde do sistema atualizada sem ações recomendadas."
            ),
            "Itens": itens,
            "Recomendacoes": recomendacoes,
            "DuracaoSegundos": duracao,
        }
    
    @staticmethod
    def reiniciar_spooler_impressao() -> bool:
        if not elevacao_sob_demanda("reiniciar o spooler de impressão"):
            return False
        try:
            executar_powershell("Stop-Service -Name Spooler -Force", timeout=10)
            time.sleep(1)
            executar_powershell("Start-Service -Name Spooler", timeout=10)
            registrar_log("SISTEMA", "SPOOLER", "Reiniciado com sucesso")
            return True
        except Exception as e:
            logger.error(f"Erro ao reiniciar spooler: {e}")
            return False

    @staticmethod
    def listar_unidades() -> List[Dict[str, Any]]:
        """Lista volumes com letra e tenta identificar o tipo de mídia."""
        script = r"""
$volumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }
$result = foreach ($vol in $volumes) {
    $media = 'Unknown'
    try {
        $part = Get-Partition -DriveLetter $vol.DriveLetter -ErrorAction Stop
        $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
        $media = [string]$disk.MediaType
    } catch {}
    [PSCustomObject]@{
        DriveLetter = [string]$vol.DriveLetter
        FileSystem  = [string]$vol.FileSystem
        SizeGB      = [math]::Round($vol.Size / 1GB, 2)
        FreeGB      = [math]::Round($vol.SizeRemaining / 1GB, 2)
        MediaType   = $media
    }
}
@($result) | ConvertTo-Json -Depth 3 -Compress
"""
        try:
            res = executar_powershell(script, timeout=20)
            if res.returncode != 0 or not res.stdout.strip():
                logger.error(f"Erro ao listar unidades: {res.stderr.strip()}")
                return []
            dados = json.loads(res.stdout.strip())
            return dados if isinstance(dados, list) else [dados]
        except Exception as e:
            logger.error(f"Erro ao listar unidades: {e}")
            return []

    # =========================================================
    # Análise defensiva — processos, arquivos e persistências
    # =========================================================
    # Este módulo é deliberadamente somente leitura. Ele correlaciona sinais
    # observáveis e explica limitações, mas não remove, encerra, desabilita,
    # quarentena ou altera processos, arquivos, tarefas, serviços ou Registro.

    @staticmethod
    def _cancelamento_analise_defensiva_solicitado(cancel_callback) -> bool:
        try:
            return bool(callable(cancel_callback) and cancel_callback())
        except Exception:
            return False

    @staticmethod
    def _emitir_progresso_analise_defensiva(
        progress_callback, percentual: int, mensagem: str
    ) -> None:
        if not callable(progress_callback):
            return
        try:
            progress_callback(
                max(0, min(100, int(percentual))), str(mensagem)
            )
        except Exception:
            pass

    @staticmethod
    def _registrar_evento_analise_defensiva(
        acao: str, detalhes: str = ""
    ) -> None:
        """Registra somente métricas resumidas, nunca comandos ou hashes."""
        texto = str(detalhes or "sem_detalhes")
        try:
            registrar_log("SISTEMA", acao, texto)
        except Exception:
            try:
                logger.info("%s | %s", acao, texto)
            except Exception:
                pass

    @staticmethod
    def _lista_json_analise_defensiva(valor: Any) -> List[Dict[str, Any]]:
        if isinstance(valor, list):
            return [item for item in valor if isinstance(item, dict)]
        if isinstance(valor, dict):
            return [valor]
        return []

    @staticmethod
    def _expandir_variaveis_analise_defensiva(
        valor: str, contexto: Optional[Dict[str, Any]] = None
    ) -> str:
        texto = str(valor or "").strip()
        if not texto:
            return ""
        contexto = contexto if isinstance(contexto, dict) else {}
        mapa = {
            "windir": contexto.get("WindowsDirectory"),
            "systemroot": contexto.get("WindowsDirectory"),
            "programfiles": contexto.get("ProgramFiles"),
            "programfiles(x86)": contexto.get("ProgramFilesX86"),
            "programdata": contexto.get("ProgramData"),
            "userprofile": contexto.get("UserProfile"),
            "appdata": contexto.get("AppData"),
            "localappdata": contexto.get("LocalAppData"),
            "temp": contexto.get("Temp"),
            "tmp": contexto.get("Temp"),
            "comspec": contexto.get("ComSpec"),
            "systemdrive": contexto.get("SystemDrive"),
        }

        def substituir(correspondencia):
            nome = correspondencia.group(1).casefold()
            substituto = mapa.get(nome)
            return str(substituto) if substituto else correspondencia.group(0)

        texto = re.sub(r"%([^%]+)%", substituir, texto)
        raiz_windows = str(
            contexto.get("WindowsDirectory") or r"C:\Windows"
        )
        texto = re.sub(
            r"(?i)^\\systemroot(?=\\)",
            lambda _m: raiz_windows,
            texto,
        )
        return texto

    @staticmethod
    def _normalizar_caminho_analise_defensiva(
        caminho: Any, contexto: Optional[Dict[str, Any]] = None
    ) -> str:
        texto = ModuloSistema._expandir_variaveis_analise_defensiva(
            str(caminho or ""), contexto
        ).strip().strip('"').strip("'").strip()
        if not texto or "\x00" in texto:
            return ""
        texto = texto.replace("/", "\\")
        if texto.startswith("\\\\?\\"):
            texto = texto[4:]
        try:
            texto = ntpath.normpath(texto)
        except Exception:
            return ""
        if texto in {".", "\\"}:
            return ""
        return texto

    @staticmethod
    def _chave_caminho_analise_defensiva(
        caminho: Any, contexto: Optional[Dict[str, Any]] = None
    ) -> str:
        normalizado = ModuloSistema._normalizar_caminho_analise_defensiva(
            caminho, contexto
        )
        return ntpath.normcase(normalizado) if normalizado else ""

    @staticmethod
    def _caminho_absoluto_windows_analise_defensiva(caminho: Any) -> bool:
        texto = str(caminho or "")
        return bool(
            re.match(r"(?i)^[a-z]:\\", texto)
            or re.match(r"^\\\\[^\\]+\\[^\\]+", texto)
        )

    @staticmethod
    def _caminho_sob_raiz_analise_defensiva(
        caminho: Any, raiz: Any
    ) -> bool:
        chave = ModuloSistema._chave_caminho_analise_defensiva(caminho)
        chave_raiz = ModuloSistema._chave_caminho_analise_defensiva(raiz)
        if not chave or not chave_raiz:
            return False
        limite = chave_raiz.rstrip("\\") + "\\"
        return chave == chave_raiz or chave.startswith(limite)

    @staticmethod
    def _tokenizar_comando_windows_analise_defensiva(comando: Any) -> List[str]:
        """Separa argumentos sem executar nem reinterpretar conteúdo do comando."""
        texto = str(comando or "").replace("\x00", "").strip()
        if not texto:
            return []
        tokens: List[str] = []
        atual: List[str] = []
        aspas = ""
        indice = 0
        while indice < len(texto):
            caractere = texto[indice]
            if caractere in {'"', "'"}:
                if not aspas:
                    aspas = caractere
                    indice += 1
                    continue
                if aspas == caractere:
                    aspas = ""
                    indice += 1
                    continue
            if caractere.isspace() and not aspas:
                if atual:
                    tokens.append("".join(atual))
                    atual = []
                indice += 1
                continue
            atual.append(caractere)
            indice += 1
        if atual:
            tokens.append("".join(atual))
        return [token for token in tokens if token]

    @staticmethod
    def _resolver_token_caminho_analise_defensiva(
        token: Any,
        contexto: Optional[Dict[str, Any]] = None,
        extensoes: Optional[set] = None,
        resolver_sistema: bool = False,
        remover_entrypoint: bool = False,
    ) -> str:
        """Valida um token de caminho; nomes soltos só são resolvidos se existirem."""
        texto = str(token or "").strip().strip('"').strip("'").strip()
        if not texto or "\x00" in texto:
            return ""
        if remover_entrypoint:
            texto = texto.split(",", 1)[0].strip()
        if (
            texto.startswith("-")
            or texto.startswith("/")
            or re.match(r"(?i)^--?[^=]+=", texto)
        ):
            return ""
        extensao = ntpath.splitext(texto)[1].casefold()
        if extensoes and extensao not in extensoes:
            return ""
        normalizado = ModuloSistema._normalizar_caminho_analise_defensiva(
            texto, contexto
        )
        if ModuloSistema._caminho_absoluto_windows_analise_defensiva(normalizado):
            return normalizado
        if not resolver_sistema or "\\" in texto or "/" in texto:
            return ""

        contexto = contexto if isinstance(contexto, dict) else {}
        windir = str(contexto.get("WindowsDirectory") or "").strip()
        candidatos = []
        if windir:
            candidatos.extend(
                ntpath.join(windir, subpasta, texto)
                for subpasta in ("System32", "SysWOW64")
            )
            candidatos.append(ntpath.join(windir, texto))
        localizado = shutil.which(texto)
        if localizado:
            candidatos.append(localizado)
        for candidato in candidatos:
            candidato = ModuloSistema._normalizar_caminho_analise_defensiva(
                candidato, contexto
            )
            try:
                existe = os.path.isfile(candidato)
            except OSError:
                existe = False
            if (
                existe
                and ModuloSistema._caminho_absoluto_windows_analise_defensiva(
                    candidato
                )
            ):
                return candidato
        return ""

    @staticmethod
    def _extrair_caminhos_comando_analise_defensiva(
        comando: Any, contexto: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """Separa host e arquivos secundários apenas em sintaxes conhecidas."""
        texto = ModuloSistema._expandir_variaveis_analise_defensiva(
            str(comando or ""), contexto
        )
        if not texto or "\x00" in texto:
            return []
        extensoes_host = {
            ".exe", ".com", ".scr", ".cmd", ".bat", ".ps1",
            ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
            ".py", ".pyw", ".msi",
        }
        extensoes_secundarias = extensoes_host | {".dll", ".ocx"}
        tokens = ModuloSistema._tokenizar_comando_windows_analise_defensiva(
            texto
        )
        if not tokens:
            return []

        # Um caminho inicial sem aspas pode conter espaços. Limitamos a busca
        # ao início e à primeira extensão executável, sem vasculhar switches.
        extensoes_regex = "|".join(
            re.escape(extensao.lstrip("."))
            for extensao in sorted(extensoes_host, key=len, reverse=True)
        )
        correspondencia_host = re.match(
            rf"(?is)^\s*((?:[a-z]:\\|\\\\).*?\.(?:{extensoes_regex}))"
            rf"(?=\s|,|$)",
            texto,
        )
        token_host = (
            correspondencia_host.group(1)
            if correspondencia_host
            else tokens[0]
        )
        argumentos = (
            ModuloSistema._tokenizar_comando_windows_analise_defensiva(
                texto[correspondencia_host.end():]
            )
            if correspondencia_host
            else tokens[1:]
        )
        encontrados: List[str] = []
        chaves = set()

        def adicionar(candidato: str):
            chave = ModuloSistema._chave_caminho_analise_defensiva(candidato)
            if candidato and chave and chave not in chaves:
                chaves.add(chave)
                encontrados.append(candidato)

        host = ModuloSistema._resolver_token_caminho_analise_defensiva(
            token_host, contexto, extensoes_host, resolver_sistema=True
        )
        adicionar(host)
        nome_host = ntpath.basename(token_host).casefold().strip('"').strip("'")
        if "," in nome_host:
            nome_host = nome_host.split(",", 1)[0]

        def primeiro_posicional(valores: List[str]) -> str:
            for valor in valores:
                if valor.startswith("-") or valor.startswith("/"):
                    continue
                return valor
            return ""

        secundario = ""
        if nome_host in {"rundll32", "rundll32.exe"}:
            token = primeiro_posicional(argumentos)
            secundario = ModuloSistema._resolver_token_caminho_analise_defensiva(
                token, contexto, {".dll", ".ocx"}, resolver_sistema=True,
                remover_entrypoint=True,
            )
        elif nome_host in {"regsvr32", "regsvr32.exe"}:
            token = primeiro_posicional(argumentos)
            secundario = ModuloSistema._resolver_token_caminho_analise_defensiva(
                token, contexto, {".dll", ".ocx"}, resolver_sistema=True
            )
        elif nome_host in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
            for indice, token in enumerate(argumentos[:-1]):
                if token.casefold() in {"-file", "-f"}:
                    secundario = ModuloSistema._resolver_token_caminho_analise_defensiva(
                        argumentos[indice + 1], contexto,
                        extensoes_secundarias,
                    )
                    break
        elif nome_host in {
            "wscript", "wscript.exe", "cscript", "cscript.exe",
            "mshta", "mshta.exe", "python", "python.exe", "pythonw",
            "pythonw.exe",
        }:
            token = primeiro_posicional(argumentos)
            secundario = ModuloSistema._resolver_token_caminho_analise_defensiva(
                token, contexto, extensoes_secundarias
            )
        elif nome_host in {"cmd", "cmd.exe"}:
            for indice, token in enumerate(argumentos[:-1]):
                if token.casefold() in {"/c", "/k"}:
                    secundario = ModuloSistema._resolver_token_caminho_analise_defensiva(
                        argumentos[indice + 1], contexto,
                        extensoes_secundarias, resolver_sistema=True,
                    )
                    break
        adicionar(secundario)
        return encontrados

    @staticmethod
    def _sanitizar_comando_analise_defensiva(
        comando: Any, contexto: Optional[Dict[str, Any]] = None
    ) -> str:
        """Mascara segredos comuns e limita texto exibido/copiado pela GUI."""
        texto = str(comando or "").replace("\x00", "").strip()
        if not texto:
            return "—"
        contexto = contexto if isinstance(contexto, dict) else {}
        perfil = str(contexto.get("UserProfile") or "").strip()
        if perfil:
            texto = re.sub(
                re.escape(perfil), "%USERPROFILE%", texto, flags=re.IGNORECASE
            )
        texto = re.sub(
            r"(?i)(-(?:encodedcommand|enc)\b(?:\s+|[:=]))(?:\"[^\"]*\"|'[^']*'|\S+)",
            lambda m: f"{m.group(1)}<conteúdo codificado omitido>",
            texto,
        )
        texto = re.sub(
            r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{180,}={0,2}(?![A-Za-z0-9+/])",
            "<bloco codificado omitido>",
            texto,
        )
        texto = re.sub(
            r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@",
            lambda m: f"{m.group(1)}<credenciais>@",
            texto,
        )
        nomes = (
            r"password|passwd|pwd|senha|token|access[_-]?token|api[_-]?key|"
            r"apikey|secret|client[_-]?secret|authorization"
        )
        texto = re.sub(
            rf"(?i)\b({nomes})\b\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|\S+)",
            lambda m: f"{m.group(1)}=<mascarado>",
            texto,
        )
        texto = re.sub(
            rf"(?i)(--?(?:{nomes})|/(?:{nomes}))\s+(?:\"[^\"]*\"|'[^']*'|\S+)",
            lambda m: f"{m.group(1)} <mascarado>",
            texto,
        )
        texto = re.sub(
            rf"(?i)([?&](?:{nomes})=)[^&#\s]+",
            lambda m: f"{m.group(1)}<mascarado>",
            texto,
        )
        texto = re.sub(
            r"(?i)\b(Basic|Bearer)\s+[A-Za-z0-9._~+/=-]{8,}",
            lambda m: f"{m.group(1)} <mascarado>",
            texto,
        )
        texto = re.sub(r"[\r\n\t]+", " ", texto)
        texto = re.sub(r"\s{2,}", " ", texto).strip()
        return texto if len(texto) <= 1200 else texto[:1197] + "..."

    @staticmethod
    def _contexto_caminho_analise_defensiva(
        caminho: Any, contexto: Optional[Dict[str, Any]] = None
    ) -> Dict[str, bool]:
        contexto = contexto if isinstance(contexto, dict) else {}
        normalizado = ModuloSistema._normalizar_caminho_analise_defensiva(
            caminho, contexto
        )
        resultado = {
            "Absoluto": ModuloSistema._caminho_absoluto_windows_analise_defensiva(
                normalizado
            ),
            "Rede": normalizado.startswith("\\\\"),
            "Windows": False,
            "System32": False,
            "SysWOW64": False,
            "WinSxS": False,
            "ProgramFiles": False,
            "ProgramData": False,
            "Temp": False,
            "AppData": False,
            "Downloads": False,
            "Startup": False,
            "PerfilUsuario": False,
        }
        if not normalizado:
            return resultado

        windir = contexto.get("WindowsDirectory")
        resultado["Windows"] = ModuloSistema._caminho_sob_raiz_analise_defensiva(
            normalizado, windir
        )
        if windir:
            resultado["System32"] = ModuloSistema._caminho_sob_raiz_analise_defensiva(
                normalizado, ntpath.join(str(windir), "System32")
            )
            resultado["SysWOW64"] = ModuloSistema._caminho_sob_raiz_analise_defensiva(
                normalizado, ntpath.join(str(windir), "SysWOW64")
            )
            resultado["WinSxS"] = ModuloSistema._caminho_sob_raiz_analise_defensiva(
                normalizado, ntpath.join(str(windir), "WinSxS")
            )
        resultado["ProgramFiles"] = any(
            ModuloSistema._caminho_sob_raiz_analise_defensiva(normalizado, raiz)
            for raiz in (
                contexto.get("ProgramFiles"),
                contexto.get("ProgramFilesX86"),
            )
            if raiz
        )
        resultado["ProgramData"] = ModuloSistema._caminho_sob_raiz_analise_defensiva(
            normalizado, contexto.get("ProgramData")
        )
        resultado["Temp"] = any(
            ModuloSistema._caminho_sob_raiz_analise_defensiva(normalizado, raiz)
            for raiz in (contexto.get("Temp"), contexto.get("WindowsTemp"))
            if raiz
        )
        resultado["AppData"] = any(
            ModuloSistema._caminho_sob_raiz_analise_defensiva(normalizado, raiz)
            for raiz in (
                contexto.get("AppData"),
                contexto.get("LocalAppData"),
            )
            if raiz
        )
        resultado["Downloads"] = ModuloSistema._caminho_sob_raiz_analise_defensiva(
            normalizado, contexto.get("Downloads")
        )
        resultado["Startup"] = any(
            ModuloSistema._caminho_sob_raiz_analise_defensiva(normalizado, raiz)
            for raiz in (
                contexto.get("StartupUser"),
                contexto.get("StartupCommon"),
            )
            if raiz
        )
        resultado["PerfilUsuario"] = ModuloSistema._caminho_sob_raiz_analise_defensiva(
            normalizado, contexto.get("UserProfile")
        )
        return resultado

    @staticmethod
    def _normalizar_assinatura_analise_defensiva(status: Any) -> str:
        normalizado = str(status or "").strip().casefold()
        if normalizado == "valid":
            return "Válida"
        if normalizado == "notsigned":
            return "Não assinada"
        if normalizado in {
            "hashmismatch", "nottrusted", "notvalid", "invalid", "incompatible"
        }:
            return "Inválida"
        return "Não disponível"

    @staticmethod
    def _sinais_comando_analise_defensiva(comando: Any) -> List[Dict[str, str]]:
        """Reconhece indicadores defensivos sem reconstruir qualquer payload."""
        texto = str(comando or "")
        if not texto:
            return []
        sinais: List[Dict[str, str]] = []

        def adicionar(codigo: str, forca: str, motivo: str, evidencia: str):
            if not any(item.get("Codigo") == codigo for item in sinais):
                sinais.append(
                    {
                        "Codigo": codigo,
                        "Forca": forca,
                        "Motivo": motivo,
                        "Evidencia": evidencia,
                    }
                )

        if re.search(r"(?i)(?:^|\s)-(?:encodedcommand|enc)\b", texto):
            adicionar(
                "COMANDO_CODIFICADO", "medio",
                "A linha de comando solicita conteúdo codificado.",
                "Foi identificado o parâmetro defensivo EncodedCommand/enc; o conteúdo não foi decodificado.",
            )
        if re.search(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{180,}={0,2}(?![A-Za-z0-9+/])", texto):
            adicionar(
                "BLOCO_BASE64_LONGO", "medio",
                "A linha de comando contém um bloco longo compatível com codificação.",
                "O bloco foi apenas detectado e não foi exibido nem reconstruído.",
            )
        if re.search(
            r"(?i)(?:-windowstyle\s+hidden|-w(?:indowstyle)?\s+hidden|"
            r"showwindow\s*[:=]\s*0)", texto
        ):
            adicionar(
                "EXECUCAO_OCULTA", "medio",
                "A linha de comando solicita execução sem janela visível.",
                "Execução oculta pode ser legítima; precisa ser avaliada com os demais sinais.",
            )

        remoto = bool(re.search(r"(?i)https?://|\\\\[^\\\s]+\\", texto))
        lolbin = bool(re.search(r"(?i)\b(?:mshta|rundll32|regsvr32)(?:\.exe)?\b", texto))
        if remoto and lolbin:
            adicionar(
                "UTILITARIO_SISTEMA_ORIGEM_REMOTA", "forte",
                "Um utilitário do sistema recebeu uma origem remota ou de rede.",
                "A combinação utilitário/origem foi detectada; nenhum conteúdo remoto foi acessado.",
            )

        transferencia = bool(
            re.search(
                r"(?i)\b(?:invoke-webrequest|downloadstring|downloadfile|"
                r"start-bitstransfer|bitsadmin|certutil|curl|wget)\b",
                texto,
            )
        )
        execucao = bool(
            re.search(
                r"(?i)\b(?:invoke-expression|iex|start-process|cmd(?:\.exe)?\s+/c|"
                r"powershell(?:\.exe)?)\b",
                texto,
            )
        )
        if remoto and transferencia and execucao:
            adicionar(
                "TRANSFERENCIA_E_EXECUCAO_ENCADEADAS", "forte",
                "A linha de comando correlaciona origem remota, transferência e execução.",
                "Somente os indicadores foram registrados; a cadeia não foi executada nem reconstruída.",
            )
        return sinais

    @staticmethod
    def _classificar_item_analise_defensiva(
        item: Dict[str, Any],
        metadados: Optional[Dict[str, Any]],
        contexto: Optional[Dict[str, Any]],
        correlacao: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Classifica por correlação; um único sinal fraco nunca é suspeito."""
        metadados = metadados if isinstance(metadados, dict) else {}
        contexto = contexto if isinstance(contexto, dict) else {}
        correlacao = correlacao if isinstance(correlacao, dict) else {}
        resultado = dict(item)
        caminho = ModuloSistema._normalizar_caminho_analise_defensiva(
            resultado.get("Caminho"), contexto
        )
        resultado["Caminho"] = caminho
        flags = ModuloSistema._contexto_caminho_analise_defensiva(
            caminho, contexto
        )
        assinatura = ModuloSistema._normalizar_assinatura_analise_defensiva(
            metadados.get("AssinaturaStatus")
        )
        publisher = str(metadados.get("Publisher") or "").strip()
        atributos = str(metadados.get("Atributos") or "")
        existe = metadados.get("Existe")
        persistencia = bool(resultado.get("PersistenciaAtiva"))
        tipo = str(resultado.get("Tipo") or "")
        tipo_acao = str(resultado.get("TipoAcao") or "").casefold()
        tarefa_exec = tipo == "Tarefa agendada" and tipo_acao == "exec"
        tarefa_sem_executavel = (
            tipo == "Tarefa agendada" and tipo_acao not in {"", "exec"}
        )
        extensao = ntpath.splitext(caminho)[1].casefold() if caminho else ""
        arquivo_assinavel = extensao in {
            ".exe", ".com", ".scr", ".dll", ".sys", ".cpl", ".ocx",
            ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js",
            ".jse", ".wsf", ".hta", ".py", ".pyw",
        }
        caminho_startup = str(resultado.get("ArquivoStartup") or caminho)
        metadado_shell_startup = (
            tipo == "Startup"
            and str(resultado.get("Fonte") or "") == "Pasta Startup"
            and ntpath.basename(caminho_startup).casefold() == "desktop.ini"
            and not arquivo_assinavel
            and not bool(resultado.get("ComandoExecucaoExplicito"))
        )
        sinais: List[Dict[str, str]] = []
        evidencias: List[str] = []
        inconsistencia_objetiva = False

        def adicionar(codigo: str, forca: str, motivo: str, evidencia: str):
            if not any(sinal.get("Codigo") == codigo for sinal in sinais):
                sinais.append(
                    {
                        "Codigo": codigo,
                        "Forca": forca,
                        "Motivo": motivo,
                        "Evidencia": evidencia,
                    }
                )

        if flags.get("Temp") and not metadado_shell_startup:
            adicionar(
                "CAMINHO_TEMP", "fraco",
                "O executável/alvo está em uma pasta temporária.",
                "Pastas temporárias são graváveis e transitórias, mas esse sinal isolado não confirma ameaça.",
            )
        elif flags.get("AppData") and not metadado_shell_startup:
            adicionar(
                "CAMINHO_APPDATA", "fraco",
                "O executável/alvo está em AppData.",
                "Aplicativos legítimos usam AppData; esse sinal isolado não confirma ameaça.",
            )
        elif flags.get("Downloads") and not metadado_shell_startup:
            adicionar(
                "CAMINHO_DOWNLOADS", "fraco",
                "O executável/alvo está na pasta Downloads.",
                "A localização sugere origem do usuário, mas não confirma ameaça.",
            )

        if flags.get("Startup") and not metadado_shell_startup:
            adicionar(
                "CAMINHO_STARTUP", "fraco",
                "O item está localizado em uma pasta Startup.",
                "Startup é um mecanismo legítimo de inicialização; exige contexto.",
            )
        if tipo in {"Run", "RunOnce", "Startup"} and persistencia:
            adicionar(
                "INICIALIZACAO_AUTOMATICA", "fraco",
                "O item está configurado para inicialização automática.",
                "Persistência por si só não confirma comportamento malicioso.",
            )
        if tipo == "Arquivo associado" and persistencia:
            adicionar(
                "ARQUIVO_ASSOCIADO_PERSISTENCIA", "fraco",
                "O arquivo está diretamente associado a um mecanismo de inicialização.",
                "A associação foi preservada para contexto; isoladamente, ela não confirma ameaça.",
            )

        if metadado_shell_startup:
            adicionar(
                "METADADO_SHELL_STARTUP", "fraco",
                "Arquivo de metadados do shell reconhecido na pasta Startup.",
                "desktop.ini não é executável/script e não possui comando de execução associado.",
            )
        if assinatura == "Não assinada" and arquivo_assinavel:
            adicionar(
                "SEM_ASSINATURA", "fraco",
                "O arquivo não possui assinatura Authenticode válida.",
                "Ausência de assinatura é comum em software legítimo e não confirma ameaça.",
            )
        elif assinatura == "Inválida":
            adicionar(
                "ASSINATURA_INVALIDA", "medio",
                "A assinatura Authenticode foi reportada como inválida/não confiável.",
                "O status nativo deve ser verificado antes de confiar no arquivo.",
            )
        elif assinatura == "Válida":
            evidencias.append(
                "Assinatura Authenticode válida"
                + (f"; assinante: {publisher}." if publisher else ".")
            )

        atributos_normalizados = atributos.casefold()
        oculto = "hidden" in atributos_normalizados or "oculto" in atributos_normalizados
        sistema = "system" in atributos_normalizados or "sistema" in atributos_normalizados
        contexto_gravavel = any(
            flags.get(nome) for nome in ("Temp", "AppData", "Downloads", "Startup")
        )
        if oculto and contexto_gravavel and not metadado_shell_startup:
            adicionar(
                "ARQUIVO_OCULTO_EM_CONTEXTO_GRAVAVEL", "medio",
                "O arquivo está oculto em uma localização gravável pelo usuário.",
                "Atributo oculto e localização incomum foram correlacionados.",
            )
        elif oculto and not metadado_shell_startup:
            adicionar(
                "ARQUIVO_OCULTO", "fraco",
                "O arquivo possui atributo oculto.",
                "O atributo isolado pode ser legítimo e não confirma ameaça.",
            )
        if (
            sistema and contexto_gravavel and not flags.get("Windows")
            and not metadado_shell_startup
        ):
            adicionar(
                "ATRIBUTO_SISTEMA_FORA_WINDOWS", "medio",
                "O arquivo usa atributo de sistema em uma localização do usuário.",
                "Atributo e localização foram correlacionados; requer validação humana.",
            )
        if (
            persistencia
            and contexto_gravavel
            and oculto
            and assinatura != "Válida"
            and not metadado_shell_startup
        ):
            adicionar(
                "PERSISTENCIA_OCULTA_CAMINHO_GRAVAVEL", "forte",
                "Persistência, localização gravável e atributo oculto foram correlacionados.",
                "A correlação reúne múltiplos sinais; ainda assim, exige validação humana antes de qualquer ação.",
            )

        if caminho and flags.get("Absoluto") and existe is False:
            if tipo in {"Run", "RunOnce", "Startup", "Serviço", "Tarefa agendada"}:
                adicionar(
                    "ALVO_PERSISTENTE_AUSENTE", "medio",
                    "A persistência aponta para um arquivo que não estava disponível.",
                    "O arquivo pode ter sido removido ou estar inacessível; confirme o alvo manualmente.",
                )
                if tipo in {"Run", "RunOnce", "Serviço"} or tarefa_exec:
                    inconsistencia_objetiva = True
            else:
                adicionar(
                    "ARQUIVO_PROCESSO_INDISPONIVEL", "medio",
                    "O caminho do processo foi informado, mas o arquivo não estava disponível.",
                    "O estado pode ter mudado durante a coleta; repita a análise antes de concluir.",
                )

        nomes_sistema = {
            "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
            "csrss.exe", "smss.exe", "spoolsv.exe", "taskhostw.exe",
            "dllhost.exe", "explorer.exe",
        }
        nome_arquivo = ntpath.basename(caminho).casefold() if caminho else ""
        if nome_arquivo in nomes_sistema and not flags.get("Windows"):
            adicionar(
                "NOME_SISTEMA_FORA_DIRETORIO_WINDOWS", "medio",
                "O nome se parece com um componente do Windows, mas o caminho está fora do diretório Windows.",
                "A avaliação usa nome e localização em conjunto; não se baseia apenas no nome.",
            )

        criado = str(metadados.get("CriadoUtc") or "").strip()
        if criado and persistencia:
            try:
                instante = datetime.fromisoformat(criado.replace("Z", "+00:00"))
                agora = datetime.now(instante.tzinfo) if instante.tzinfo else datetime.now()
                idade_dias = (agora - instante).total_seconds() / 86400
                if 0 <= idade_dias <= 7:
                    adicionar(
                        "ARQUIVO_RECENTE_E_PERSISTENTE", "fraco",
                        "O arquivo foi criado recentemente e está associado à inicialização.",
                        "A data recente é apenas contexto e precisa ser correlacionada com origem, caminho e assinatura.",
                    )
            except (TypeError, ValueError, OverflowError):
                pass

        conta = str(resultado.get("Usuario") or resultado.get("ContextoUsuario") or "")
        if (
            tipo == "Serviço"
            and contexto_gravavel
            and re.search(r"(?i)(localsystem|sistema local|nt authority\\system)", conta)
        ):
            adicionar(
                "SERVICO_PRIVILEGIADO_CAMINHO_GRAVAVEL", "medio",
                "Um serviço privilegiado aponta para uma localização gravável pelo usuário.",
                "Conta do serviço e caminho foram correlacionados; confirme ACL e origem do binário.",
            )
        if (
            tipo == "Tarefa agendada"
            and contexto_gravavel
            and "highest" in str(resultado.get("NivelExecucao") or "").casefold()
        ):
            adicionar(
                "TAREFA_ELEVADA_CAMINHO_GRAVAVEL", "medio",
                "Uma tarefa com nível mais alto aponta para localização gravável pelo usuário.",
                "Nível de execução e caminho foram correlacionados.",
            )

        for sinal in ModuloSistema._sinais_comando_analise_defensiva(
            resultado.get("ComandoOriginal")
        ):
            adicionar(
                str(sinal.get("Codigo")), str(sinal.get("Forca")),
                str(sinal.get("Motivo")), str(sinal.get("Evidencia")),
            )

        processos_correlatos = list(correlacao.get("Processos") or [])
        persistencias_correlatas = list(correlacao.get("Persistencias") or [])
        parent_nome = str(resultado.get("ParentNome") or "").strip()
        if parent_nome:
            evidencias.append(
                f"Processo pai observado: {parent_nome} (PID {resultado.get('ParentPID') or '—'})."
            )
        if processos_correlatos and persistencias_correlatas:
            evidencias.append(
                "O mesmo caminho foi observado em processo ativo e mecanismo de inicialização."
            )
            if contexto_gravavel and assinatura != "Válida":
                adicionar(
                    "PROCESSO_E_PERSISTENCIA_CORRELACIONADOS", "medio",
                    "O mesmo caminho incomum aparece em execução e em persistência.",
                    "Processo, persistência, localização e assinatura foram avaliados em conjunto.",
                )

        if flags.get("System32") and assinatura == "Válida" and "microsoft" in publisher.casefold():
            evidencias.append(
                "Caminho System32 e assinatura Microsoft válida foram confirmados."
            )
        elif (flags.get("Windows") or flags.get("ProgramFiles")) and assinatura == "Válida":
            evidencias.append(
                "O caminho está em diretório geralmente confiável e a assinatura é válida."
            )

        chave_caminho = ModuloSistema._chave_caminho_analise_defensiva(caminho)
        raiz_programdata_microsoft = ntpath.join(
            str(contexto.get("ProgramData") or ""), "Microsoft"
        )
        em_programdata_microsoft = bool(
            contexto.get("ProgramData")
            and ModuloSistema._caminho_sob_raiz_analise_defensiva(
                caminho, raiz_programdata_microsoft
            )
        )
        em_programfiles_microsoft = bool(
            flags.get("ProgramFiles")
            and any(
                trecho in chave_caminho
                for trecho in ("\\microsoft\\", "\\windows defender\\")
            )
        )
        descricao_produto = " ".join(
            str(metadados.get(chave) or "")
            for chave in ("Empresa", "Produto")
        ).casefold()
        produto_microsoft_coerente = (
            not descricao_produto.strip()
            or any(
                termo in descricao_produto
                for termo in ("microsoft", "windows", "defender")
            )
        )
        contexto_microsoft_confiavel = bool(
            assinatura == "Válida"
            and "microsoft" in publisher.casefold()
            and produto_microsoft_coerente
            and (
                flags.get("System32")
                or flags.get("SysWOW64")
                or flags.get("WinSxS")
                or em_programdata_microsoft
                or em_programfiles_microsoft
            )
        )
        if contexto_microsoft_confiavel:
            evidencias.append(
                "Localização coerente, assinatura válida e publisher Microsoft foram correlacionados."
            )

        pesos = {"fraco": 1, "medio": 2, "forte": 3}
        fracos = sum(s.get("Forca") == "fraco" for s in sinais)
        medios = sum(s.get("Forca") == "medio" for s in sinais)
        fortes = sum(s.get("Forca") == "forte" for s in sinais)
        pontuacao = sum(pesos.get(s.get("Forca"), 0) for s in sinais)

        if (
            len(sinais) >= 3
            and pontuacao >= 6
            and (fortes >= 1 or medios >= 2)
        ):
            classificacao = "Suspeito"
        elif inconsistencia_objetiva:
            classificacao = "Requer análise"
        elif not caminho and tipo != "Processo":
            executavel_declarado = str(
                resultado.get("ExecutavelDeclarado") or ""
            ).strip()
            comando_declarado = str(
                resultado.get("ComandoOriginal") or ""
            ).strip()
            if tarefa_sem_executavel:
                adicionar(
                    "ACAO_SEM_EXECUTAVEL_DIRETO", "indeterminado",
                    "A ação não expõe um executável direto por seu tipo nativo.",
                    "A ausência de caminho em ações COM Handler/especiais é uma limitação esperada da fonte, não uma anomalia.",
                )
                classificacao = (
                    "Atenção" if fortes >= 1 or medios >= 1 else "Informativo"
                )
            elif tarefa_exec or executavel_declarado or comando_declarado:
                adicionar(
                    "ALVO_DECLARADO_NAO_RESOLVIDO", "indeterminado",
                    "Um alvo executável declarado não pôde ser resolvido com segurança.",
                    "A configuração declara execução, mas não produziu um caminho absoluto verificável.",
                )
                classificacao = "Requer análise"
            else:
                adicionar(
                    "FONTE_SEM_ALVO_EXPOSTO", "indeterminado",
                    "A fonte não disponibilizou um alvo executável nesta sessão.",
                    "Ausência de dado foi registrada como limitação de coleta, sem presumir anomalia.",
                )
                classificacao = "Não disponível"
        elif fortes >= 1 or medios >= 1 or fracos >= 2:
            classificacao = "Atenção"
        elif fracos == 1:
            classificacao = "Informativo"
        elif caminho and existe is None:
            classificacao = "Não disponível"
            adicionar(
                "METADADOS_NAO_DISPONIVEIS", "indeterminado",
                "Os metadados do arquivo não ficaram disponíveis nesta sessão.",
                "O caminho foi preservado, mas existência e assinatura não puderam ser confirmadas.",
            )
        elif not caminho and tipo == "Processo":
            classificacao = "Não disponível"
        else:
            classificacao = "Normal"

        # Uma assinatura válida com editor identificado reduz falsos positivos
        # quando restam apenas sinais fracos de localização/inicialização.
        if (
            classificacao == "Atenção"
            and assinatura == "Válida"
            and publisher
            and medios == 0
            and fortes == 0
        ):
            classificacao = "Informativo"
        if (
            classificacao == "Atenção"
            and contexto_microsoft_confiavel
            and medios == 0
            and fortes == 0
        ):
            classificacao = "Informativo"

        ordem_forca = {"forte": 3, "medio": 2, "fraco": 1, "indeterminado": 0}
        sinais_ordenados = sorted(
            sinais,
            key=lambda sinal: ordem_forca.get(str(sinal.get("Forca")), 0),
            reverse=True,
        )
        if classificacao == "Requer análise":
            sinal_indeterminado = next(
                (
                    sinal for sinal in sinais_ordenados
                    if sinal.get("Codigo") in {
                        "ALVO_DECLARADO_NAO_RESOLVIDO",
                        "ALVO_PERSISTENTE_AUSENTE",
                    }
                ),
                None,
            )
            motivo_principal = str(
                (sinal_indeterminado or {}).get("Motivo")
                or "Os dados disponíveis exigem conferência humana."
            )
        elif sinais_ordenados:
            motivo_principal = str(sinais_ordenados[0].get("Motivo") or "")
        elif classificacao == "Normal":
            motivo_principal = "Nenhum sinal de atenção foi correlacionado."
        elif classificacao == "Não disponível":
            motivo_principal = "O Windows não disponibilizou o caminho deste processo."
        else:
            motivo_principal = "Os dados disponíveis exigem conferência humana."

        recomendacoes = {
            "Suspeito": (
                "Valide origem, assinatura, necessidade e persistência com as ferramentas "
                "corporativas antes de qualquer ação manual."
            ),
            "Atenção": (
                "Confirme publisher, origem e necessidade do software; repita a coleta se "
                "o arquivo tiver mudado."
            ),
            "Requer análise": (
                "Resolva o alvo e confira a configuração manualmente antes de concluir."
            ),
        }
        limitacoes = [
            "A classificação é uma triagem local e não confirma malware.",
            "AppData, Temp, persistência e ausência de assinatura podem ser legítimos isoladamente.",
        ]
        if assinatura == "Não disponível" and arquivo_assinavel:
            limitacoes.append(
                "A assinatura não pôde ser determinada nesta sessão."
            )
        erro_metadados = str(metadados.get("ErroTipo") or "")
        if erro_metadados == "CaminhoRedeNaoConsultado":
            limitacoes.append(
                "O alvo UNC não foi aberto automaticamente para evitar acesso de rede."
            )
        elif erro_metadados == "LimiteConsultaAssinatura":
            limitacoes.append(
                "A assinatura ficou fora do lote prioritário; os metadados básicos foram preservados."
            )
        elif erro_metadados == "AcessoNegado":
            limitacoes.append(
                "O Windows negou acesso aos metadados deste arquivo nesta sessão."
            )
        elif erro_metadados in {
            "ConsultaIndisponivel", "ArquivoAusenteOuInacessivel"
        }:
            limitacoes.append(
                "A fonte nativa não disponibilizou todos os metadados do arquivo."
            )
        if tarefa_sem_executavel:
            limitacoes.append(
                "Este tipo de ação agendada não expõe um executável direto."
            )
        for limite_origem in resultado.get("LimitacoesOrigem") or []:
            limite_texto = str(limite_origem or "").strip()
            if limite_texto and limite_texto not in limitacoes:
                limitacoes.append(limite_texto)

        perfil = str(contexto.get("UserProfile") or "").strip()
        caminho_exibicao = caminho
        if perfil and caminho_exibicao:
            caminho_exibicao = re.sub(
                re.escape(perfil), "%USERPROFILE%", caminho_exibicao,
                flags=re.IGNORECASE,
            )
        resultado.update(
            {
                "CaminhoExibicao": caminho_exibicao or "—",
                "Assinatura": assinatura,
                "Publisher": publisher or "—",
                "Empresa": str(metadados.get("Empresa") or "—"),
                "Produto": str(metadados.get("Produto") or "—"),
                "Existe": existe,
                "TamanhoBytes": metadados.get("TamanhoBytes"),
                "CriadoUtc": criado or "—",
                "ModificadoUtc": str(metadados.get("ModificadoUtc") or "—"),
                "Atributos": atributos or "—",
                "Classificacao": classificacao,
                "MotivoPrincipal": motivo_principal,
                "Motivos": [str(s.get("Motivo") or "") for s in sinais_ordenados],
                "Evidencias": evidencias + [
                    str(s.get("Evidencia") or "") for s in sinais_ordenados
                ],
                "Sinais": sinais_ordenados,
                "QuantidadeSinais": len(sinais_ordenados),
                "Recomendacao": recomendacoes.get(classificacao, ""),
                "Limitacoes": limitacoes,
                "Correlacoes": {
                    "Processos": processos_correlatos,
                    "Persistencias": persistencias_correlatas,
                },
                "SHA256": "—",
                "HashStatus": "Não calculado",
            }
        )
        return resultado

    @staticmethod
    def _script_coleta_analise_defensiva() -> str:
        return r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$erros = @()

function DataIso($valor) {
    if ($null -eq $valor) { return $null }
    try { return ([datetime]$valor).ToUniversalTime().ToString('o') }
    catch { return [string]$valor }
}

$contexto = [ordered]@{
    WindowsDirectory = [Environment]::GetFolderPath('Windows')
    ProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
    ProgramFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    ProgramData = [Environment]::GetFolderPath('CommonApplicationData')
    UserProfile = [Environment]::GetFolderPath('UserProfile')
    AppData = [Environment]::GetFolderPath('ApplicationData')
    LocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
    Temp = [IO.Path]::GetTempPath()
    WindowsTemp = [IO.Path]::Combine([Environment]::GetFolderPath('Windows'), 'Temp')
    ComSpec = [string]$env:ComSpec
    SystemDrive = [string]$env:SystemDrive
    Downloads = [IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), 'Downloads')
    StartupUser = [Environment]::GetFolderPath('Startup')
    StartupCommon = [Environment]::GetFolderPath('CommonStartup')
}

$usuarios = @{}
try {
    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object {
        $chave = [string]$_.Id
        if ($chave) { $usuarios[$chave] = [string]$_.UserName }
    }
}
catch { $erros += 'Processos:usuario_indisponivel' }

$processos = @()
try {
    $processos = @(
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
            $processo = $_
            $chave = [string]$processo.ProcessId
            [PSCustomObject]@{
                PID = $processo.ProcessId
                Nome = [string]$processo.Name
                Caminho = [string]$processo.ExecutablePath
                Comando = [string]$processo.CommandLine
                ParentPID = $processo.ParentProcessId
                Usuario = [string]$usuarios[$chave]
                CriadoEm = DataIso $processo.CreationDate
            }
        }
    )
}
catch { $erros += 'Processos:coleta_indisponivel' }

function ColetarRun($hive, $escopo, $view, $arquitetura, $subchave, $tipo) {
    $base = $null
    $chave = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        $chave = $base.OpenSubKey($subchave, $false)
        if ($null -eq $chave) { return @() }
        return @(
            foreach ($nome in $chave.GetValueNames()) {
                [PSCustomObject]@{
                    Tipo = $tipo
                    Escopo = $escopo
                    Arquitetura = $arquitetura
                    Nome = [string]$nome
                    Comando = [string]$chave.GetValue(
                        $nome, $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                }
            }
        )
    }
    catch {
        $script:erros += ('Registro:{0}:{1}:{2}' -f $escopo, $arquitetura, $tipo)
        return @()
    }
    finally {
        if ($null -ne $chave) { $chave.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
}

$run = @()
$views = @(
    [PSCustomObject]@{
        Valor = [Microsoft.Win32.RegistryView]::Registry32
        Nome = '32-bit'
    }
)
if ([Environment]::Is64BitOperatingSystem) {
    $views += [PSCustomObject]@{
        Valor = [Microsoft.Win32.RegistryView]::Registry64
        Nome = '64-bit'
    }
}
foreach ($view in $views) {
    foreach ($definicao in @(
        [PSCustomObject]@{ Tipo = 'Run'; Sub = 'Software\Microsoft\Windows\CurrentVersion\Run' },
        [PSCustomObject]@{ Tipo = 'RunOnce'; Sub = 'Software\Microsoft\Windows\CurrentVersion\RunOnce' }
    )) {
        $run += @(ColetarRun (
            [Microsoft.Win32.RegistryHive]::CurrentUser
        ) 'HKCU' $view.Valor $view.Nome $definicao.Sub $definicao.Tipo)
        $run += @(ColetarRun (
            [Microsoft.Win32.RegistryHive]::LocalMachine
        ) 'HKLM' $view.Valor $view.Nome $definicao.Sub $definicao.Tipo)
    }
}

$startup = @()
$shell = $null
try { $shell = New-Object -ComObject WScript.Shell }
catch { $erros += 'Startup:atalhos_indisponiveis' }
foreach ($pastaInfo in @(
    [PSCustomObject]@{ Escopo = 'Usuário'; Caminho = $contexto.StartupUser },
    [PSCustomObject]@{ Escopo = 'Comum'; Caminho = $contexto.StartupCommon }
)) {
    if ([string]::IsNullOrWhiteSpace([string]$pastaInfo.Caminho)) { continue }
    try {
        foreach ($arquivo in @(Get-ChildItem -LiteralPath $pastaInfo.Caminho -Force -File -ErrorAction Stop)) {
            $alvo = [string]$arquivo.FullName
            $argumentos = ''
            $ehAtalho = $arquivo.Extension -ieq '.lnk'
            if ($ehAtalho -and $null -ne $shell) {
                try {
                    $atalho = $shell.CreateShortcut($arquivo.FullName)
                    $alvo = [string]$atalho.TargetPath
                    $argumentos = [string]$atalho.Arguments
                }
                catch {}
            }
            $startup += [PSCustomObject]@{
                Escopo = [string]$pastaInfo.Escopo
                Nome = [string]$arquivo.Name
                Arquivo = [string]$arquivo.FullName
                Alvo = $alvo
                Argumentos = $argumentos
                EhAtalho = [bool]$ehAtalho
            }
        }
    }
    catch { $erros += ('Startup:{0}' -f $pastaInfo.Escopo) }
}
if ($null -ne $shell) {
    try { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
    catch {}
}

$servicos = @()
try {
    $servicos = @(
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Nome = [string]$_.Name
                DisplayName = [string]$_.DisplayName
                Estado = [string]$_.State
                StartMode = [string]$_.StartMode
                PathName = [string]$_.PathName
                Conta = [string]$_.StartName
            }
        }
    )
}
catch { $erros += 'Servicos:coleta_indisponivel' }

$tarefas = @()
try {
    foreach ($tarefa in @(Get-ScheduledTask -ErrorAction Stop)) {
        $gatilhos = @(
            foreach ($gatilho in @($tarefa.Triggers)) {
                $tipo = [string]$gatilho.CimClass.CimClassName
                $inicio = [string]$gatilho.StartBoundary
                if ($inicio) { '{0} ({1})' -f $tipo, $inicio } else { $tipo }
            }
        ) -join ', '
        $acoes = @($tarefa.Actions)
        if ($acoes.Count -eq 0) { $acoes = @($null) }
        foreach ($acao in $acoes) {
            $classeAcao = if ($null -ne $acao) {
                [string]$acao.CimClass.CimClassName
            } else { '' }
            $tipoAcao = if ($classeAcao -match 'TaskExecAction') {
                'Exec'
            } elseif ($classeAcao -match 'TaskComHandlerAction') {
                'COM Handler'
            } elseif ($classeAcao) {
                $classeAcao
            } else {
                'Sem ação exposta'
            }
            $tarefas += [PSCustomObject]@{
                Nome = [string]$tarefa.TaskName
                CaminhoTarefa = [string]$tarefa.TaskPath
                Estado = [string]$tarefa.State
                Habilitada = if ($null -ne $tarefa.Settings.Enabled) {
                    [bool]$tarefa.Settings.Enabled
                } else { $true }
                TipoAcao = $tipoAcao
                ClasseAcao = $classeAcao
                Executavel = if ($null -ne $acao) { [string]$acao.Execute } else { '' }
                Argumentos = if ($null -ne $acao) { [string]$acao.Arguments } else { '' }
                DiretorioTrabalho = if ($null -ne $acao) { [string]$acao.WorkingDirectory } else { '' }
                ClassId = if ($null -ne $acao) { [string]$acao.ClassId } else { '' }
                Gatilhos = $gatilhos
                Usuario = [string]$tarefa.Principal.UserId
                NivelExecucao = [string]$tarefa.Principal.RunLevel
                TipoLogon = [string]$tarefa.Principal.LogonType
                Autor = [string]$tarefa.Author
            }
        }
    }
}
catch { $erros += 'TarefasAgendadas:coleta_indisponivel' }

$defender = [ordered]@{ Disponivel = $false }
try {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defender = [ordered]@{
            Disponivel = $true
            AntivirusAtivo = [bool]$mp.AntivirusEnabled
            TempoRealAtivo = [bool]$mp.RealTimeProtectionEnabled
            ServicoAtivo = [bool]$mp.AMServiceEnabled
            MonitorComportamentoAtivo = [bool]$mp.BehaviorMonitorEnabled
            AssinaturasAtualizadasEm = DataIso $mp.AntivirusSignatureLastUpdated
        }
    }
}
catch { $erros += 'Defender:status_indisponivel' }

[PSCustomObject]@{
    Contexto = [PSCustomObject]$contexto
    Processos = @($processos)
    Run = @($run)
    Startup = @($startup)
    Servicos = @($servicos)
    Tarefas = @($tarefas)
    Defender = [PSCustomObject]$defender
    Erros = @($erros)
} | ConvertTo-Json -Depth 9 -Compress
"""

    @staticmethod
    def _coletar_metadados_arquivos_analise_defensiva(
        caminhos: List[str], cancel_callback=None, limite_assinaturas: int = 180
    ) -> Dict[str, Dict[str, Any]]:
        """Lê metadados básicos e consulta assinaturas prioritárias em lotes."""
        resultados: Dict[str, Dict[str, Any]] = {}
        pendentes: List[str] = []
        vistos = set()
        assinaturas_cache = {}

        for caminho in caminhos or []:
            normalizado = ModuloSistema._normalizar_caminho_analise_defensiva(
                caminho
            )
            chave = ModuloSistema._chave_caminho_analise_defensiva(normalizado)
            if not chave or chave in vistos:
                continue
            vistos.add(chave)
            # Caminhos UNC são exibidos e classificados, mas não são abertos
            # automaticamente: a triagem não deve gerar acesso de rede.
            if normalizado.startswith("\\\\"):
                resultados[chave] = {
                    "Caminho": normalizado,
                    "Existe": None,
                    "AssinaturaStatus": "Unavailable",
                    "ErroTipo": "CaminhoRedeNaoConsultado",
                }
                continue
            identidade = None
            try:
                estado = os.stat(normalizado)
                identidade = (chave, int(estado.st_size), int(estado.st_mtime_ns))
                atributos_arquivo = int(
                    getattr(estado, "st_file_attributes", 0) or 0
                )
                nomes_atributos = []
                for nome, constante in (
                    ("Hidden", getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 0)),
                    ("System", getattr(stat, "FILE_ATTRIBUTE_SYSTEM", 0)),
                    ("ReadOnly", getattr(stat, "FILE_ATTRIBUTE_READONLY", 0)),
                    ("Archive", getattr(stat, "FILE_ATTRIBUTE_ARCHIVE", 0)),
                ):
                    if constante and atributos_arquivo & constante:
                        nomes_atributos.append(nome)
                resultados[chave] = {
                    "Caminho": normalizado,
                    "Existe": True,
                    "TamanhoBytes": int(estado.st_size),
                    "CriadoUtc": datetime.utcfromtimestamp(
                        estado.st_ctime
                    ).isoformat() + "Z",
                    "ModificadoUtc": datetime.utcfromtimestamp(
                        estado.st_mtime
                    ).isoformat() + "Z",
                    "Atributos": ", ".join(nomes_atributos) or "Normal",
                    "AssinaturaStatus": "Unavailable",
                    "Publisher": "",
                    "Empresa": "",
                    "Produto": "",
                    "ErroTipo": "AssinaturaNaoConsultada",
                }
            except FileNotFoundError:
                resultados[chave] = {
                    "Caminho": normalizado,
                    "Existe": False,
                    "AssinaturaStatus": "Unavailable",
                    "ErroTipo": "ArquivoAusente",
                }
                continue
            except PermissionError:
                resultados[chave] = {
                    "Caminho": normalizado,
                    "Existe": None,
                    "AssinaturaStatus": "Unavailable",
                    "ErroTipo": "AcessoNegado",
                }
            except OSError as exc:
                resultados[chave] = {
                    "Caminho": normalizado,
                    "Existe": None,
                    "AssinaturaStatus": "Unavailable",
                    "ErroTipo": type(exc).__name__,
                }
            if identidade is not None:
                with _lock_cache_analise_defensiva:
                    cache = _cache_assinaturas_analise_defensiva.get(identidade)
                if isinstance(cache, dict):
                    resultados[chave] = dict(cache)
                    continue
            pendentes.append(normalizado)
            assinaturas_cache[chave] = identidade

        limite = max(0, min(300, int(limite_assinaturas)))
        excedentes = pendentes[limite:]
        pendentes = pendentes[:limite]
        for caminho in excedentes:
            chave = ModuloSistema._chave_caminho_analise_defensiva(caminho)
            if chave in resultados:
                resultados[chave]["ErroTipo"] = "LimiteConsultaAssinatura"

        indice = 0
        while indice < len(pendentes):
            if ModuloSistema._cancelamento_analise_defensiva_solicitado(
                cancel_callback
            ):
                break
            lote: List[str] = []
            caracteres = 0
            while indice < len(pendentes) and len(lote) < 40:
                candidato = pendentes[indice]
                custo = len(candidato) + 8
                if lote and caracteres + custo > 16000:
                    break
                lote.append(candidato)
                caracteres += custo
                indice += 1
            literais = ",\n".join(
                "'" + caminho.replace("'", "''") + "'" for caminho in lote
            )
            script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$caminhos = @(
__CAMINHOS__
)
$resultado = @(
    foreach ($caminho in $caminhos) {
        if (-not (Test-Path -LiteralPath $caminho -PathType Leaf)) {
            [PSCustomObject]@{
                Caminho = [string]$caminho
                Existe = $false
                AssinaturaStatus = 'Unavailable'
                ErroTipo = 'ArquivoAusenteOuInacessivel'
            }
            continue
        }
        try {
            $arquivo = Get-Item -LiteralPath $caminho -Force -ErrorAction Stop
            $assinatura = Get-AuthenticodeSignature -LiteralPath $caminho -ErrorAction SilentlyContinue
            $versao = $arquivo.VersionInfo
            [PSCustomObject]@{
                Caminho = [string]$arquivo.FullName
                Existe = $true
                TamanhoBytes = [int64]$arquivo.Length
                CriadoUtc = $arquivo.CreationTimeUtc.ToString('o')
                ModificadoUtc = $arquivo.LastWriteTimeUtc.ToString('o')
                Atributos = [string]$arquivo.Attributes
                AssinaturaStatus = if ($null -ne $assinatura) {
                    [string]$assinatura.Status
                } else { 'Unavailable' }
                Publisher = if ($null -ne $assinatura.SignerCertificate) {
                    [string]$assinatura.SignerCertificate.Subject
                } else { $null }
                Empresa = if ($null -ne $versao) {
                    [string]$versao.CompanyName
                } else { $null }
                Produto = if ($null -ne $versao) {
                    [string]$versao.ProductName
                } else { $null }
                ErroTipo = $null
            }
        }
        catch {
            [PSCustomObject]@{
                Caminho = [string]$caminho
                Existe = $false
                AssinaturaStatus = 'Unavailable'
                ErroTipo = [string]$_.Exception.GetType().Name
            }
        }
    }
)
@($resultado) | ConvertTo-Json -Depth 5 -Compress
""".replace("__CAMINHOS__", literais)
            try:
                resposta = executar_powershell(script, timeout=45)
                if resposta.returncode != 0:
                    itens = []
                else:
                    bruto = json.loads((resposta.stdout or "[]").lstrip("\ufeff"))
                    itens = ModuloSistema._lista_json_analise_defensiva(bruto)
            except Exception:
                itens = []

            recebidos = set()
            for item in itens:
                chave = ModuloSistema._chave_caminho_analise_defensiva(
                    item.get("Caminho")
                )
                if not chave:
                    continue
                recebidos.add(chave)
                normalizado = dict(item)
                resultados[chave] = normalizado
                identidade = assinaturas_cache.get(chave)
                if identidade is not None and normalizado.get("Existe") is True:
                    with _lock_cache_analise_defensiva:
                        _cache_assinaturas_analise_defensiva[identidade] = dict(
                            normalizado
                        )
            for caminho in lote:
                chave = ModuloSistema._chave_caminho_analise_defensiva(caminho)
                if chave not in recebidos and chave not in resultados:
                    resultados[chave] = {
                        "Caminho": caminho,
                        "Existe": None,
                        "AssinaturaStatus": "Unavailable",
                        "ErroTipo": "ConsultaIndisponivel",
                    }
        return resultados

    @staticmethod
    def obter_analise_defensiva(
        progress_callback=None, cancel_callback=None
    ) -> Dict[str, Any]:
        """Triagem local, conservadora e somente leitura do Windows."""
        inicio = time.monotonic()
        if not _lock_analise_defensiva.acquire(blocking=False):
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": "Já existe uma análise defensiva em andamento.",
                "Itens": [],
            }
        ModuloSistema._registrar_evento_analise_defensiva(
            "ANALISE_DEFENSIVA_INICIADA", "origem=acao_explicita"
        )
        try:
            if ModuloSistema._cancelamento_analise_defensiva_solicitado(
                cancel_callback
            ):
                ModuloSistema._registrar_evento_analise_defensiva(
                    "ANALISE_DEFENSIVA_CANCELADA", "etapa=antes_coleta"
                )
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Análise defensiva cancelada antes da coleta.",
                    "Itens": [],
                }
            if not sys.platform.startswith("win"):
                raise RuntimeError(
                    "A análise defensiva está disponível somente no Windows."
                )

            ModuloSistema._emitir_progresso_analise_defensiva(
                progress_callback, 5, "Coletando processos e persistências..."
            )
            resposta = executar_powershell(
                ModuloSistema._script_coleta_analise_defensiva(), timeout=90
            )
            if resposta.returncode != 0 or not (resposta.stdout or "").strip():
                raise RuntimeError(
                    "A coleta nativa não retornou dados utilizáveis."
                )
            bruto = json.loads((resposta.stdout or "{}").lstrip("\ufeff"))
            if not isinstance(bruto, dict):
                raise ValueError("A coleta nativa retornou formato inválido.")
            if ModuloSistema._cancelamento_analise_defensiva_solicitado(
                cancel_callback
            ):
                ModuloSistema._registrar_evento_analise_defensiva(
                    "ANALISE_DEFENSIVA_CANCELADA", "etapa=apos_coleta"
                )
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Análise defensiva cancelada após a coleta nativa.",
                    "Itens": [],
                }

            contexto = bruto.get("Contexto") if isinstance(bruto.get("Contexto"), dict) else {}
            itens: List[Dict[str, Any]] = []

            def adicionar_item(
                tipo: str,
                nome: Any,
                caminho_direto: Any = "",
                comando: Any = "",
                pid: Any = "",
                usuario: Any = "",
                parent_pid: Any = "",
                persistencia_ativa: bool = False,
                **extras,
            ) -> None:
                caminhos: List[str] = []
                direto = ModuloSistema._normalizar_caminho_analise_defensiva(
                    caminho_direto, contexto
                )
                if (
                    direto
                    and ModuloSistema._caminho_absoluto_windows_analise_defensiva(
                        direto
                    )
                ):
                    caminhos.append(direto)
                for associado in ModuloSistema._extrair_caminhos_comando_analise_defensiva(
                    comando, contexto
                ):
                    if ModuloSistema._chave_caminho_analise_defensiva(associado) not in {
                        ModuloSistema._chave_caminho_analise_defensiva(valor)
                        for valor in caminhos
                    }:
                        caminhos.append(associado)
                principal = caminhos[0] if caminhos else ""
                limitacoes_origem = []
                comando_texto = str(comando or "")
                if (
                    re.search(r"(?i)\brundll32(?:\.exe)?\b", comando_texto)
                    and re.search(r"(?i)\.dll\s*,", comando_texto)
                    and len(caminhos) < 2
                ):
                    limitacoes_origem.append(
                        "A DLL informada ao rundll32 não pôde ser resolvida com segurança."
                    )
                registro = {
                    "Tipo": str(tipo),
                    "Nome": str(nome or "Sem nome"),
                    "PID": str(pid) if pid not in (None, "") else "—",
                    "Caminho": principal,
                    "CaminhosAssociados": caminhos,
                    "ComandoOriginal": str(comando or ""),
                    "Comando": ModuloSistema._sanitizar_comando_analise_defensiva(
                        comando, contexto
                    ),
                    "Usuario": str(usuario or "—"),
                    "ParentPID": str(parent_pid) if parent_pid not in (None, "") else "—",
                    "PersistenciaAtiva": bool(persistencia_ativa),
                    "LimitacoesOrigem": limitacoes_origem,
                }
                registro.update(extras)
                itens.append(registro)

            for processo in ModuloSistema._lista_json_analise_defensiva(
                bruto.get("Processos")
            ):
                adicionar_item(
                    "Processo", processo.get("Nome"), processo.get("Caminho"),
                    processo.get("Comando"), processo.get("PID"),
                    processo.get("Usuario"), processo.get("ParentPID"), False,
                    CriadoProcesso=str(processo.get("CriadoEm") or "—"),
                    Fonte="Win32_Process",
                )

            run_agrupado: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
            for entrada in ModuloSistema._lista_json_analise_defensiva(bruto.get("Run")):
                tipo = str(entrada.get("Tipo") or "Run")
                escopo = str(entrada.get("Escopo") or "Registro")
                nome = str(entrada.get("Nome") or "Sem nome")
                comando = str(entrada.get("Comando") or "")
                chave_run = (
                    tipo.casefold(), escopo.casefold(), nome.casefold(),
                    comando.strip().casefold(),
                )
                agrupado = run_agrupado.setdefault(
                    chave_run,
                    {
                        "Tipo": tipo,
                        "Escopo": escopo,
                        "Nome": nome,
                        "Comando": comando,
                        "Arquiteturas": [],
                    },
                )
                arquitetura = str(
                    entrada.get("Arquitetura") or "visão padrão"
                )
                if arquitetura not in agrupado["Arquiteturas"]:
                    agrupado["Arquiteturas"].append(arquitetura)

            for entrada in run_agrupado.values():
                adicionar_item(
                    entrada.get("Tipo"), entrada.get("Nome"), "", entrada.get("Comando"),
                    usuario=entrada.get("Escopo"), persistencia_ativa=True,
                    ContextoUsuario=str(entrada.get("Escopo") or "—"),
                    Fonte=(
                        f"{entrada.get('Escopo') or 'Registro'} / "
                        f"{', '.join(entrada.get('Arquiteturas') or ['visão padrão'])}"
                    ),
                )

            for entrada in ModuloSistema._lista_json_analise_defensiva(
                bruto.get("Startup")
            ):
                alvo = entrada.get("Alvo") or entrada.get("Arquivo")
                metadado_shell_startup = (
                    not bool(entrada.get("EhAtalho"))
                    and ntpath.basename(str(entrada.get("Arquivo") or "")).casefold()
                    == "desktop.ini"
                )
                executavel_startup = not metadado_shell_startup
                comando = (
                    " ".join(
                        parte for parte in (
                            str(alvo or ""),
                            str(entrada.get("Argumentos") or ""),
                        ) if parte
                    )
                    if executavel_startup
                    else ""
                )
                adicionar_item(
                    "Startup", entrada.get("Nome"), alvo, comando,
                    usuario=entrada.get("Escopo"),
                    persistencia_ativa=executavel_startup,
                    ContextoUsuario=str(entrada.get("Escopo") or "—"),
                    ArquivoStartup=str(entrada.get("Arquivo") or "—"),
                    ComandoExecucaoExplicito=executavel_startup,
                    Fonte="Pasta Startup",
                )

            for servico in ModuloSistema._lista_json_analise_defensiva(
                bruto.get("Servicos")
            ):
                start_mode = str(servico.get("StartMode") or "")
                adicionar_item(
                    "Serviço", servico.get("DisplayName") or servico.get("Nome"),
                    "", servico.get("PathName"), usuario=servico.get("Conta"),
                    persistencia_ativa=start_mode.casefold() in {"auto", "automatic"},
                    NomeTecnico=str(servico.get("Nome") or "—"),
                    Estado=str(servico.get("Estado") or "—"),
                    Inicializacao=start_mode or "—",
                    ContextoUsuario=str(servico.get("Conta") or "—"),
                    Fonte="Win32_Service",
                )

            for tarefa in ModuloSistema._lista_json_analise_defensiva(
                bruto.get("Tarefas")
            ):
                tipo_acao = str(tarefa.get("TipoAcao") or "Sem ação exposta")
                acao_exec = tipo_acao.casefold() == "exec"
                comando = " ".join(
                    parte for parte in (
                        str(tarefa.get("Executavel") or ""),
                        str(tarefa.get("Argumentos") or ""),
                    ) if parte
                ) if acao_exec else ""
                habilitada = bool(tarefa.get("Habilitada", True))
                adicionar_item(
                    "Tarefa agendada", tarefa.get("Nome"),
                    tarefa.get("Executavel"), comando,
                    usuario=tarefa.get("Usuario"),
                    persistencia_ativa=habilitada,
                    ContextoUsuario=str(tarefa.get("Usuario") or "—"),
                    CaminhoTarefa=str(tarefa.get("CaminhoTarefa") or "\\"),
                    Estado=str(tarefa.get("Estado") or "—"),
                    Habilitada=habilitada,
                    TipoAcao=tipo_acao,
                    ClasseAcao=str(tarefa.get("ClasseAcao") or "—"),
                    ClassIdAcao=str(tarefa.get("ClassId") or "—"),
                    AutorTarefa=str(tarefa.get("Autor") or "—"),
                    ExecutavelDeclarado=str(tarefa.get("Executavel") or ""),
                    Gatilhos=str(tarefa.get("Gatilhos") or "—"),
                    NivelExecucao=str(tarefa.get("NivelExecucao") or "—"),
                    TipoLogon=str(tarefa.get("TipoLogon") or "—"),
                    DiretorioTrabalho=str(tarefa.get("DiretorioTrabalho") or "—"),
                    Fonte="Get-ScheduledTask",
                )

            processos_por_pid = {
                str(item.get("PID")): item
                for item in itens
                if item.get("Tipo") == "Processo" and item.get("PID") not in (None, "", "—")
            }
            for item in itens:
                if item.get("Tipo") != "Processo":
                    continue
                pai = processos_por_pid.get(str(item.get("ParentPID") or ""))
                if pai is not None:
                    item["ParentNome"] = str(pai.get("Nome") or "—")
                    item["ParentCaminho"] = str(pai.get("Caminho") or "")

            # Um host legítimo (por exemplo, powershell.exe ou cmd.exe) pode
            # carregar um script diretamente associado. Esses alvos secundários
            # também pertencem ao escopo da triagem, mas são apresentados como
            # itens próprios para que os metadados do host não escondam os do
            # arquivo efetivamente acionado. Nenhum caminho adicional é buscado.
            itens_associados: List[Dict[str, Any]] = []
            for origem in list(itens):
                associados = list(origem.get("CaminhosAssociados") or [])
                for caminho_associado in associados[1:]:
                    itens_associados.append(
                        {
                            "Tipo": "Arquivo associado",
                            "Nome": ntpath.basename(caminho_associado) or "Arquivo associado",
                            "PID": str(origem.get("PID") or "—"),
                            "Caminho": caminho_associado,
                            "CaminhosAssociados": [caminho_associado],
                            "ComandoOriginal": str(origem.get("ComandoOriginal") or ""),
                            "Comando": str(origem.get("Comando") or "—"),
                            "Usuario": str(origem.get("Usuario") or "—"),
                            "ContextoUsuario": str(
                                origem.get("ContextoUsuario")
                                or origem.get("Usuario")
                                or "—"
                            ),
                            "ParentPID": str(origem.get("ParentPID") or "—"),
                            "ParentNome": str(origem.get("ParentNome") or "—"),
                            "PersistenciaAtiva": bool(
                                origem.get("PersistenciaAtiva")
                            ),
                            "OrigemTipo": str(origem.get("Tipo") or "—"),
                            "OrigemNome": str(origem.get("Nome") or "—"),
                            "Fonte": (
                                f"Associado a {origem.get('Tipo') or 'item'}: "
                                f"{origem.get('Nome') or 'sem nome'}"
                            ),
                        }
                    )
            itens.extend(itens_associados)

            ModuloSistema._emitir_progresso_analise_defensiva(
                progress_callback, 35, "Deduplicando caminhos associados..."
            )
            caminhos_unicos: List[str] = []
            chaves_caminhos = set()
            for item in itens:
                for caminho in item.get("CaminhosAssociados") or []:
                    chave = ModuloSistema._chave_caminho_analise_defensiva(caminho)
                    if chave and chave not in chaves_caminhos:
                        chaves_caminhos.add(chave)
                        caminhos_unicos.append(caminho)

            caminhos_processos = {
                ModuloSistema._chave_caminho_analise_defensiva(item.get("Caminho"))
                for item in itens
                if item.get("Tipo") == "Processo" and item.get("Caminho")
            }

            def prioridade_assinatura(caminho):
                flags = ModuloSistema._contexto_caminho_analise_defensiva(
                    caminho, contexto
                )
                chave = ModuloSistema._chave_caminho_analise_defensiva(caminho)
                if any(
                    flags.get(nome)
                    for nome in ("Temp", "AppData", "Downloads", "Startup")
                ):
                    return 0
                if chave in caminhos_processos:
                    return 1
                if flags.get("Windows") or flags.get("ProgramFiles"):
                    return 3
                return 2

            # A ordem prioriza contextos graváveis e processos ativos. Os
            # demais caminhos ainda recebem metadados básicos locais, mas a
            # consulta Authenticode tem limite explícito para não alongar a
            # coleta indefinidamente em estações com muitas tarefas/serviços.
            caminhos_unicos.sort(key=prioridade_assinatura)

            ModuloSistema._emitir_progresso_analise_defensiva(
                progress_callback, 45, "Consultando assinaturas e metadados em lotes..."
            )
            metadados = ModuloSistema._coletar_metadados_arquivos_analise_defensiva(
                caminhos_unicos, cancel_callback=cancel_callback,
                limite_assinaturas=180,
            )
            if ModuloSistema._cancelamento_analise_defensiva_solicitado(
                cancel_callback
            ):
                ModuloSistema._registrar_evento_analise_defensiva(
                    "ANALISE_DEFENSIVA_CANCELADA", "etapa=metadados"
                )
                return {
                    "Sucesso": False,
                    "Cancelada": True,
                    "Mensagem": "Análise defensiva cancelada durante os metadados.",
                    "Itens": [],
                }

            correlacoes: Dict[str, Dict[str, List[str]]] = {}
            for item in itens:
                chave = ModuloSistema._chave_caminho_analise_defensiva(
                    item.get("Caminho")
                )
                if not chave:
                    continue
                grupo = correlacoes.setdefault(
                    chave, {"Processos": [], "Persistencias": []}
                )
                nome = str(item.get("Nome") or "Sem nome")
                origem_tipo = str(item.get("OrigemTipo") or "")
                origem_nome = str(item.get("OrigemNome") or nome)
                if item.get("Tipo") == "Processo" or (
                    item.get("Tipo") == "Arquivo associado"
                    and origem_tipo == "Processo"
                ):
                    descricao = origem_nome
                    if descricao not in grupo["Processos"]:
                        grupo["Processos"].append(descricao)
                else:
                    descricao = f"{origem_tipo or item.get('Tipo')}: {origem_nome}"
                    if descricao not in grupo["Persistencias"]:
                        grupo["Persistencias"].append(descricao)

            ModuloSistema._emitir_progresso_analise_defensiva(
                progress_callback, 78, "Correlacionando sinais conservadores..."
            )
            classificados: List[Dict[str, Any]] = []
            for indice, item in enumerate(itens, start=1):
                if indice % 25 == 0 and ModuloSistema._cancelamento_analise_defensiva_solicitado(
                    cancel_callback
                ):
                    ModuloSistema._registrar_evento_analise_defensiva(
                        "ANALISE_DEFENSIVA_CANCELADA", "etapa=classificacao"
                    )
                    return {
                        "Sucesso": False,
                        "Cancelada": True,
                        "Mensagem": "Análise defensiva cancelada durante a classificação.",
                        "Itens": [],
                    }
                chave = ModuloSistema._chave_caminho_analise_defensiva(
                    item.get("Caminho")
                )
                classificado = ModuloSistema._classificar_item_analise_defensiva(
                    item, metadados.get(chave), contexto, correlacoes.get(chave)
                )
                classificado["Id"] = f"analise-{indice:05d}"
                classificados.append(classificado)

            prioridade = {
                "Suspeito": 0, "Atenção": 1, "Requer análise": 2,
                "Informativo": 3, "Normal": 4, "Não disponível": 5,
            }
            classificados.sort(
                key=lambda item: (
                    prioridade.get(str(item.get("Classificacao")), 9),
                    str(item.get("Tipo") or "").casefold(),
                    str(item.get("Nome") or "").casefold(),
                )
            )
            contagens = {
                nome: sum(
                    item.get("Classificacao") == nome for item in classificados
                )
                for nome in (
                    "Normal", "Informativo", "Atenção", "Suspeito",
                    "Requer análise", "Não disponível",
                )
            }

            defender = bruto.get("Defender") if isinstance(bruto.get("Defender"), dict) else {}
            if defender.get("Disponivel"):
                antivirus = bool(defender.get("AntivirusAtivo"))
                tempo_real = bool(defender.get("TempoRealAtivo"))
                defender_normalizado = dict(defender)
                defender_normalizado["Estado"] = (
                    "Ativo" if antivirus and tempo_real else "Atenção"
                )
            else:
                defender_normalizado = {
                    "Disponivel": False,
                    "Estado": "Não disponível",
                }

            duracao_ms = int((time.monotonic() - inicio) * 1000)
            erros = bruto.get("Erros") or []
            if isinstance(erros, str):
                erros = [erros]
            elif not isinstance(erros, list):
                erros = []
            ModuloSistema._emitir_progresso_analise_defensiva(
                progress_callback, 100, "Análise defensiva concluída."
            )
            ModuloSistema._registrar_evento_analise_defensiva(
                "ANALISE_DEFENSIVA_CONCLUIDA",
                (
                    f"itens={len(classificados)};normal={contagens['Normal']};"
                    f"atencao={contagens['Atenção']};suspeito={contagens['Suspeito']};"
                    f"requer_analise={contagens['Requer análise']};"
                    f"fontes_indisponiveis={len(erros)};duracao_ms={duracao_ms}"
                ),
            )
            return {
                "Sucesso": True,
                "Cancelada": False,
                "Mensagem": (
                    f"Triagem somente leitura concluída: {len(classificados)} item(ns). "
                    "Os sinais apresentados não confirmam ameaça."
                ),
                "Itens": classificados,
                "Contagens": contagens,
                "Defender": defender_normalizado,
                "Contexto": contexto,
                "CaminhosPermitidosHash": [
                    caminho for caminho in caminhos_unicos
                    if re.match(r"(?i)^[a-z]:\\", caminho)
                ],
                "FontesIndisponiveis": [str(erro) for erro in erros],
                "DuracaoMs": duracao_ms,
                "ColetadoEm": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "SomenteLeitura": True,
            }
        except Exception as exc:
            ModuloSistema._registrar_evento_analise_defensiva(
                "ANALISE_DEFENSIVA_FALHOU", f"tipo={type(exc).__name__}"
            )
            try:
                logger.exception("Falha controlada na análise defensiva")
            except Exception:
                pass
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": (
                    "Não foi possível concluir a análise defensiva. "
                    "Consulte configurador_ti.log para o detalhe técnico."
                ),
                "Itens": [],
                "TipoFalha": type(exc).__name__,
            }
        finally:
            _lock_analise_defensiva.release()

    @staticmethod
    def calcular_sha256_analise_defensiva(
        caminho: str,
        caminhos_permitidos: Optional[List[str]] = None,
        progress_callback=None,
        cancel_callback=None,
        limite_bytes: int = 512 * 1024 * 1024,
        timeout_segundos: float = 45.0,
    ) -> Dict[str, Any]:
        """Calcula SHA-256 local apenas para um arquivo associado à coleta."""
        inicio = time.monotonic()
        normalizado = ModuloSistema._normalizar_caminho_analise_defensiva(caminho)
        chave = ModuloSistema._chave_caminho_analise_defensiva(normalizado)
        permitidos = {
            ModuloSistema._chave_caminho_analise_defensiva(valor)
            for valor in (caminhos_permitidos or [])
            if ModuloSistema._chave_caminho_analise_defensiva(valor)
        }
        if not normalizado or not chave or chave not in permitidos:
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Status": "Não autorizado",
                "Mensagem": "O arquivo não pertence à análise defensiva atual.",
                "SHA256": "—",
            }
        if normalizado.startswith("\\\\"):
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Status": "Caminho de rede não consultado",
                "Mensagem": (
                    "O hash interativo é limitado a arquivos locais para não "
                    "gerar acesso de rede durante a triagem."
                ),
                "SHA256": "—",
            }
        if ModuloSistema._cancelamento_analise_defensiva_solicitado(cancel_callback):
            return {
                "Sucesso": False,
                "Cancelada": True,
                "Status": "Cancelado",
                "Mensagem": "Cálculo de SHA-256 cancelado antes de iniciar.",
                "SHA256": "—",
            }
        try:
            arquivo = Path(normalizado)
            if arquivo.is_symlink() or not arquivo.is_file():
                return {
                    "Sucesso": False,
                    "Cancelada": False,
                    "Status": "Arquivo indisponível",
                    "Mensagem": "O arquivo foi removido, não é regular ou ficou inacessível.",
                    "SHA256": "—",
                    "Caminho": normalizado,
                }
            estado = arquivo.stat()
            tamanho = int(estado.st_size)
            if tamanho < 0 or tamanho > int(limite_bytes):
                return {
                    "Sucesso": False,
                    "Cancelada": False,
                    "Status": "Limite excedido",
                    "Mensagem": (
                        "O arquivo excede o limite de 512 MiB para hash interativo."
                    ),
                    "SHA256": "—",
                    "TamanhoBytes": tamanho,
                    "Caminho": normalizado,
                }
            identidade = (chave, tamanho, int(estado.st_mtime_ns))
            with _lock_cache_analise_defensiva:
                cache = _cache_hashes_analise_defensiva.get(identidade)
            if isinstance(cache, dict):
                retorno = dict(cache)
                retorno["Cache"] = True
                return retorno

            digest = hashlib.sha256()
            processado = 0
            with arquivo.open("rb") as fluxo:
                while True:
                    if ModuloSistema._cancelamento_analise_defensiva_solicitado(
                        cancel_callback
                    ):
                        return {
                            "Sucesso": False,
                            "Cancelada": True,
                            "Status": "Cancelado",
                            "Mensagem": "Cálculo de SHA-256 cancelado.",
                            "SHA256": "—",
                            "TamanhoBytes": tamanho,
                            "Caminho": normalizado,
                        }
                    if time.monotonic() - inicio > float(timeout_segundos):
                        return {
                            "Sucesso": False,
                            "Cancelada": False,
                            "Status": "Tempo limite",
                            "Mensagem": "O cálculo de SHA-256 excedeu o tempo de segurança.",
                            "SHA256": "—",
                            "TamanhoBytes": tamanho,
                            "Caminho": normalizado,
                        }
                    bloco = fluxo.read(1024 * 1024)
                    if not bloco:
                        break
                    digest.update(bloco)
                    processado += len(bloco)
                    percentual = int((processado / tamanho) * 100) if tamanho else 100
                    ModuloSistema._emitir_progresso_analise_defensiva(
                        progress_callback, percentual, "Calculando SHA-256 local..."
                    )
            # Detecta substituição do arquivo durante a leitura antes de usar
            # ou armazenar o resultado em cache.
            estado_final = arquivo.stat()
            if (
                int(estado_final.st_size) != tamanho
                or int(estado_final.st_mtime_ns) != int(estado.st_mtime_ns)
            ):
                return {
                    "Sucesso": False,
                    "Cancelada": False,
                    "Status": "Arquivo alterado",
                    "Mensagem": "O arquivo mudou durante o cálculo; o hash foi descartado.",
                    "SHA256": "—",
                    "TamanhoBytes": tamanho,
                    "Caminho": normalizado,
                }
            retorno = {
                "Sucesso": True,
                "Cancelada": False,
                "Status": "Calculado",
                "Mensagem": "SHA-256 calculado localmente.",
                "SHA256": digest.hexdigest(),
                "TamanhoBytes": tamanho,
                "Caminho": normalizado,
                "Cache": False,
            }
            with _lock_cache_analise_defensiva:
                _cache_hashes_analise_defensiva[identidade] = dict(retorno)
            return retorno
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Status": "Arquivo indisponível",
                "Mensagem": (
                    "O arquivo foi removido ou ficou inacessível durante o cálculo."
                ),
                "SHA256": "—",
                "Caminho": normalizado,
                "TipoFalha": type(exc).__name__,
            }

    # =========================================================
    # Benchmark Configurador TI — desempenho controlado e histórico local
    # =========================================================
    # O benchmark não é compatível nem comparável com ferramentas de terceiros.
    # Todas as fórmulas abaixo pertencem ao Configurador TI e permanecem
    # versionadas por BENCHMARK_CONFIGURADOR_TI_VERSION para permitir comparações locais
    # honestas entre execuções da mesma máquina.

    @staticmethod
    def _cancelamento_benchmark_configurador_ti_solicitado(cancel_callback) -> bool:
        try:
            return bool(callable(cancel_callback) and cancel_callback())
        except Exception:
            return False

    @staticmethod
    def _emitir_progresso_benchmark_configurador_ti(
        progress_callback, percentual: int, mensagem: str
    ) -> None:
        if not callable(progress_callback):
            return
        try:
            progress_callback(max(0, min(100, int(percentual))), str(mensagem))
        except Exception:
            pass

    @staticmethod
    def _registrar_evento_benchmark_configurador_ti(
        acao: str, modo: str, etapa: str = "", detalhes: str = ""
    ) -> None:
        """Registra somente informação técnica resumida e não sensível."""
        campos = [f"modo={modo}"]
        if etapa:
            campos.append(f"etapa={etapa}")
        if detalhes:
            campos.append(str(detalhes))
        texto = "; ".join(campos)
        try:
            logger.info("%s | %s", acao, texto)
        except Exception:
            pass
        try:
            registrar_log("BENCHMARK", acao, texto)
        except Exception:
            pass

    @staticmethod
    def _configuracao_benchmark_configurador_ti(modo: str) -> Dict[str, Any]:
        """Retorna limites fixos da versão 1 do benchmark próprio Configurador TI.

        A carga é deliberadamente limitada a um fluxo de CPU, buffers de RAM
        controlados e uma única escrita sequencial. Não há stress prolongado,
        mudança de plano de energia, acesso bruto a disco ou dependência externa.
        """
        normalizado = str(modo or "").strip().casefold()
        aliases = {
            "rapido": "rapido",
            "rápido": "rapido",
            "quick": "rapido",
            "completo": "completo",
            "complete": "completo",
            "full": "completo",
        }
        chave = aliases.get(normalizado)
        if chave is None:
            raise ValueError("Modo de benchmark inválido. Use Rápido ou Completo.")

        mib = 1024 * 1024
        configuracoes = {
            "rapido": {
                "Modo": "Rápido",
                "CpuSegundos": 22.0,
                "RamSegundos": 8.0,
                "RamBufferBytes": 32 * mib,
                "ArmazenamentoBytes": 64 * mib,
                "BlocoIoBytes": 1 * mib,
                "DuracaoEsperada": "aproximadamente 30–90 segundos",
            },
            "completo": {
                "Modo": "Completo",
                # Uma etapa de CPU de 90 s somada à RAM e ao I/O controlado
                # mantém o modo completo próximo de dois minutos, sem virar
                # stress test prolongado nem usar todos os núcleos.
                "CpuSegundos": 90.0,
                "RamSegundos": 30.0,
                "RamBufferBytes": 128 * mib,
                "ArmazenamentoBytes": 256 * mib,
                "BlocoIoBytes": 1 * mib,
                "DuracaoEsperada": "aproximadamente 2–5 minutos",
            },
        }
        return dict(configuracoes[chave])

    @staticmethod
    def _memoria_nativa_benchmark_configurador_ti() -> Dict[str, Optional[int]]:
        """Lê apenas totais de memória com APIs nativas, sem psutil."""
        if os.name == "nt":
            try:
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                estado = MEMORYSTATUSEX()
                estado.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(estado)):
                    return {
                        "TotalBytes": int(estado.ullTotalPhys),
                        "DisponivelBytes": int(estado.ullAvailPhys),
                    }
            except Exception:
                pass

        try:
            pagina = int(os.sysconf("SC_PAGE_SIZE"))
            total = int(os.sysconf("SC_PHYS_PAGES")) * pagina
            disponivel = int(os.sysconf("SC_AVPHYS_PAGES")) * pagina
            return {"TotalBytes": total, "DisponivelBytes": disponivel}
        except (AttributeError, OSError, ValueError):
            return {"TotalBytes": None, "DisponivelBytes": None}

    @staticmethod
    def _energia_nativa_benchmark_configurador_ti() -> Dict[str, Any]:
        """Consulta a alimentação sem UAC; ausência de bateria não é erro."""
        resultado = {
            "Disponivel": False,
            "PossuiBateria": False,
            "EmBateria": None,
            "NaTomada": None,
            "CargaPercentual": None,
            "Mensagem": "Status de bateria não disponível.",
        }
        if os.name != "nt":
            return resultado
        try:
            class SYSTEM_POWER_STATUS(ctypes.Structure):
                _fields_ = [
                    ("ACLineStatus", ctypes.c_byte),
                    ("BatteryFlag", ctypes.c_byte),
                    ("BatteryLifePercent", ctypes.c_byte),
                    ("SystemStatusFlag", ctypes.c_byte),
                    ("BatteryLifeTime", ctypes.c_ulong),
                    ("BatteryFullLifeTime", ctypes.c_ulong),
                ]

            estado = SYSTEM_POWER_STATUS()
            if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(estado)):
                return resultado
            ac = int(estado.ACLineStatus) & 0xFF
            flag_bateria = int(estado.BatteryFlag) & 0xFF
            carga = int(estado.BatteryLifePercent) & 0xFF
            possui_bateria = flag_bateria != 128
            resultado.update({
                "Disponivel": True,
                "PossuiBateria": possui_bateria,
                "EmBateria": True if ac == 0 else (False if ac == 1 else None),
                "NaTomada": True if ac == 1 else (False if ac == 0 else None),
                "CargaPercentual": carga if 0 <= carga <= 100 else None,
            })
            if not possui_bateria:
                resultado["Mensagem"] = "Este computador não informou bateria ao Windows."
            elif ac == 0:
                resultado["Mensagem"] = "Notebook em bateria."
            elif ac == 1:
                resultado["Mensagem"] = "Notebook conectado à energia."
            else:
                resultado["Mensagem"] = "O Windows não confirmou a fonte de energia."
        except Exception:
            pass
        return resultado

    @staticmethod
    def _contexto_benchmark_configurador_ti() -> Dict[str, Any]:
        """Coleta identificação e pré-condições leves no Worker do benchmark."""
        memoria = ModuloSistema._memoria_nativa_benchmark_configurador_ti()
        cpu = {
            "Modelo": None,
            "Nucleos": None,
            "Threads": os.cpu_count() or None,
            "ClockReportadoMHz": None,
        }
        if os.name == "nt":
            script = r"""
$ErrorActionPreference='Stop'
$cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
[PSCustomObject]@{
    Modelo = if ($cpu) { [string]$cpu.Name } else { $null }
    Nucleos = if ($cpu) { $cpu.NumberOfCores } else { $null }
    Threads = if ($cpu) { $cpu.NumberOfLogicalProcessors } else { $null }
    ClockReportadoMHz = if ($cpu) { $cpu.CurrentClockSpeed } else { $null }
    ClockMaximoMHz = if ($cpu) { $cpu.MaxClockSpeed } else { $null }
} | ConvertTo-Json -Compress
"""
            try:
                resposta = executar_powershell(script, timeout=20)
                bruto = json.loads((resposta.stdout or "").strip() or "{}")
                if resposta.returncode == 0 and isinstance(bruto, dict):
                    for chave in (
                        "Modelo", "Nucleos", "Threads",
                        "ClockReportadoMHz", "ClockMaximoMHz",
                    ):
                        if bruto.get(chave) not in (None, ""):
                            cpu[chave] = bruto.get(chave)
            except Exception:
                pass

        if not cpu.get("Modelo"):
            modelo_local = str(platform.processor() or "").strip()
            cpu["Modelo"] = modelo_local or "Não disponível"
        for chave in ("Nucleos", "Threads", "ClockReportadoMHz", "ClockMaximoMHz"):
            try:
                valor = int(cpu.get(chave))
                cpu[chave] = valor if valor > 0 else None
            except (TypeError, ValueError):
                cpu[chave] = None

        return {
            "Hostname": os.environ.get("COMPUTERNAME") or socket.gethostname(),
            "CPU": cpu,
            "RAM": memoria,
            "Energia": ModuloSistema._energia_nativa_benchmark_configurador_ti(),
        }

    @staticmethod
    def _diretorio_temporario_benchmark_configurador_ti() -> Path:
        """Retorna diretório transitório próprio, sempre abaixo de %TEMP%."""
        raiz_temp = Path(tempfile.gettempdir()).resolve()
        pasta = (raiz_temp / "ConfiguradorTI" / "benchmark_configurador_ti").resolve()
        try:
            pasta.relative_to(raiz_temp)
        except ValueError as exc:
            raise RuntimeError("Diretório temporário Configurador TI fora de %TEMP%.") from exc
        pasta.mkdir(parents=True, exist_ok=True)
        return pasta

    @staticmethod
    def _candidatos_historico_benchmark_configurador_ti() -> List[Path]:
        """Mantém portabilidade e tem fallback persistente para pasta sem escrita."""
        candidatos = [Path(ARQUIVO_HISTORICO_BENCHMARK_CONFIGURADOR_TI)]
        local_app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if local_app_data:
            candidatos.append(
                Path(local_app_data) / "ConfiguradorTI" / "benchmark_configurador_ti_historico.json"
            )
        else:
            candidatos.append(
                Path.home() / ".config" / "ConfiguradorTI" / "benchmark_configurador_ti_historico.json"
            )
        unicos = []
        vistos = set()
        for candidato in candidatos:
            try:
                chave = str(candidato.resolve()).casefold()
            except OSError:
                chave = str(candidato).casefold()
            if chave not in vistos:
                vistos.add(chave)
                unicos.append(candidato)
        return unicos

    @staticmethod
    def _historico_benchmark_vazio() -> Dict[str, Any]:
        return {
            "SchemaVersion": SCHEMA_HISTORICO_BENCHMARK_CONFIGURADOR_TI,
            "BenchmarkVersion": BENCHMARK_CONFIGURADOR_TI_VERSION,
            "Resultados": [],
        }

    @staticmethod
    def _ler_historico_benchmark_configurador_ti(
        caminho: Path
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not caminho.exists():
            return ModuloSistema._historico_benchmark_vazio(), None
        try:
            dados = json.loads(caminho.read_text(encoding="utf-8"))
            if not isinstance(dados, dict) or not isinstance(dados.get("Resultados"), list):
                raise ValueError("schema inválido")
            dados.setdefault("SchemaVersion", SCHEMA_HISTORICO_BENCHMARK_CONFIGURADOR_TI)
            dados.setdefault("BenchmarkVersion", BENCHMARK_CONFIGURADOR_TI_VERSION)
            return dados, None
        except Exception as exc:
            try:
                logger.warning(
                    "BENCHMARK_HISTORICO_INVALIDO | tipo=%s",
                    type(exc).__name__,
                )
            except Exception:
                pass
            return None, "O histórico existente está inválido e foi preservado sem sobrescrita."

    @staticmethod
    def _carregar_historico_benchmark_configurador_ti() -> Tuple[Dict[str, Any], Optional[Path], Optional[str]]:
        candidatos = ModuloSistema._candidatos_historico_benchmark_configurador_ti()
        for caminho in candidatos:
            if caminho.exists():
                dados, erro = ModuloSistema._ler_historico_benchmark_configurador_ti(caminho)
                return (
                    dados if isinstance(dados, dict) else ModuloSistema._historico_benchmark_vazio(),
                    caminho,
                    erro,
                )
        return ModuloSistema._historico_benchmark_vazio(), candidatos[0], None

    @staticmethod
    def _salvar_historico_benchmark_configurador_ti(entrada: Dict[str, Any]) -> Tuple[bool, str]:
        """Persiste resultado com escrita atômica; cancelamentos nunca chegam aqui."""
        dados, caminho_existente, erro_historico = ModuloSistema._carregar_historico_benchmark_configurador_ti()
        if erro_historico:
            return False, erro_historico

        resultados = [
            item for item in (dados.get("Resultados") or [])
            if isinstance(item, dict)
        ]
        hostname = str(entrada.get("Hostname") or "").casefold()
        mesmos = [
            item for item in resultados
            if str(item.get("Hostname") or "").casefold() == hostname
        ]
        outros = [
            item for item in resultados
            if str(item.get("Hostname") or "").casefold() != hostname
        ]
        mesmos.append(dict(entrada))
        mesmos.sort(key=lambda item: str(item.get("Timestamp") or ""))
        dados["Resultados"] = outros + mesmos[-LIMITE_HISTORICO_BENCHMARK_POR_MAQUINA:]
        dados["SchemaVersion"] = SCHEMA_HISTORICO_BENCHMARK_CONFIGURADOR_TI
        dados["BenchmarkVersion"] = BENCHMARK_CONFIGURADOR_TI_VERSION

        # Se o histórico principal existir, tentamos preservá-lo primeiro. Se
        # a pasta tiver se tornado somente leitura (por exemplo, instalação em
        # mídia protegida), a mesma estrutura já carregada é gravada no
        # fallback persistente. Não se perde nem se sobrescreve silenciosamente
        # o arquivo legado que não pôde ser alterado.
        candidatos = []
        if caminho_existente is not None:
            candidatos.append(caminho_existente)
        candidatos.extend(ModuloSistema._candidatos_historico_benchmark_configurador_ti())
        candidatos_unicos = []
        caminhos_vistos = set()
        for candidato in candidatos:
            try:
                chave = str(candidato.resolve()).casefold()
            except OSError:
                chave = str(candidato).casefold()
            if chave not in caminhos_vistos:
                caminhos_vistos.add(chave)
                candidatos_unicos.append(candidato)
        ultimo_erro = None
        for caminho in candidatos_unicos:
            temporario = None
            try:
                caminho.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=str(caminho.parent),
                    prefix=f".{caminho.stem}_",
                    suffix=".tmp",
                    delete=False,
                ) as fluxo:
                    temporario = Path(fluxo.name)
                    json.dump(dados, fluxo, ensure_ascii=False, indent=2, sort_keys=True)
                    fluxo.flush()
                    os.fsync(fluxo.fileno())
                os.replace(str(temporario), str(caminho))
                temporario = None
                restringir_acl_arquivo(str(caminho))
                return True, "Histórico local atualizado."
            except Exception as exc:
                ultimo_erro = type(exc).__name__
            finally:
                if temporario is not None:
                    try:
                        temporario.unlink(missing_ok=True)
                    except OSError:
                        pass
        return False, (
            "Não foi possível salvar o histórico local "
            f"({ultimo_erro or 'erro desconhecido'})."
        )

    @staticmethod
    def obter_historico_benchmark_configurador_ti(hostname: Optional[str] = None) -> Dict[str, Any]:
        """Lê somente o histórico local; adequado para um Worker curto da GUI."""
        dados, _, erro = ModuloSistema._carregar_historico_benchmark_configurador_ti()
        if erro:
            return {"Sucesso": False, "Mensagem": erro, "Resultados": []}
        alvo = str(hostname or os.environ.get("COMPUTERNAME") or socket.gethostname()).casefold()
        resultados = [
            dict(item) for item in (dados.get("Resultados") or [])
            if isinstance(item, dict)
            and str(item.get("Hostname") or "").casefold() == alvo
        ]
        resultados.sort(key=lambda item: str(item.get("Timestamp") or ""), reverse=True)
        return {
            "Sucesso": True,
            "Mensagem": (
                "Nenhum benchmark anterior foi encontrado nesta máquina."
                if not resultados else f"{len(resultados)} resultado(s) local(is) encontrado(s)."
            ),
            "Resultados": resultados,
            "BenchmarkVersion": BENCHMARK_CONFIGURADOR_TI_VERSION,
        }

    @staticmethod
    def _comparar_benchmark_anterior_configurador_ti(
        atual: Dict[str, Any], resultados_anteriores: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calcula variação apenas para scores realmente presentes nas duas execuções."""
        anterior = next(
            (item for item in resultados_anteriores if isinstance(item, dict)),
            None,
        )
        if anterior is None:
            return {"Disponivel": False, "Mensagem": "Sem execução anterior para comparação.", "Itens": []}

        itens = []
        scores_atuais = atual.get("Scores") if isinstance(atual.get("Scores"), dict) else {}
        scores_anteriores = anterior.get("Scores") if isinstance(anterior.get("Scores"), dict) else {}
        for componente in ("CPU", "RAM", "Armazenamento", "Geral"):
            valor_atual = scores_atuais.get(componente)
            valor_anterior = scores_anteriores.get(componente)
            if isinstance(valor_atual, bool) or isinstance(valor_anterior, bool):
                continue
            try:
                valor_atual = float(valor_atual)
                valor_anterior = float(valor_anterior)
            except (TypeError, ValueError):
                continue
            if valor_anterior <= 0:
                continue
            variacao = ((valor_atual - valor_anterior) * 100.0) / valor_anterior
            itens.append({
                "Componente": componente,
                "VariacaoPercentual": round(variacao, 1),
                "Anterior": round(valor_anterior, 2),
                "Atual": round(valor_atual, 2),
            })
        return {
            "Disponivel": bool(itens),
            "Mensagem": (
                "Comparação informativa com a execução anterior; variações não confirmam defeito."
                if itens else "A execução anterior não possui scores comparáveis nesta versão."
            ),
            "Itens": itens,
        }

    @staticmethod
    def _executar_cpu_benchmark_configurador_ti(
        configuracao: Dict[str, Any], cancel_callback=None
    ) -> Dict[str, Any]:
        """Carga determinística e limitada a um fluxo, segura para frozen/PyInstaller."""
        duracao_alvo = max(0.1, float(configuracao.get("CpuSegundos") or 0.1))
        base = bytes(range(256)) * 128  # 32 KiB, sem buffer grande persistente.
        estado = 0xC571C571
        verificador = 0
        ciclos = 0
        inicio = time.perf_counter()
        try:
            while (time.perf_counter() - inicio) < duracao_alvo:
                if ModuloSistema._cancelamento_benchmark_configurador_ti_solicitado(cancel_callback):
                    return {"Status": "Cancelada", "Score": None}
                inteiro = estado
                acumulado_flutuante = 0.0
                for indice in range(192):
                    inteiro = (inteiro * 1664525 + 1013904223) & 0xFFFFFFFF
                    acumulado_flutuante += math.sqrt((inteiro & 0xFFFF) + indice + 1)
                carga = base + inteiro.to_bytes(4, "little")
                digest = hashlib.sha256(carga).digest()
                comprimido = zlib.compress(carga, level=1)
                if zlib.decompress(comprimido) != carga:
                    raise RuntimeError("Verificação de compressão Configurador TI falhou.")
                verificador ^= int.from_bytes(digest[:4], "little") ^ int(acumulado_flutuante)
                estado = inteiro ^ verificador
                ciclos += 1
        except Exception as exc:
            return {
                "Status": "Falhou",
                "Score": None,
                "Mensagem": f"Falha controlada na etapa CPU ({type(exc).__name__}).",
            }

        duracao = max(0.001, time.perf_counter() - inicio)
        ciclos_por_segundo = ciclos / duracao
        # Fórmula Configurador TI v1: taxa do ciclo composto (inteiros + ponto flutuante
        # + SHA-256 + compressão/descompressão) multiplicada por 100.
        score = int(round(ciclos_por_segundo * 100.0))
        return {
            "Status": "OK",
            "Score": score,
            "Metricas": {
                "Ciclos": ciclos,
                "CiclosPorSegundo": round(ciclos_por_segundo, 3),
                "DuracaoSegundos": round(duracao, 3),
                "Perfil": "inteiros, ponto flutuante, SHA-256 e compressão/descompressão",
                "Fluxos": 1,
            },
        }

    @staticmethod
    def _executar_ram_benchmark_configurador_ti(
        configuracao: Dict[str, Any], memoria_disponivel: Optional[int], cancel_callback=None
    ) -> Dict[str, Any]:
        """Mede leitura/cópia/escrita com no máximo dois buffers controlados."""
        mib = 1024 * 1024
        limite_configurado = max(16 * mib, int(configuracao.get("RamBufferBytes") or 16 * mib))
        if memoria_disponivel is None:
            tamanho_buffer = min(limite_configurado, 32 * mib)
        else:
            memoria_disponivel = max(0, int(memoria_disponivel))
            if memoria_disponivel < max(256 * mib, limite_configurado * 4):
                return {
                    "Status": "Pulado",
                    "Score": None,
                    "Mensagem": "Memória disponível insuficiente para um teste RAM seguro.",
                    "Metricas": {
                        "DisponivelAntesBytes": memoria_disponivel,
                        "BufferBytes": 0,
                    },
                }
            tamanho_buffer = min(limite_configurado, max(16 * mib, memoria_disponivel // 8))

        duracao_total = max(0.6, float(configuracao.get("RamSegundos") or 0.6))
        duracao_por_medida = duracao_total / 3.0
        padrao = bytes(range(256)) * 4096  # 1 MiB determinístico.
        fonte = destino = None

        class _CancelamentoRam(Exception):
            pass

        def verificar_cancelamento():
            if ModuloSistema._cancelamento_benchmark_configurador_ti_solicitado(cancel_callback):
                raise _CancelamentoRam()

        try:
            fonte = bytearray(tamanho_buffer)
            destino = bytearray(tamanho_buffer)
            for deslocamento in range(0, tamanho_buffer, len(padrao)):
                verificar_cancelamento()
                tamanho = min(len(padrao), tamanho_buffer - deslocamento)
                fonte[deslocamento:deslocamento + tamanho] = padrao[:tamanho]

            def medir(operacao):
                total = 0
                inicio = time.perf_counter()
                while (time.perf_counter() - inicio) < duracao_por_medida:
                    verificar_cancelamento()
                    operacao()
                    total += tamanho_buffer
                duracao = max(0.001, time.perf_counter() - inicio)
                return (total / mib) / duracao, total, duracao

            escrita, total_escrita, duracao_escrita = medir(
                lambda: destino.__setitem__(slice(None), fonte)
            )
            copia, total_copia, duracao_copia = medir(
                lambda: fonte.__setitem__(slice(None), destino)
            )

            def leitura():
                # crc32 lê o buffer inteiro em C; o valor serve somente para
                # impedir que uma leitura futura seja tratada como descartável.
                zlib.crc32(fonte)

            leitura_mb, total_leitura, duracao_leitura = medir(leitura)
        except _CancelamentoRam:
            return {"Status": "Cancelada", "Score": None}
        except MemoryError:
            return {
                "Status": "Pulado",
                "Score": None,
                "Mensagem": "A alocação de RAM foi recusada; o teste foi pulado com segurança.",
                "Metricas": {"BufferBytes": 0},
            }
        except Exception as exc:
            return {
                "Status": "Falhou",
                "Score": None,
                "Mensagem": f"Falha controlada na etapa RAM ({type(exc).__name__}).",
            }
        finally:
            # Solta os dois buffers logo após a medição; não há RAMDisk nem
            # alteração de paginação.
            del fonte
            del destino

        # Fórmula Configurador TI v1: 30% escrita + 45% cópia + 25% leitura, em MB/s,
        # multiplicada por 10. É um índice próprio, não comparável externamente.
        indice_mb_s = escrita * 0.30 + copia * 0.45 + leitura_mb * 0.25
        return {
            "Status": "OK",
            "Score": int(round(indice_mb_s * 10.0)),
            "Metricas": {
                "BufferBytes": tamanho_buffer,
                "DisponivelAntesBytes": memoria_disponivel,
                "EscritaMBps": round(escrita, 2),
                "CopiaMBps": round(copia, 2),
                "LeituraMBps": round(leitura_mb, 2),
                "AmostrasBytes": {
                    "Escrita": total_escrita,
                    "Copia": total_copia,
                    "Leitura": total_leitura,
                },
                "DuracaoSegundos": round(
                    duracao_escrita + duracao_copia + duracao_leitura, 3
                ),
            },
        }

    @staticmethod
    def _precondicao_armazenamento_benchmark_configurador_ti(
        configuracao: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Valida espaço e diretório Configurador TI antes da carga de CPU/RAM.

        A mesma verificação é repetida imediatamente antes da escrita para não
        confiar em espaço que possa ter sido consumido durante o benchmark.
        """
        mib = 1024 * 1024
        tamanho_arquivo = max(
            1 * mib,
            int(configuracao.get("ArmazenamentoBytes") or 64 * mib),
        )
        try:
            pasta = ModuloSistema._diretorio_temporario_benchmark_configurador_ti()
            uso = shutil.disk_usage(pasta)
        except Exception as exc:
            return {
                "Disponivel": False,
                "Resultado": {
                    "Status": "Pulado",
                    "Score": None,
                    "Mensagem": (
                        "Diretório temporário Configurador TI indisponível "
                        f"({type(exc).__name__})."
                    ),
                },
            }

        espaco_minimo = max(512 * mib, tamanho_arquivo * 3)
        if uso.free < espaco_minimo:
            return {
                "Disponivel": False,
                "Resultado": {
                    "Status": "Pulado",
                    "Score": None,
                    "Mensagem": (
                        "Espaço livre insuficiente; o teste de armazenamento "
                        "foi pulado com segurança."
                    ),
                    "Metricas": {
                        "Volume": str(pasta.drive or pasta.anchor or "temporário"),
                        "EspacoLivreBytes": int(uso.free),
                        "EspacoNecessarioBytes": int(espaco_minimo),
                        "EscritaMaximaBytes": tamanho_arquivo,
                    },
                },
            }
        return {
            "Disponivel": True,
            "Pasta": pasta,
            "Uso": uso,
            "TamanhoArquivoBytes": tamanho_arquivo,
            "EspacoMinimoBytes": espaco_minimo,
        }

    @staticmethod
    def _executar_armazenamento_benchmark_configurador_ti(
        configuracao: Dict[str, Any], cancel_callback=None
    ) -> Dict[str, Any]:
        """Usa um único arquivo temporário Configurador TI e limita a escrita por execução."""
        mib = 1024 * 1024
        tamanho_arquivo = max(1 * mib, int(configuracao.get("ArmazenamentoBytes") or 64 * mib))
        bloco_tamanho = max(64 * 1024, min(tamanho_arquivo, int(configuracao.get("BlocoIoBytes") or mib)))
        if ModuloSistema._cancelamento_benchmark_configurador_ti_solicitado(cancel_callback):
            return {"Status": "Cancelada", "Score": None}

        precondicao = ModuloSistema._precondicao_armazenamento_benchmark_configurador_ti(
            configuracao
        )
        if not precondicao.get("Disponivel"):
            return precondicao.get("Resultado") or {
                "Status": "Pulado",
                "Score": None,
                "Mensagem": "Pré-condição de armazenamento não disponível.",
            }
        pasta = precondicao["Pasta"]
        uso = precondicao["Uso"]

        caminho_arquivo = None
        erro_limpeza = None
        resultado = None
        aviso_fsync = None
        padrao = bytes(range(256)) * (bloco_tamanho // 256 + 1)
        try:
            with tempfile.NamedTemporaryFile(
                mode="w+b",
                dir=str(pasta),
                prefix="configurador_ti_",
                suffix=".bin",
                delete=False,
            ) as fluxo:
                caminho_arquivo = Path(fluxo.name)
                if caminho_arquivo.resolve().parent != pasta.resolve():
                    raise RuntimeError("Arquivo temporário Configurador TI fora do diretório autorizado.")

                inicio_escrita = time.perf_counter()
                gravados = 0
                while gravados < tamanho_arquivo:
                    if ModuloSistema._cancelamento_benchmark_configurador_ti_solicitado(cancel_callback):
                        resultado = {"Status": "Cancelada", "Score": None}
                        break
                    quantidade = min(bloco_tamanho, tamanho_arquivo - gravados)
                    fluxo.write(padrao[:quantidade])
                    gravados += quantidade
                if resultado is None:
                    fluxo.flush()
                    try:
                        os.fsync(fluxo.fileno())
                    except OSError as exc:
                        aviso_fsync = f"A sincronização explícita não foi confirmada ({type(exc).__name__})."
                    duracao_escrita = max(0.001, time.perf_counter() - inicio_escrita)

            if resultado is None:
                inicio_latencia = time.perf_counter()
                with open(caminho_arquivo, "rb", buffering=0) as fluxo_leitura:
                    primeiro_bloco = fluxo_leitura.read(min(4096, tamanho_arquivo))
                if not primeiro_bloco:
                    raise RuntimeError("Arquivo temporário Configurador TI não pôde ser lido.")
                latencia_ms = (time.perf_counter() - inicio_latencia) * 1000.0

                inicio_leitura = time.perf_counter()
                lidos = 0
                buffer = bytearray(bloco_tamanho)
                with open(caminho_arquivo, "rb", buffering=0) as fluxo_leitura:
                    while True:
                        if ModuloSistema._cancelamento_benchmark_configurador_ti_solicitado(cancel_callback):
                            resultado = {"Status": "Cancelada", "Score": None}
                            break
                        quantidade = fluxo_leitura.readinto(buffer)
                        if not quantidade:
                            break
                        lidos += quantidade
                if resultado is None:
                    duracao_leitura = max(0.001, time.perf_counter() - inicio_leitura)
                    escrita_mb_s = (gravados / mib) / duracao_escrita
                    leitura_mb_s = (lidos / mib) / duracao_leitura
                    # Fórmula Configurador TI v1: 45% escrita sequencial + 55% leitura
                    # sequencial, em MB/s, multiplicada por 10.
                    resultado = {
                        "Status": "OK",
                        "Score": int(round((escrita_mb_s * 0.45 + leitura_mb_s * 0.55) * 10.0)),
                        "Metricas": {
                            "Volume": str(pasta.drive or pasta.anchor or "temporário"),
                            "EspacoLivreAntesBytes": int(uso.free),
                            "EscritaMaximaBytes": tamanho_arquivo,
                            "EscritaMBps": round(escrita_mb_s, 2),
                            "LeituraMBps": round(leitura_mb_s, 2),
                            "LatenciaPrimeiraLeituraMs": round(latencia_ms, 3),
                            "DuracaoEscritaSegundos": round(duracao_escrita, 3),
                            "DuracaoLeituraSegundos": round(duracao_leitura, 3),
                            "FsyncConfirmado": aviso_fsync is None,
                        },
                        "Avisos": [
                            aviso for aviso in (
                                aviso_fsync,
                                "Resultado pode variar com cache do Windows, antivírus, energia e atividade concorrente.",
                            ) if aviso
                        ],
                    }
        except Exception as exc:
            resultado = {
                "Status": "Falhou",
                "Score": None,
                "Mensagem": f"Falha controlada na etapa de armazenamento ({type(exc).__name__}).",
            }
        finally:
            if caminho_arquivo is not None:
                try:
                    if caminho_arquivo.exists():
                        caminho_arquivo.unlink()
                except OSError as exc:
                    erro_limpeza = type(exc).__name__

        if erro_limpeza:
            return {
                "Status": "Falhou",
                "Score": None,
                "Mensagem": (
                    "O arquivo temporário do benchmark não pôde ser removido "
                    f"({erro_limpeza}). O resultado não foi tratado como concluído."
                ),
                "FalhaLimpezaTemporario": True,
            }
        return resultado or {
            "Status": "Falhou",
            "Score": None,
            "Mensagem": "A etapa de armazenamento não retornou resultado.",
        }

    @staticmethod
    def _extrair_temperaturas_snapshot_benchmark_configurador_ti(
        dados_saude_armazenamento: Any
    ) -> List[str]:
        """Reaproveita somente temperaturas já obtidas; não reconsulta SMART."""
        if not isinstance(dados_saude_armazenamento, dict):
            return []
        discos = dados_saude_armazenamento.get("Discos") or []
        if isinstance(discos, dict):
            discos = [discos]
        temperaturas = []
        for disco in discos if isinstance(discos, list) else []:
            if not isinstance(disco, dict):
                continue
            valor = str(disco.get("Temperatura") or "").strip()
            if not re.search(r"\d", valor):
                continue
            identificador = str(disco.get("Numero") or "").strip()
            modelo = str(disco.get("Modelo") or "").strip()
            nome = " ".join(parte for parte in (
                f"Disco {identificador}" if identificador else "Disco", modelo
            ) if parte)
            temperaturas.append(f"{nome}: {valor}")
        return temperaturas

    @staticmethod
    def _score_geral_benchmark_configurador_ti(scores: Dict[str, Any]) -> Tuple[Optional[int], Dict[str, float]]:
        """Normaliza pesos somente entre componentes realmente testados."""
        pesos_base = {"CPU": 0.45, "RAM": 0.30, "Armazenamento": 0.25}
        participantes = {}
        for componente, peso in pesos_base.items():
            valor = scores.get(componente)
            if isinstance(valor, bool):
                continue
            try:
                numero = float(valor)
            except (TypeError, ValueError):
                continue
            if numero < 0:
                continue
            participantes[componente] = (numero, peso)
        if not participantes:
            return None, {}
        total_pesos = sum(peso for _, peso in participantes.values())
        pesos_normalizados = {
            componente: round(peso / total_pesos, 4)
            for componente, (_, peso) in participantes.items()
        }
        geral = sum(
            numero * pesos_normalizados[componente]
            for componente, (numero, _) in participantes.items()
        )
        return int(round(geral)), pesos_normalizados

    @staticmethod
    def executar_benchmark_configurador_ti(
        modo: str = "rapido",
        dados_saude_armazenamento=None,
        progress_callback=None,
        cancel_callback=None,
    ) -> Dict[str, Any]:
        """Executa o Benchmark Configurador TI próprio, limitado e cooperativamente cancelável.

        Nenhuma etapa solicita elevação, modifica plano de energia, abre ferramenta
        externa, reconsulta SMART ou altera arquivos do usuário. A escrita máxima
        em armazenamento é 64 MiB no modo Rápido e 256 MiB no modo Completo.
        """
        try:
            configuracao = ModuloSistema._configuracao_benchmark_configurador_ti(modo)
        except ValueError as exc:
            return {"Sucesso": False, "Cancelada": False, "Mensagem": str(exc)}
        nome_modo = configuracao["Modo"]
        if not _lock_benchmark_configurador_ti.acquire(blocking=False):
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": "Já existe um Benchmark Configurador TI em andamento.",
            }

        inicio = time.monotonic()
        def cancelada():
            return ModuloSistema._cancelamento_benchmark_configurador_ti_solicitado(cancel_callback)

        def resultado_cancelado(etapa: str) -> Dict[str, Any]:
            duracao = round(time.monotonic() - inicio, 2)
            ModuloSistema._registrar_evento_benchmark_configurador_ti(
                "BENCHMARK_CANCELADO", nome_modo, etapa,
                f"duracao_s={duracao}",
            )
            return {
                "Sucesso": False,
                "Cancelada": True,
                "Mensagem": "Benchmark Configurador TI cancelado. Nenhum resultado foi salvo no histórico.",
                "DuracaoSegundos": duracao,
            }

        try:
            if cancelada():
                return resultado_cancelado("Preparação")
            ModuloSistema._registrar_evento_benchmark_configurador_ti(
                "BENCHMARK_INICIADO", nome_modo, "Preparação",
                f"versao={BENCHMARK_CONFIGURADOR_TI_VERSION}",
            )
            ModuloSistema._emitir_progresso_benchmark_configurador_ti(
                progress_callback, 3, "Preparando contexto técnico e pré-condições..."
            )
            contexto = ModuloSistema._contexto_benchmark_configurador_ti()
            avisos = [
                "Feche aplicativos pesados, evite cópias de arquivos e aguarde a máquina estabilizar para comparar execuções.",
                "Scores Configurador TI são próprios e servem para comparação desta máquina; não são comparáveis com PassMark, Cinebench ou PCMark.",
            ]
            energia = contexto.get("Energia") if isinstance(contexto.get("Energia"), dict) else {}
            if nome_modo == "Completo":
                if energia.get("EmBateria") is True:
                    avisos.append(
                        "Teste completo em bateria: conecte o notebook à energia quando possível. O plano de energia não foi alterado."
                    )
                elif energia.get("PossuiBateria") and energia.get("NaTomada") is None:
                    avisos.append(
                        "A fonte de energia do notebook não foi confirmada; recomenda-se conectar à tomada para o teste completo."
                    )

            # A pré-condição de espaço ocorre antes de CPU/RAM; a etapa de
            # armazenamento a repete antes da escrita para manter a decisão
            # segura caso outro processo consuma espaço enquanto o teste roda.
            ModuloSistema._emitir_progresso_benchmark_configurador_ti(
                progress_callback, 5, "Verificando espaço para o arquivo temporário Configurador TI..."
            )
            precondicao_armazenamento = (
                ModuloSistema._precondicao_armazenamento_benchmark_configurador_ti(
                    configuracao
                )
            )
            if not precondicao_armazenamento.get("Disponivel"):
                aviso_espaco = (
                    precondicao_armazenamento.get("Resultado", {}).get("Mensagem")
                )
                if aviso_espaco:
                    avisos.append(str(aviso_espaco))

            if cancelada():
                return resultado_cancelado("Preparação")
            ModuloSistema._emitir_progresso_benchmark_configurador_ti(
                progress_callback, 8, "Executando benchmark de CPU..."
            )
            cpu = ModuloSistema._executar_cpu_benchmark_configurador_ti(configuracao, cancel_callback)
            if cpu.get("Status") == "Cancelada" or cancelada():
                return resultado_cancelado("CPU")
            if cpu.get("Status") != "OK":
                mensagem = cpu.get("Mensagem") or "A etapa de CPU não pôde ser concluída."
                ModuloSistema._registrar_evento_benchmark_configurador_ti(
                    "BENCHMARK_FALHOU", nome_modo, "CPU", "duracao_s=0",
                )
                return {"Sucesso": False, "Cancelada": False, "Mensagem": mensagem, "CPU": cpu}
            ModuloSistema._registrar_evento_benchmark_configurador_ti(
                "BENCHMARK_ETAPA_CONCLUIDA", nome_modo, "CPU",
                f"score={cpu.get('Score')};duracao_s={cpu.get('Metricas', {}).get('DuracaoSegundos')}",
            )

            ModuloSistema._emitir_progresso_benchmark_configurador_ti(
                progress_callback, 48, "Medindo throughput controlado de memória RAM..."
            )
            ram = ModuloSistema._executar_ram_benchmark_configurador_ti(
                configuracao,
                (contexto.get("RAM") or {}).get("DisponivelBytes"),
                cancel_callback,
            )
            if ram.get("Status") == "Cancelada" or cancelada():
                return resultado_cancelado("RAM")
            ModuloSistema._registrar_evento_benchmark_configurador_ti(
                "BENCHMARK_ETAPA_CONCLUIDA", nome_modo, "RAM",
                f"status={ram.get('Status')};score={ram.get('Score')}",
            )

            ModuloSistema._emitir_progresso_benchmark_configurador_ti(
                progress_callback, 72, "Medindo armazenamento em arquivo temporário controlado..."
            )
            if precondicao_armazenamento.get("Disponivel"):
                armazenamento = ModuloSistema._executar_armazenamento_benchmark_configurador_ti(
                    configuracao, cancel_callback
                )
            else:
                armazenamento = (
                    precondicao_armazenamento.get("Resultado")
                    or {
                        "Status": "Pulado",
                        "Score": None,
                        "Mensagem": "Pré-condição de armazenamento não disponível.",
                    }
                )
            if armazenamento.get("Status") == "Cancelada" or cancelada():
                return resultado_cancelado("Armazenamento")
            if armazenamento.get("FalhaLimpezaTemporario"):
                mensagem = armazenamento.get("Mensagem") or "Falha ao limpar arquivo temporário Configurador TI."
                ModuloSistema._registrar_evento_benchmark_configurador_ti(
                    "BENCHMARK_FALHOU", nome_modo, "Armazenamento",
                    "falha_limpeza_temporario=true",
                )
                return {"Sucesso": False, "Cancelada": False, "Mensagem": mensagem, "CPU": cpu, "RAM": ram, "Armazenamento": armazenamento}
            ModuloSistema._registrar_evento_benchmark_configurador_ti(
                "BENCHMARK_ETAPA_CONCLUIDA", nome_modo, "Armazenamento",
                f"status={armazenamento.get('Status')};score={armazenamento.get('Score')}",
            )

            ModuloSistema._emitir_progresso_benchmark_configurador_ti(
                progress_callback, 88, "Registrando GPU indisponível e consolidando scores..."
            )
            gpu = {
                "Status": "Não disponível nesta fase",
                "Score": None,
                "Mensagem": "Benchmark de GPU não disponível nesta fase; nenhum score foi estimado.",
            }
            scores = {
                "CPU": cpu.get("Score"),
                "RAM": ram.get("Score"),
                "Armazenamento": armazenamento.get("Score"),
                "GPU": None,
            }
            score_geral, pesos = ModuloSistema._score_geral_benchmark_configurador_ti(scores)
            scores["Geral"] = score_geral
            parcial = any(
                componente.get("Status") in {"Falhou", "Pulado"}
                for componente in (ram, armazenamento)
            )
            if ram.get("Status") == "Pulado":
                avisos.append(ram.get("Mensagem") or "Benchmark de RAM foi pulado com segurança.")
            if armazenamento.get("Status") == "Pulado":
                aviso_armazenamento = (
                    armazenamento.get("Mensagem")
                    or "Benchmark de armazenamento foi pulado com segurança."
                )
                if aviso_armazenamento not in avisos:
                    avisos.append(aviso_armazenamento)
            if armazenamento.get("Status") == "Falhou":
                avisos.append(armazenamento.get("Mensagem") or "A etapa de armazenamento falhou de forma controlada.")
            if ram.get("Status") == "Falhou":
                avisos.append(ram.get("Mensagem") or "A etapa de RAM falhou de forma controlada.")

            temperaturas = ModuloSistema._extrair_temperaturas_snapshot_benchmark_configurador_ti(
                dados_saude_armazenamento
            )
            if temperaturas:
                contexto["TemperaturasArmazenamentoSnapshot"] = temperaturas
                contexto["OrigemTemperaturasArmazenamento"] = (
                    "Saúde de Armazenamento (última análise); não houve nova consulta SMART."
                )

            duracao = round(time.monotonic() - inicio, 2)
            resultado = {
                "Sucesso": True,
                "Cancelada": False,
                "Parcial": parcial,
                "BenchmarkVersion": BENCHMARK_CONFIGURADOR_TI_VERSION,
                "VersaoAplicativo": "Configurador TI v5.0",
                "Modo": nome_modo,
                "DuracaoSegundos": duracao,
                "Contexto": contexto,
                "Componentes": {
                    "CPU": cpu,
                    "RAM": ram,
                    "Armazenamento": armazenamento,
                    "GPU": gpu,
                },
                "Scores": scores,
                "PesosScoreGeral": pesos,
                "Avisos": avisos,
            }
            resultado["Mensagem"] = (
                "Benchmark Configurador TI concluído parcialmente; consulte as etapas indisponíveis ou falhas controladas."
                if parcial else "Benchmark Configurador TI concluído."
            )

            historico_atual, _, erro_historico = ModuloSistema._carregar_historico_benchmark_configurador_ti()
            anteriores = []
            if not erro_historico:
                hostname = str(contexto.get("Hostname") or "").casefold()
                anteriores = [
                    item for item in (historico_atual.get("Resultados") or [])
                    if isinstance(item, dict)
                    and str(item.get("Hostname") or "").casefold() == hostname
                ]
                anteriores.sort(key=lambda item: str(item.get("Timestamp") or ""), reverse=True)
            resultado["ComparacaoAnterior"] = ModuloSistema._comparar_benchmark_anterior_configurador_ti(
                resultado, anteriores
            )
            entrada_historico = {
                "Timestamp": datetime.now().isoformat(timespec="seconds"),
                "Hostname": contexto.get("Hostname") or "Não disponível",
                "BenchmarkVersion": BENCHMARK_CONFIGURADOR_TI_VERSION,
                "Modo": nome_modo,
                "CPU": {"Modelo": (contexto.get("CPU") or {}).get("Modelo")},
                "RAM": {"TotalBytes": (contexto.get("RAM") or {}).get("TotalBytes")},
                "Armazenamento": {
                    "Volume": (armazenamento.get("Metricas") or {}).get("Volume"),
                },
                "MetricasBrutas": {
                    "CPU": cpu.get("Metricas"),
                    "RAM": ram.get("Metricas"),
                    "Armazenamento": armazenamento.get("Metricas"),
                },
                "Scores": scores,
                "DuracaoSegundos": duracao,
                "VersaoAplicativo": "Configurador TI v5.0",
                "Parcial": parcial,
            }
            salvo, mensagem_historico = ModuloSistema._salvar_historico_benchmark_configurador_ti(
                entrada_historico
            )
            resultado["HistoricoSalvo"] = salvo
            resultado["MensagemHistorico"] = mensagem_historico
            if not salvo:
                resultado["Mensagem"] += " O resultado atual não pôde ser salvo no histórico local."

            ModuloSistema._emitir_progresso_benchmark_configurador_ti(
                progress_callback, 100, "Benchmark Configurador TI finalizado."
            )
            ModuloSistema._registrar_evento_benchmark_configurador_ti(
                "BENCHMARK_CONCLUIDO", nome_modo, "Consolidação",
                (
                    f"duracao_s={duracao};cpu={scores.get('CPU')};ram={scores.get('RAM')};"
                    f"armazenamento={scores.get('Armazenamento')};geral={scores.get('Geral')};"
                    f"parcial={str(parcial).lower()};historico={str(salvo).lower()}"
                ),
            )
            return resultado
        except Exception as exc:
            duracao = round(time.monotonic() - inicio, 2)
            ModuloSistema._registrar_evento_benchmark_configurador_ti(
                "BENCHMARK_FALHOU", nome_modo, "Inesperada",
                f"tipo={type(exc).__name__};duracao_s={duracao}",
            )
            try:
                logger.exception("Falha controlada no Benchmark Configurador TI")
            except Exception:
                pass
            return {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": "O Benchmark Configurador TI falhou de forma controlada. Consulte configurador_ti.log.",
                "DuracaoSegundos": duracao,
            }
        finally:
            _lock_benchmark_configurador_ti.release()

    @staticmethod
    def verificar_erros_disco(letra: str, progress_callback=None) -> Tuple[bool, str]:
        """Executa CHKDSK /scan preservando a codificação OEM do Windows.

        A versão anterior passava o CHKDSK por PowerShell. Em algumas máquinas
        o texto OEM (cp850) chegava ao Python como UTF-8/ANSI e produzia textos
        como "VerificaþÒo" e "Ýndice". Aqui o executável chkdsk.exe é chamado
        diretamente em bytes e a saída é decodificada com a heurística correta.

        progress_callback(percentual, mensagem) é opcional e permite que a GUI
        mostre o progresso real quando o CHKDSK reporta uma porcentagem.
        """
        letra = str(letra).strip().upper().replace(":", "")
        if not re.fullmatch(r"[A-Z]", letra):
            return False, "Unidade inválida."
        if not elevacao_sob_demanda("verificar erros de disco (CHKDSK)"):
            return False, "Operação cancelada (privilégio de administrador necessário)."

        def emitir(pct, msg):
            if callable(progress_callback):
                try:
                    progress_callback(max(0, min(100, int(pct))), str(msg))
                except Exception:
                    pass

        def decodificar(dados):
            if not dados:
                return ""
            # CHKDSK é um programa nativo e, no Windows em PT-BR, normalmente
            # escreve na página OEM 850 quando stdout é redirecionado.
            candidatos = []
            for codec in ("cp850", "cp1252", "utf-8", "cp437"):
                try:
                    valor = dados.decode(codec)
                except UnicodeDecodeError:
                    continue
                ruim = (
                    valor.count("�") * 20 +
                    valor.count("þ") * 8 +
                    valor.count("Ý") * 8 +
                    valor.count("Ò") * 6 +
                    valor.count("ß") * 6 +
                    valor.count("Ã") * 6 +
                    valor.count("Â") * 4
                )
                bom = sum(valor.count(ch) for ch in "áàãâéêíóôõúçÁÀÃÂÉÊÍÓÔÕÚÇ")
                candidatos.append((ruim - bom, valor))
            if candidatos:
                candidatos.sort(key=lambda x: x[0])
                return candidatos[0][1]
            return dados.decode("utf-8", errors="replace")

        inicio = time.monotonic()
        linhas = []
        ultimo_pct = 0
        processo = None
        try:
            emitir(0, f"Iniciando CHKDSK na unidade {letra}:")
            processo = subprocess.Popen(
                ["chkdsk.exe", f"{letra}:", "/scan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

            while True:
                raw = processo.stdout.readline() if processo.stdout else b""
                if raw:
                    linha = decodificar(raw).rstrip("\r\n")
                    linhas.append(linha)
                    # O CHKDSK pode reportar "Estágio: 85%" ou
                    # "Progresso: ... Estágio: 85%; Total: 37%".
                    m = re.search(r"Estágio:\s*(\d{1,3})\s*%", linha, re.I)
                    if not m:
                        m = re.search(r"Estagio:\s*(\d{1,3})\s*%", linha, re.I)
                    if m:
                        ultimo_pct = max(ultimo_pct, min(99, int(m.group(1))))
                        emitir(ultimo_pct, "CHKDSK em execução")
                    elif "Estágio 3" in linha or "Estagio 3" in linha:
                        ultimo_pct = max(ultimo_pct, 70)
                        emitir(ultimo_pct, "Verificando descritores de segurança")
                    elif "verificando o diário" in linha.lower() or "verificando o diario" in linha.lower():
                        ultimo_pct = max(ultimo_pct, 90)
                        emitir(ultimo_pct, "Verificando diário USN")
                    continue
                if processo.poll() is not None:
                    break
                time.sleep(0.05)

            retorno = processo.wait(timeout=10)
            emitir(100, "CHKDSK concluído")
            saida = "\n".join(linhas).strip()

            if retorno == 0:
                registrar_log(
                    "SISTEMA",
                    "CHKDSK_SCAN",
                    f"Unidade {letra}: verificada com sucesso"
                )
                return True, saida or "Verificação concluída."
            registrar_log(
                "SISTEMA",
                "CHKDSK_SCAN_FALHA",
                f"Unidade {letra}: código {retorno}"
            )
            return False, saida or f"CHKDSK terminou com código {retorno}."
        except subprocess.TimeoutExpired as e:
            if processo is not None:
                try:
                    processo.kill()
                except Exception:
                    pass
            raise RuntimeError("O CHKDSK excedeu o tempo limite de segurança.") from e
        except FileNotFoundError as e:
            raise RuntimeError("CHKDSK não foi encontrado no Windows.") from e
        except Exception as e:
            logger.error(f"Erro ao verificar disco {letra}: {e}")
            return False, str(e)

    @staticmethod
    def otimizar_unidade(letra: str, tipo_midia: str = "Unknown") -> Tuple[bool, str, str]:
        """Otimiza SSD com TRIM e HDD com desfragmentação."""
        letra = str(letra).strip().upper().replace(":", "")
        if not re.fullmatch(r"[A-Z]", letra):
            return False, "Unidade inválida.", ""
        tipo = str(tipo_midia or "Unknown").strip().upper()
        if tipo == "SSD":
            acao = "TRIM / ReTrim (SSD)"
            cmd = f"Optimize-Volume -DriveLetter {letra} -ReTrim -Verbose"
        elif tipo == "HDD":
            acao = "Desfragmentação (HDD)"
            cmd = f"Optimize-Volume -DriveLetter {letra} -Defrag -Verbose"
        else:
            acao = "Otimização automática"
            cmd = f"Optimize-Volume -DriveLetter {letra} -Verbose"
        try:
            res = executar_powershell(cmd, timeout=1800)
            saida = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
            if res.returncode == 0:
                registrar_log("SISTEMA", "OTIMIZAR_UNIDADE", f"{letra}: {acao}")
                return True, acao, saida.strip() or "Operação concluída com sucesso."
            registrar_log("SISTEMA", "OTIMIZAR_UNIDADE_FALHA", f"{letra}: código {res.returncode}")
            return False, acao, saida.strip() or f"Otimização terminou com código {res.returncode}."
        except Exception as e:
            logger.error(f"Erro ao otimizar unidade {letra}: {e}")
            return False, acao, str(e)

    @staticmethod
    def limpar_cache_do_programa() -> Tuple[int, int]:
        base = Path(__file__).resolve().parent
        registrar_evento_instancia(
            "LIMPEZA_ENCERRAMENTO_INICIADA",
            motivo=f"base={base}",
        )
        arquivos = pastas = 0
        for cache in base.rglob('__pycache__'):
            try:
                shutil.rmtree(cache); pastas += 1
            except OSError:
                pass
        for padrao in ('*.tmp','*.temp'):
            for arq in base.glob(padrao):
                try:
                    arq.unlink(); arquivos += 1
                except OSError:
                    pass
        _cache_ps.clear()
        registrar_log('SISTEMA','LIMPEZA_ENCERRAMENTO',f'{arquivos} arquivos temporários e {pastas} caches removidos')
        registrar_evento_instancia(
            "LIMPEZA_ENCERRAMENTO_CONCLUIDA",
            motivo=f"arquivos={arquivos};pastas={pastas}",
        )
        return arquivos, pastas

# ==========================================
# FUNÇÕES DE INTERFACE DO USUÁRIO
# ==========================================
def selecionar_interface() -> Optional[str]:
    print(f"\n{Cores.CIANO}Obtendo lista de adaptadores de rede...{Cores.RESET}")
    adaptadores = ModuloRede.listar_adaptadores_detalhados()
    
    if not adaptadores:
        print(f"{Cores.AMARELO}Nenhum adaptador encontrado.{Cores.RESET}")
        return None
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}{'─' * 60}{Cores.RESET}")
    print(f"{Cores.CIANO}{Cores.NEGRITO}  SELEÇÃO DE ADAPTADOR DE REDE{Cores.RESET}")
    print(f"{Cores.CIANO}{Cores.NEGRITO}{'─' * 60}{Cores.RESET}")
    print(f"{Cores.AMARELO}0 - [ Cancelar e Voltar ]{Cores.RESET}\n")
    
    for idx, adp in enumerate(adaptadores, 1):
        nome = adp.nome
        status = adp.status
        ip = adp.ip or "Sem IP"
        
        status_fmt = f"{Cores.VERDE}●{Cores.RESET} Ativo" if adp.esta_ativo() else f"{Cores.VERMELHO}○{Cores.RESET} Inativo"
        
        print(f"{idx:2} - {Cores.NEGRITO}{nome:<30}{Cores.RESET} {Cores.AZUL_CLARO}{ip:<15}{Cores.RESET} {status_fmt}")
    
    print(f"\n{Cores.CIANO}{Cores.NEGRITO}{'─' * 60}{Cores.RESET}")
    
    while True:
        op = input(f"\nEscolha o adaptador ({Cores.AMARELO}0 para voltar{Cores.RESET}): ").strip()
        if op == "0" or op.lower() in ["voltar", "cancelar", "v", "c"]:
            return None
        if op.isdigit() and 1 <= int(op) <= len(adaptadores):
            return adaptadores[int(op) - 1].nome
        print(f"{Cores.VERMELHO}Opção inválida! Escolha de 0 a {len(adaptadores)}.{Cores.RESET}")

def submenu_perfis_dns(alvo_interface: str):
    while True:
        limpar_tela()
        perfis = gerenciador_perfis.listar()
        
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}{'─' * 60}{Cores.RESET}")
        print(f"{Cores.CIANO}{Cores.NEGRITO}  PERFIS DE CONFIGURAÇÃO DE DNS{Cores.RESET}")
        print(f"{Cores.CIANO}{Cores.NEGRITO}{'─' * 60}{Cores.RESET}")
        print(f"Interface selecionada: {Cores.VERDE}{alvo_interface}{Cores.RESET}\n")
        
        for idx, perfil in enumerate(perfis, 1):
            ips_txt = ", ".join(perfil.servidores)
            desc = f" - {perfil.descricao}" if perfil.descricao else ""
            print(f"{idx:2} - {Cores.NEGRITO}{perfil.nome:<20}{Cores.RESET} ({Cores.AZUL_CLARO}{ips_txt}{Cores.RESET}){Cores.CINZA}{desc}{Cores.RESET}")
        
        print(f"\n{Cores.VERDE}[A] - Adicionar Novo Perfil{Cores.RESET}")
        print(f"{Cores.AMARELO}[E] - Editar Perfil{Cores.RESET}")
        print(f"{Cores.VERMELHO}[R] - Remover Perfil{Cores.RESET}")
        print(f"{Cores.CIANO}[T] - Testar Perfis{Cores.RESET}")
        print(f"{Cores.CINZA}[0] - Voltar{Cores.RESET}")
        print(f"\n{Cores.CIANO}{Cores.NEGRITO}{'─' * 60}{Cores.RESET}")
        
        op = input("\nEscolha: ").strip().upper()
        
        if op == "0":
            break
        
        elif op == "A":
            print(f"\n{Cores.NEGRITO}Cadastrar Novo Perfil{Cores.RESET}")
            nome_p = input("Nome do Perfil: ").strip()
            if not nome_p:
                continue
            
            desc = input("Descrição (opcional): ").strip()
            
            pref = input("DNS Preferencial: ").strip()
            v1, m1 = validar_ip_estrito(pref)
            if not v1:
                print(f"{Cores.VERMELHO}❌ {m1}{Cores.RESET}")
                input("Pressione Enter...")
                continue
            
            sec = input("DNS Secundário (opcional): ").strip()
            ips_novos = [pref]
            if sec:
                v2, m2 = validar_ip_estrito(sec)
                if v2:
                    ips_novos.append(sec)
                else:
                    print(f"{Cores.AMARELO}⚠️ DNS Secundário inválido, ignorado.{Cores.RESET}")
            
            novo_perfil = PerfilDNS(nome_p, ips_novos, desc)
            gerenciador_perfis.adicionar(novo_perfil)
            print(f"{Cores.VERDE}✅ Perfil '{nome_p}' salvo!{Cores.RESET}")
            input("Pressione Enter...")
        
        elif op == "E":
            num = input("Número do perfil para editar: ").strip()
            if num.isdigit() and 1 <= int(num) <= len(perfis):
                perfil = perfis[int(num) - 1]
                print(f"\nEditando: {perfil.nome}")
                print(f"Servidores atuais: {', '.join(perfil.servidores)}")
                # Implementação simplificada - poderia ter edição completa
                input("Pressione Enter para continuar...")
        
        elif op == "R":
            num = input("Número do perfil para remover: ").strip()
            if num.isdigit() and 1 <= int(num) <= len(perfis):
                perfil = perfis[int(num) - 1]
                if confirmar_acao(f"Remover '{perfil.nome}'?", padrao=False):
                    gerenciador_perfis.remover(perfil.nome)
                    print(f"{Cores.AMARELO}🗑️ Perfil removido.{Cores.RESET}")
                input("Pressione Enter...")
        
        elif op == "T":
            print(f"\n{Cores.CIANO}Testando todos os servidores DNS...{Cores.RESET}")
            for perfil in perfis:
                print(f"\n{perfil.nome}:")
                for ip in perfil.servidores:
                    ok, lat = testar_servidor_dns(ip)
                    status = f"{Cores.VERDE}✓ Online ({lat:.0f}ms){Cores.RESET}" if ok else f"{Cores.VERMELHO}✗ Offline{Cores.RESET}"
                    print(f"  {ip}: {status}")
            input("\nPressione Enter...")
        
        elif op.isdigit() and 1 <= int(op) <= len(perfis):
            perfil = perfis[int(op) - 1]
            print(f"\n{Cores.CIANO}Aplicando perfil '{perfil.nome}'...{Cores.RESET}")
            sucesso, erro = ModuloRede.aplicar_dns(alvo_interface, perfil.servidores)
            if sucesso:
                print(f"{Cores.VERDE}✅ Perfil aplicado com sucesso!{Cores.RESET}")
            else:
                print(f"{Cores.VERMELHO}❌ Erro: {erro}{Cores.RESET}")
            input("Pressione Enter...")

def sub_menu_rede():
    """Menu de rede com tratamento explícito de erros em cada opção."""
    while True:
        limpar_tela()
        print(f"{Cores.CIANO}{'═' * 60}{Cores.RESET}")
        print(f"{Cores.CIANO}{Cores.NEGRITO}{'CONFIGURAÇÕES DE REDE & DNS':^60}{Cores.RESET}")
        print(f"{Cores.CIANO}{'═' * 60}{Cores.RESET}\n")

        print(f" {MenuRede.CONSULTAR.value} - 🔍 {Cores.CIANO}Consultar informações detalhadas{Cores.RESET}")
        print(f" {MenuRede.PERFIS_DNS.value} - 📋 {Cores.AZUL}Usar Perfis de DNS Salvos{Cores.RESET}")
        print(f" {MenuRede.DNS_MANUAL.value} - ✏️  {Cores.AMARELO}Configurar DNS Manualmente{Cores.RESET}")
        print(f" {MenuRede.RESTAURAR_DHCP.value} - 🔄 {Cores.VERDE}Restaurar DNS para DHCP{Cores.RESET}")
        print(f" {MenuRede.RENOVAR_CONEXAO.value} - 🔄 {Cores.VERDE}Renovar Conexão (Flush + Renew){Cores.RESET}")
        print(f" {MenuRede.TESTAR_DNS.value} - 🧪 {Cores.MAGENTA}Testar Servidores DNS{Cores.RESET}")
        print(f" {MenuRede.IP_FIXO.value} - 🌐 {Cores.AZUL_CLARO}Configurar IP Fixo, Máscara e Gateway{Cores.RESET}")
        print(f" {MenuRede.VOLTAR.value} - ↩️  {Cores.VERMELHO}Voltar{Cores.RESET}")

        print(f"\n{Cores.CIANO}{'─' * 60}{Cores.RESET}")
        op = input("Escolha: ").strip()

        if op == MenuRede.VOLTAR.value:
            return

        try:
            if op == MenuRede.CONSULTAR.value:
                alvo = selecionar_interface()
                if alvo:
                    ModuloRede.consultar_detalhes_interface(alvo)
                else:
                    print(f"{Cores.AMARELO}Operação cancelada ou nenhum adaptador disponível.{Cores.RESET}")
                input("\nPressione Enter para voltar...")

            elif op == MenuRede.PERFIS_DNS.value:
                alvo = selecionar_interface()
                if alvo:
                    submenu_perfis_dns(alvo)
                else:
                    print(f"{Cores.AMARELO}Operação cancelada ou nenhum adaptador disponível.{Cores.RESET}")
                    input("\nPressione Enter para voltar...")

            elif op == MenuRede.DNS_MANUAL.value:
                alvo = selecionar_interface()
                if not alvo:
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                    input("\nPressione Enter para voltar...")
                    continue

                print(f"\n💡 Digite '{Cores.AMARELO}voltar{Cores.RESET}' para cancelar.\n")
                p = input("DNS Preferencial: ").strip()
                if p.lower() in ("voltar", "v", "cancelar", "c"):
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                    input("\nPressione Enter para voltar...")
                    continue

                valido, msg = validar_ip_estrito(p)
                if not valido:
                    print(f"{Cores.VERMELHO}❌ {msg}{Cores.RESET}")
                    input("\nPressione Enter para voltar...")
                    continue

                dns_servidores = [p]
                s = input("DNS Secundário (Enter para ignorar): ").strip()
                if s.lower() not in ("voltar", "v", "cancelar", "c", ""):
                    valido, msg = validar_ip_estrito(s)
                    if not valido:
                        print(f"{Cores.VERMELHO}❌ {msg}{Cores.RESET}")
                        input("\nPressione Enter para voltar...")
                        continue
                    dns_servidores.append(s)

                print(f"\nInterface: {Cores.NEGRITO}{alvo}{Cores.RESET}")
                print(f"DNS: {Cores.VERDE}{', '.join(dns_servidores)}{Cores.RESET}")

                if confirmar_acao("Confirmar alteração?", padrao=True):
                    sucesso, erro = ModuloRede.aplicar_dns(alvo, dns_servidores)
                    if sucesso:
                        print(f"{Cores.VERDE}✅ DNS aplicado com sucesso!{Cores.RESET}")
                    else:
                        print(f"{Cores.VERMELHO}❌ Erro: {erro or 'Falha desconhecida.'}{Cores.RESET}")
                else:
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")

                input("\nPressione Enter para voltar...")

            elif op == MenuRede.RESTAURAR_DHCP.value:
                alvo = selecionar_interface()
                if alvo:
                    if confirmar_acao(f"Restaurar DNS para DHCP em '{alvo}'?", padrao=False):
                        if ModuloRede.restaurar_dhcp(alvo):
                            print(f"{Cores.VERDE}✅ DHCP restaurado!{Cores.RESET}")
                        else:
                            print(f"{Cores.VERMELHO}❌ Falha ao restaurar DHCP. Consulte o log para detalhes.{Cores.RESET}")
                    else:
                        print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                else:
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                input("\nPressione Enter para voltar...")

            elif op == MenuRede.RENOVAR_CONEXAO.value:
                if confirmar_acao("Renovar IP e limpar cache DNS?", padrao=True):
                    sucesso, mensagem = ModuloRede.renovar_ip_e_flush_dns()
                    if sucesso:
                        print(f"{Cores.VERDE}✅ {mensagem}{Cores.RESET}")
                    else:
                        print(f"{Cores.VERMELHO}❌ Não foi possível concluir a renovação.{Cores.RESET}")
                        print(f"{Cores.AMARELO}{mensagem}{Cores.RESET}")
                else:
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                input("\nPressione Enter para voltar...")

            elif op == MenuRede.TESTAR_DNS.value:
                print(f"\n{Cores.CIANO}Servidores DNS públicos para teste:{Cores.RESET}")
                servidores_teste = {
                    "Google": ["8.8.8.8", "8.8.4.4"],
                    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
                    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
                    "Quad9": ["9.9.9.9", "149.112.112.112"]
                }

                for nome, ips in servidores_teste.items():
                    print(f"\n{Cores.NEGRITO}{nome}:{Cores.RESET}")
                    for ip in ips:
                        ok, lat = testar_servidor_dns(ip, timeout=3)
                        if ok:
                            print(f"  {ip}: {Cores.VERDE}✓ Online ({lat:.0f}ms){Cores.RESET}")
                        else:
                            print(f"  {ip}: {Cores.VERMELHO}✗ Sem resposta{Cores.RESET}")

                input("\nPressione Enter para voltar...")

            elif op == MenuRede.IP_FIXO.value:
                alvo = selecionar_interface()
                if not alvo:
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                    input("\nPressione Enter para voltar...")
                    continue

                print(f"\n{Cores.CIANO}Configuração IPv4 estática para: {Cores.NEGRITO}{alvo}{Cores.RESET}")
                print(f"{Cores.CINZA}Informe a máscara como 255.255.255.0 ou prefixo como 24. Digite 'voltar' para cancelar.{Cores.RESET}")
                ip_fixo = input("IP fixo: ").strip()
                if ip_fixo.lower() in ("voltar", "v", "cancelar", "c"):
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                    input("\nPressione Enter para voltar...")
                    continue
                mascara = input("Máscara / Prefixo: ").strip().lstrip("/")
                gateway = input("Gateway padrão: ").strip()

                print(f"\nInterface: {Cores.NEGRITO}{alvo}{Cores.RESET}")
                print(f"IP: {Cores.VERDE}{ip_fixo}{Cores.RESET}  Máscara/Prefixo: {Cores.VERDE}{mascara}{Cores.RESET}")
                print(f"Gateway: {Cores.VERDE}{gateway}{Cores.RESET}")
                if confirmar_acao("Aplicar esta configuração de IP? A conexão poderá ser interrompida temporariamente.", padrao=False):
                    ok, msg = ModuloRede.configurar_ip_fixo(alvo, ip_fixo, mascara, gateway)
                    print(f"{Cores.VERDE if ok else Cores.VERMELHO}{'✅' if ok else '❌'} {msg}{Cores.RESET}")
                else:
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                input("\nPressione Enter para voltar...")

            else:
                print(f"{Cores.VERMELHO}❌ Opção inválida!{Cores.RESET}")
                input("\nPressione Enter para continuar...")

        except Exception as e:
            logger.exception(f"Erro na opção de rede {op}")
            print(f"\n{Cores.VERMELHO}❌ Ocorreu um erro: {e}{Cores.RESET}")
            print(f"{Cores.CINZA}O erro completo foi registrado em {ARQUIVO_LOG}.{Cores.RESET}")
            input("\nPressione Enter para voltar...")


def sub_menu_sistema():
    while True:
        limpar_tela()
        print(f"{Cores.MAGENTA}{'═' * 60}{Cores.RESET}")
        print(f"{Cores.MAGENTA}{Cores.NEGRITO}{'MANUTENÇÃO & DIAGNÓSTICO':^60}{Cores.RESET}")
        print(f"{Cores.MAGENTA}{'═' * 60}{Cores.RESET}\n")
        
        print(f" {MenuSistema.DIAGNOSTICO.value} - 🔍 {Cores.CIANO}Diagnóstico Completo{Cores.RESET}")
        print(f" {MenuSistema.LIMPEZA_TEMP.value} - 🟢 {Cores.VERDE}Limpar Arquivos Temporários{Cores.RESET}")
        print(f" {MenuSistema.SPOOLER.value} - 🖨️  {Cores.AMARELO}Reiniciar Spooler de Impressão{Cores.RESET}")
        print(f" {MenuSistema.INFO_DETALHADA.value} - 📊 {Cores.AZUL}Informações Detalhadas do Sistema{Cores.RESET}")
        print(f" {MenuSistema.VERIFICAR_DISCO.value} - 🔍 {Cores.AMARELO}Verificar Erros na Unidade (CHKDSK){Cores.RESET}")
        print(f" {MenuSistema.OTIMIZAR_DISCO.value} - ⚡ {Cores.VERDE}Otimizar / Desfragmentar Unidade{Cores.RESET}")
        print(f" {MenuSistema.PLANO_ENERGIA.value} - 🔋 {Cores.VERDE}Ajustar Plano de Energia{Cores.RESET}")
        print(f" {MenuSistema.WINDOWS_UPDATE.value} - 🔄 {Cores.AZUL_CLARO}Executar Windows Update{Cores.RESET}")
        print(f" {MenuSistema.VERSAO_WINDOWS.value} - 🪟 {Cores.CIANO}Verificar Versão do Windows{Cores.RESET}")
        print(f" {MenuSistema.RENOMEAR_COMPUTADOR.value} - 🖥️  {Cores.MAGENTA}Renomear Computador{Cores.RESET}")
        print(f" {MenuSistema.GERENCIADOR_TAREFAS.value} - 📋 {Cores.AZUL}Gerenciador de Tarefas{Cores.RESET}")
        print(f" {MenuSistema.MONITORAMENTO_ATIVO.value} - 📡 {Cores.VERDE}Monitoramento Ativo + Alertas{Cores.RESET}")
        print(f" {MenuSistema.PERFIL_EMPRESA.value} - 🏢 {Cores.CIANO}Perfil da Empresa / Inventário{Cores.RESET}")
        print(f" {MenuSistema.INVENTARIO_REDE.value} - 🌐 {Cores.CIANO}Descobrir Equipamentos da Rede{Cores.RESET}")
        print(f" {MenuSistema.VOLTAR.value} - ↩️  {Cores.VERMELHO}Voltar{Cores.RESET}")
        
        print(f"\n{Cores.MAGENTA}{'─' * 60}{Cores.RESET}")
        op = input("Escolha: ").strip()
        
        if op == MenuSistema.VOLTAR.value:
            break
        
        elif op == MenuSistema.DIAGNOSTICO.value:
            ModuloSistema.exibir_diagnostico_completo()
            input("\nPressione Enter...")
        
        elif op == MenuSistema.LIMPEZA_TEMP.value:
            if confirmar_acao("Limpar arquivos temporários?", padrao=True):
                print(f"\n{Cores.AMARELO}Limpando...{Cores.RESET}")
                _, msg, qtd = ModuloSistema.limpar_arquivos_temporarios()
                print(f"{Cores.VERDE}✅ {msg}{Cores.RESET}")
            input("Pressione Enter...")
        
        elif op == MenuSistema.SPOOLER.value:
            if confirmar_acao("Reiniciar spooler de impressão?", padrao=True):
                if ModuloSistema.reiniciar_spooler_impressao():
                    print(f"{Cores.VERDE}✅ Spooler reiniciado!{Cores.RESET}")
                else:
                    print(f"{Cores.VERMELHO}❌ Falha ao reiniciar spooler{Cores.RESET}")
            input("Pressione Enter...")
        
        elif op == MenuSistema.INFO_DETALHADA.value:
            # Informações adicionais do sistema
            print(f"\n{Cores.CIANO}Coletando informações detalhadas...{Cores.RESET}")
            info = ModuloSistema.obter_informacoes_sistema()
            
            if info:
                print(f"\n{Cores.NEGRITO}Informações do Sistema:{Cores.RESET}")
                for chave, valor in info.items():
                    if chave not in ['DiscosFisicos', 'Particoes']:
                        print(f"  {chave}: {valor}")

            input("\nPressione Enter...")

        elif op == MenuSistema.PLANO_ENERGIA.value:
            print(f"\n{Cores.CIANO}{Cores.NEGRITO}{'═' * 58}{Cores.RESET}")
            print(f"{Cores.CIANO}{Cores.NEGRITO}{'PLANOS DE ENERGIA DISPONÍVEIS':^58}{Cores.RESET}")
            print(f"{Cores.CIANO}{Cores.NEGRITO}{'═' * 58}{Cores.RESET}")
            ok, planos, msg = ModuloSistema.obter_planos_energia()
            if not ok:
                print(f"{Cores.VERMELHO}❌ {msg}{Cores.RESET}")
            elif not planos:
                print(f"{Cores.AMARELO}⚠️ Nenhum plano de energia foi identificado.{Cores.RESET}")
            else:
                print(f"{Cores.CINZA}Os planos padrão ausentes são restaurados automaticamente.{Cores.RESET}\n")
                for i, plano in enumerate(planos, 1):
                    status = f" {Cores.VERDE}[ATIVO]{Cores.RESET}" if plano.get('ativo') else ""
                    print(f" {Cores.AMARELO}{i:>2}{Cores.RESET} - {plano['nome']}{status}")
                print(f" {Cores.AMARELO} 0{Cores.RESET} - Cancelar")
                esc = input("\nEscolha o plano: ").strip()
                if esc.isdigit() and 1 <= int(esc) <= len(planos):
                    plano = planos[int(esc) - 1]
                    if confirmar_acao(f"Ativar o plano '{plano['nome']}'?", padrao=True):
                        ok2, msg2 = ModuloSistema.ajustar_plano_energia(plano['guid'])
                        cor = Cores.VERDE if ok2 else Cores.VERMELHO
                        icone = 'OK' if ok2 else 'ERRO'
                        print(f"{cor}[{icone}] {msg2}{Cores.RESET}")
                elif esc != "0":
                    print(f"{Cores.VERMELHO}[ERRO] Opção inválida.{Cores.RESET}")
            input("\nPressione Enter...")

        elif op == MenuSistema.WINDOWS_UPDATE.value:
            print(f"\n{Cores.CIANO}{Cores.NEGRITO}WINDOWS UPDATE{Cores.RESET}")
            print(f"{Cores.CINZA}O indicador mostra o andamento por etapas. O Windows não fornece uma estimativa confiável de tempo restante durante todas as fases.{Cores.RESET}\n")
            ok, msg = ModuloSistema.executar_windows_update()
            print(f"\n{Cores.VERDE if ok else Cores.VERMELHO}{'[OK]' if ok else '[ERRO]'} {msg}{Cores.RESET}")
            input("\nPressione Enter...")

        elif op == MenuSistema.VERSAO_WINDOWS.value:
            dados = ModuloSistema.obter_versao_windows()
            if dados:
                largura = 58
                print(f"\n{Cores.CIANO}{Cores.NEGRITO}{'═' * largura}{Cores.RESET}")
                print(f"{Cores.CIANO}{Cores.NEGRITO}{'INFORMAÇÕES DA VERSÃO DO WINDOWS':^{largura}}{Cores.RESET}")
                print(f"{Cores.CIANO}{Cores.NEGRITO}{'═' * largura}{Cores.RESET}")
                linhas = [
                    ("Sistema", dados.get('Nome', 'N/A')),
                    ("Edição", dados.get('Edicao', dados.get('Edition', 'N/A'))),
                    ("Versão", dados.get('DisplayVersion', 'N/A')),
                    ("Build completa", dados.get('BuildCompleta', dados.get('Build', 'N/A'))),
                    ("Versão técnica", dados.get('VersaoTecnica', dados.get('Versao', 'N/A'))),
                    ("Arquitetura", dados.get('Arquitetura', 'N/A')),
                    ("Tipo de instalação", dados.get('Instalacao', 'N/A')),
                ]
                for rotulo, valor in linhas:
                    print(f" {Cores.AMARELO}{rotulo:<19}{Cores.RESET}: {valor}")
                print(f"{Cores.CIANO}{'═' * largura}{Cores.RESET}")
            else:
                print(f"{Cores.VERMELHO}[ERRO] Não foi possível consultar a versão do Windows.{Cores.RESET}")
            input("\nPressione Enter...")

        elif op == MenuSistema.GERENCIADOR_TAREFAS.value:
            print(f"\n{Cores.CIANO}📋 Abrindo Gerenciador de Tarefas...{Cores.RESET}")
            ok, msg = ModuloSistema.abrir_gerenciador_tarefas()
            if not ok:
                print(f"{Cores.VERMELHO}❌ {msg}{Cores.RESET}")
                input("\nPressione Enter...")

        elif op == MenuSistema.MONITORAMENTO_ATIVO.value:
            ok, msg = ModuloEmpresa.abrir_monitoramento_ativo()
            if not ok:
                print(f"{Cores.VERMELHO}❌ {msg}{Cores.RESET}")
                input("Pressione Enter...")

        elif op == MenuSistema.PERFIL_EMPRESA.value:
            sub_menu_empresa()

        elif op == MenuSistema.INVENTARIO_REDE.value:
            ModuloEmpresa.exibir_inventario_rede()
            input("Pressione Enter...")

        elif op == MenuSistema.RENOMEAR_COMPUTADOR.value:
            atual = os.environ.get("COMPUTERNAME", "N/A")
            print(f"\n{Cores.CIANO}🖥️  RENOMEAR COMPUTADOR{Cores.RESET}")
            print(f"Nome atual: {Cores.AMARELO}{atual}{Cores.RESET}")
            print(f"{Cores.CINZA}Use até 15 caracteres: letras, números e hífen. A reinicialização será necessária.{Cores.RESET}")
            novo = input("Novo nome (Enter para cancelar): ").strip()
            if not novo:
                print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
            elif confirmar_acao(f"Renomear '{atual}' para '{novo}'?", padrao=False):
                ok, msg = ModuloSistema.renomear_computador(novo)
                print(f"{Cores.VERDE if ok else Cores.VERMELHO}{'✅' if ok else '❌'} {msg}{Cores.RESET}")
            else:
                print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
            input("\nPressione Enter...")

        elif op in (MenuSistema.VERIFICAR_DISCO.value, MenuSistema.OTIMIZAR_DISCO.value):
            unidades = ModuloSistema.listar_unidades()
            if not unidades:
                print(f"{Cores.VERMELHO}❌ Não foi possível obter as unidades do computador.{Cores.RESET}")
                input("Pressione Enter...")
                continue
            print(f"\n{Cores.CIANO}{Cores.NEGRITO}UNIDADES DISPONÍVEIS{Cores.RESET}")
            for idx, unidade in enumerate(unidades, 1):
                print(f" {Cores.CIANO}{idx}{Cores.RESET} - {unidade.get('DriveLetter')}: | {unidade.get('SizeGB', 0)} GB | Livre: {unidade.get('FreeGB', 0)} GB | Tipo: {unidade.get('MediaType', 'Unknown')}")
            print(f" {Cores.VERMELHO}0 - Cancelar{Cores.RESET}")
            escolha = input("Escolha a unidade: ").strip()
            if escolha == "0":
                continue
            if not escolha.isdigit() or not (1 <= int(escolha) <= len(unidades)):
                print(f"{Cores.VERMELHO}❌ Opção inválida.{Cores.RESET}")
                input("Pressione Enter...")
                continue
            unidade = unidades[int(escolha) - 1]
            letra = str(unidade.get("DriveLetter"))
            if op == MenuSistema.VERIFICAR_DISCO.value:
                print(f"\n{Cores.AMARELO}🔍 Verificando a unidade {letra}:... Isso pode demorar.{Cores.RESET}")
                sucesso, resultado = executar_com_indicador(
                    lambda: ModuloSistema.verificar_erros_disco(letra),
                    f"CHKDSK em andamento na unidade {letra}:"
                )
                print(f"\n{Cores.VERDE if sucesso else Cores.VERMELHO}{'✅' if sucesso else '❌'} {'Verificação concluída.' if sucesso else 'Falha na verificação.'}{Cores.RESET}")
                if resultado:
                    print(f"\n{resultado[-4000:]}")
                input("\nPressione Enter...")
            else:
                tipo = unidade.get("MediaType", "Unknown")
                tipo_upper = str(tipo).upper()
                if tipo_upper == "SSD":
                    aviso = "Será executado TRIM/ReTrim. O SSD não será desfragmentado da forma tradicional."
                elif tipo_upper == "HDD":
                    aviso = "Será executada a desfragmentação da unidade."
                else:
                    aviso = "O tipo da mídia não foi identificado. O Windows decidirá a otimização adequada."
                print(f"\n{Cores.AMARELO}⚠️ {aviso}{Cores.RESET}")
                if confirmar_acao(f"Continuar com a otimização da unidade {letra}:?", padrao=False):
                    print(f"\n{Cores.AMARELO}⚡ Otimizando a unidade {letra}:... Isso pode demorar.{Cores.RESET}")
                    sucesso, acao, resultado = executar_com_indicador(
                        lambda: ModuloSistema.otimizar_unidade(letra, tipo),
                        f"Otimizando a unidade {letra}:"
                    )
                    print(f"\nAção: {acao}")
                    print(f"{Cores.VERDE if sucesso else Cores.VERMELHO}{'✅' if sucesso else '❌'} {'Otimização concluída.' if sucesso else 'Falha na otimização.'}{Cores.RESET}")
                    if resultado:
                        print(f"\n{resultado[-4000:]}")
                else:
                    print(f"{Cores.AMARELO}Operação cancelada.{Cores.RESET}")
                input("\nPressione Enter...")

def sub_menu_logs():
    limpar_tela()
    print(f"{Cores.AMARELO}{'═' * 60}{Cores.RESET}")
    print(f"{Cores.AMARELO}{Cores.NEGRITO}{'LOGS E HISTÓRICO':^60}{Cores.RESET}")
    print(f"{Cores.AMARELO}{'═' * 60}{Cores.RESET}\n")
    
    if os.path.exists(ARQUIVO_LOG):
        try:
            with open(ARQUIVO_LOG, "r", encoding="utf-8") as f:
                linhas = f.readlines()
            
            print(f"Total de entradas: {len(linhas)}\n")
            print(f"{Cores.CINZA}Últimas 20 entradas:{Cores.RESET}\n")
            
            for linha in linhas[-20:]:
                try:
                    dados = json.loads(linha.strip())
                    timestamp = dados.get('timestamp', 'N/A')
                    level = dados.get('level', 'INFO')
                    msg = dados.get('mensagem', '')
                    
                    cor = Cores.CINZA
                    if level == 'ERROR':
                        cor = Cores.VERMELHO
                    elif level == 'WARNING':
                        cor = Cores.AMARELO
                    elif level == 'INFO':
                        cor = Cores.VERDE
                    
                    print(f"{cor}[{timestamp}] {level}: {msg[:80]}{Cores.RESET}")
                except json.JSONDecodeError:
                    print(f"{Cores.CINZA}{linha.strip()[:100]}{Cores.RESET}")
            
            print(f"\n{Cores.CIANO}[E] Exportar para TXT  [L] Limpar logs  [0] Voltar{Cores.RESET}")
            op = input("\nEscolha: ").strip().upper()
            
            if op == 'E':
                arquivo_export = f"export_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(arquivo_export, 'w', encoding='utf-8') as out:
                    for linha in linhas:
                        out.write(linha)
                print(f"{Cores.VERDE}✅ Exportado para: {arquivo_export}{Cores.RESET}")
                input("Pressione Enter...")
            
            elif op == 'L':
                if confirmar_acao("Limpar todos os logs?", padrao=False):
                    open(ARQUIVO_LOG, 'w').close()
                    print(f"{Cores.VERDE}✅ Logs limpos.{Cores.RESET}")
                    input("Pressione Enter...")
        except Exception as e:
            print(f"{Cores.VERMELHO}Erro ao ler logs: {e}{Cores.RESET}")
            input("Pressione Enter...")
    else:
        print("Nenhum log registrado.")
        input("Pressione Enter...")


def _barra_progresso_relatorio(atual: int, total: int, texto: str):
    """Exibe uma barra visual limpa e sempre finaliza em 100%."""
    largura = 32
    total = max(int(total or 1), 1)
    atual = min(max(int(atual), 0), total)
    pct = int((atual / total) * 100)
    preenchido = int(largura * pct / 100)
    barra = "█" * preenchido + "░" * (largura - preenchido)
    linha = f"📊 [{barra}] {pct:3d}% - {texto}"
    print(f"\r{Cores.CIANO}{linha:<90}{Cores.RESET}", end="", flush=True)
    if atual >= total:
        print()


def _html_seguro(valor: Any) -> str:
    """Evita que dados coletados do computador quebrem o HTML."""
    return html.escape(str(valor if valor not in (None, "") else "N/A"))


def _normalizar_lista(valor):
    if valor is None:
        return []
    return valor if isinstance(valor, list) else [valor]


def formatar_acao_relatorio(acao: str):
    nomes = {
        "OTIMIZAR_UNIDADE": "Otimização da unidade",
        "CHKDSK_SCAN": "Verificação de erros (CHKDSK)",
        "SPOOLER": "Reinicialização do Spooler",
        "LIMPEZA_TEMP": "Limpeza de arquivos temporários",
        "LIMPEZA_TEMPORARIOS": "Limpeza de arquivos temporários",
        "CONFIGURAR_DNS": "Configuração de DNS",
        "RESTAURAR_DHCP": "Restauração automática de DNS (DHCP)",
        "RENOVAR_IP": "Renovação de endereço IP",
    }
    return nomes.get(str(acao), str(acao).replace("_", " ").title())


def _acoes_recentes_relatorio(limite: int = 50):
    """
    Retorna somente operações realmente registradas durante a execução atual,
    evitando misturar ações antigas de outros atendimentos.
    """
    ignorar = {"GERAR_RELATORIO_COMPLETO", "LIMPEZA_ENCERRAMENTO", "INICIALIZACAO"}
    acoes = []

    for item in _historico_operacoes_sessao[-limite:]:
        if str(item.get("acao", "")) in ignorar:
            continue
        acoes.append((
            str(item.get("timestamp", "")),
            str(item.get("categoria", "")),
            str(item.get("acao", "")),
            str(item.get("detalhes", "")),
        ))

    return acoes[::-1]



def gerar_relatorio(interativo: bool = True):
    """Gera o relatório completo nos modos console e GUI.

    ``interativo=False`` é o contrato usado pela interface PyQt6: não chama
    ``input()`` nem depende de um console disponível. O modo console original
    permanece preservado por padrão.
    """
    if interativo:
        limpar_tela()
        print(f"{Cores.AZUL}{'═' * 60}{Cores.RESET}")
        print(
            f"{Cores.AZUL}{Cores.NEGRITO}"
            f"{'GERAR RELATÓRIO COMPLETO':^60}{Cores.RESET}"
        )
        print(f"{Cores.AZUL}{'═' * 60}{Cores.RESET}\n")

    arquivo_saida = PASTA_RELATORIOS / (
        f"relatorio_ti_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )
    total_etapas = 8

    try:
        _barra_progresso_relatorio(1, total_etapas, "Coletando sistema")
        info = ModuloSistema.obter_informacoes_sistema() or {}

        _barra_progresso_relatorio(2, total_etapas, "Coletando hardware")
        hardware = ModuloSistema.obter_hardware_detalhado() or {}

        _barra_progresso_relatorio(3, total_etapas, "Coletando CPU e memória")
        _cpu_ram_cmd = "$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1 Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed; $os=Get-CimInstance Win32_OperatingSystem; [pscustomobject]@{CPU=$cpu.Name;Fabricante=$cpu.Manufacturer;Nucleos=$cpu.NumberOfCores;Threads=$cpu.NumberOfLogicalProcessors;ClockMHz=$cpu.MaxClockSpeed;RAMTotalGB=[math]::Round($os.TotalVisibleMemorySize/1MB,2);RAMLivreGB=[math]::Round($os.FreePhysicalMemory/1MB,2);RAMUsoPct=[math]::Round((1-($os.FreePhysicalMemory/$os.TotalVisibleMemorySize))*100,1)} | ConvertTo-Json -Compress"
        try:
            _r_cpu_ram=executar_powershell(_cpu_ram_cmd, timeout=20)
            cpu_ram=json.loads(_r_cpu_ram.stdout or '{}') if _r_cpu_ram.returncode==0 else {}
        except Exception:
            cpu_ram={}

        _barra_progresso_relatorio(4, total_etapas, "Coletando rede")
        adaptadores = ModuloRede.listar_adaptadores_detalhados() or []

        _barra_progresso_relatorio(
            4, total_etapas, "Lendo ações realizadas"
        )
        acoes = _acoes_recentes_relatorio()

        _barra_progresso_relatorio(6, total_etapas, "Montando relatório")

        particoes = _normalizar_lista(info.get("Particoes"))
        ram = _normalizar_lista(hardware.get("RAM"))
        discos = _normalizar_lista(hardware.get("Discos"))

        linhas_volumes = ""

        for volume in particoes:
            tamanho = float(volume.get("SizeGB") or 0)
            livre = float(volume.get("FreeGB") or 0)

            valor_usado = volume.get("UsedGB")
            usado = float(
                valor_usado
                if valor_usado is not None
                else max(tamanho - livre, 0)
            )

            percentual = (
                round((usado / tamanho) * 100, 1)
                if tamanho > 0
                else 0
            )

            status = (
                "ok"
                if percentual < 70
                else "warn"
                if percentual < 85
                else "error"
            )

            letra = _html_seguro(volume.get("DriveLetter"))
            sistema_arquivos = _html_seguro(volume.get("FileSystem"))

            linhas_volumes += (
                '<div class="disk-card">'
                f"<div><b>{letra}:\\</b> — {sistema_arquivos}</div>"
                '<div class="progress">'
                f'<div class="fill {status}" '
                f'style="width:{min(max(percentual, 0), 100)}%"></div>'
                "</div>"
                f"<div>{percentual}% usado — {usado:.1f} GB / "
                f"{tamanho:.1f} GB | Livre: {livre:.1f} GB</div>"
                "</div>"
            )

        if not linhas_volumes:
            linhas_volumes = "<p>Nenhum volume encontrado.</p>"

        linhas_ram = "".join(
            (
                "<tr>"
                f"<td>{_html_seguro(item.get('Banco'))}</td>"
                f"<td>{_html_seguro(item.get('Fabricante'))}</td>"
                f"<td>{_html_seguro(item.get('Tipo'))}</td>"
                f"<td>{_html_seguro(item.get('CapacidadeGB'))} GB</td>"
                f"<td>{_html_seguro(item.get('VelocidadeMHz'))} MHz</td>"
                f"<td>{_html_seguro(item.get('Modelo'))}</td>"
                "</tr>"
            )
            for item in ram
        ) or '<tr><td colspan="6">Não disponível</td></tr>'

        linhas_discos = "".join(
            (
                "<tr>"
                f"<td>{_html_seguro(item.get('Nome'))}</td>"
                f"<td>{_html_seguro(item.get('Tipo'))}</td>"
                f"<td>{_html_seguro(item.get('Interface'))}</td>"
                f"<td>{_html_seguro(item.get('TamanhoGB'))} GB</td>"
                f"<td>{_html_seguro(item.get('Saude'))}</td>"
                "</tr>"
            )
            for item in discos
        ) or '<tr><td colspan="5">Não disponível</td></tr>'

        linhas_rede = "".join(
            (
                "<tr>"
                f"<td>{_html_seguro(adaptador.nome)}</td>"
                f"<td>{'Ativo' if adaptador.esta_ativo() else 'Inativo'}</td>"
                f"<td>{_html_seguro(adaptador.ip)}</td>"
                f"<td>{_html_seguro(adaptador.mac)}</td>"
                "</tr>"
            )
            for adaptador in adaptadores
        ) or '<tr><td colspan="4">Nenhum adaptador encontrado.</td></tr>'

        linhas_acoes = "".join(
            (
                "<tr>"
                f"<td>{_html_seguro(data)}</td>"
                f"<td class=\"historico-area\">{_html_seguro(categoria)}</td>"
                f"<td class=\"historico-servico\">{_html_seguro(acao)}</td>"
                f"<td class=\"historico-detalhes\">{_html_seguro(detalhes)}</td>"
                "</tr>"
            )
            for data, categoria, acao, detalhes in acoes
        ) or '<tr><td colspan="4">Nenhum serviço ou alteração foi registrado durante este atendimento.</td></tr>'

        total_acoes = len(acoes)
        try:
            inv=json.loads(Path(ARQUIVO_INVENTARIO).read_text(encoding='utf-8')) if Path(ARQUIVO_INVENTARIO).exists() else {}
        except Exception: inv={}
        perfil_emp=ModuloEmpresa.carregar_perfil()
        inv_hosts=_normalizar_lista(inv.get('Hosts')); inv_impressoras=_normalizar_lista(inv.get('Impressoras')); inv_ativos=_normalizar_lista(perfil_emp.get('ativos_manuais'))
        linhas_inventario=''.join(f"<tr><td>Host / Dispositivo</td><td>{_html_seguro(x.get('Nome') or 'Não identificado')}</td><td>{_html_seguro(x.get('IP'))}</td><td>{_html_seguro(x.get('MAC'))}</td><td>{_html_seguro(x.get('Estado') or x.get('Interface'))}</td></tr>" for x in inv_hosts)
        linhas_inventario+=''.join(f"<tr><td>Impressora</td><td>{_html_seguro(x.get('Nome'))}</td><td>{_html_seguro(x.get('IP') or '—')}</td><td>—</td><td>{_html_seguro(x.get('Porta'))}</td></tr>" for x in inv_impressoras)
        linhas_inventario+=''.join(f"<tr><td>{_html_seguro(x.get('tipo') or 'Ativo')}</td><td>{_html_seguro(x.get('nome'))}</td><td>{_html_seguro(x.get('ip'))}</td><td>—</td><td>{_html_seguro(x.get('descricao'))}</td></tr>" for x in inv_ativos)
        if not linhas_inventario: linhas_inventario='<tr><td colspan="5">Nenhum inventário corporativo salvo.</td></tr>'
        inventario_resumo=f"Hosts: {len(inv_hosts)} | Impressoras: {len(inv_impressoras)} | Ativos cadastrados: {len(inv_ativos)}"

        # Dados da centralização: incorporados também ao relatório individual.
        _barra_progresso_relatorio(5, total_etapas, "Lendo centralização")
        try:
            central_cfg = ModuloCentralizacao.carregar_config()
            central_coletas = ModuloCentralizacao.carregar_coletas()
            hoje_central = datetime.now().strftime('%Y-%m-%d')
            central_ultimas = {}
            for coleta in central_coletas:
                if coleta.get('data') == hoje_central:
                    maquina = coleta.get('maquina', 'Desconhecida')
                    if maquina not in central_ultimas or coleta.get('coletado_em', '') > central_ultimas[maquina].get('coletado_em', ''):
                        central_ultimas[maquina] = coleta
            central_dados = sorted(central_ultimas.values(), key=lambda x: str(x.get('maquina', '')))
        except Exception as _erro_central:
            logger.warning('Não foi possível ler dados da centralização para o relatório: %s', _erro_central)
            central_cfg = {'empresa': '', 'unidade': '', 'pasta_central': 'Não disponível'}
            central_dados = []

        linhas_central = ''
        total_acoes_central = 0
        for coleta in central_dados:
            sis_c = coleta.get('sistema') or {}
            hw_c = coleta.get('hardware') or {}
            acoes_c = coleta.get('acoes') or []
            total_acoes_central += len(acoes_c)
            cpu_c = hw_c.get('CPU') or hw_c.get('Processador') or sis_c.get('CPU') or 'N/A'
            ram_c = sum(float(x.get('CapacidadeGB') or 0) for x in _normalizar_lista(hw_c.get('RAM')))
            linhas_central += (
                '<tr>'
                f'<td>{_html_seguro(coleta.get("maquina"))}</td>'
                f'<td>{_html_seguro(coleta.get("usuario"))}</td>'
                f'<td>{_html_seguro(coleta.get("coletado_em"))}</td>'
                f'<td>{_html_seguro(cpu_c)}</td>'
                f'<td>{ram_c:.1f} GB</td>'
                f'<td>{len(acoes_c)}</td>'
                '</tr>'
            )
        if not linhas_central:
            linhas_central = '<tr><td colspan="6">Nenhuma coleta centralizada encontrada para hoje.</td></tr>'
        central_empresa = _html_seguro(central_cfg.get('empresa') or perfil_emp.get('empresa') or 'Não configurada')
        central_unidade = _html_seguro(central_cfg.get('unidade') or perfil_emp.get('unidade') or 'Não configurada')
        central_pasta = _html_seguro(central_cfg.get('pasta_central') or 'Não configurada')
        cpu_nome=_html_seguro(cpu_ram.get('CPU') or hardware.get('Processador') or 'Não disponível')
        cpu_fab=_html_seguro(cpu_ram.get('Fabricante') or '—')
        cpu_nucleos=_html_seguro(cpu_ram.get('Nucleos') or '—')
        cpu_threads=_html_seguro(cpu_ram.get('Threads') or '—')
        cpu_clock=_html_seguro(cpu_ram.get('ClockMHz') or '—')
        ram_total=_html_seguro(cpu_ram.get('RAMTotalGB') or '—')
        ram_livre=_html_seguro(cpu_ram.get('RAMLivreGB') or '—')
        ram_uso=_html_seguro(cpu_ram.get('RAMUsoPct') or '—')

        html_relatorio = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>Relatório TI - {_html_seguro(info.get('HostName'))}</title>
<style>
@page {{ size: A4 portrait; margin: 14mm 12mm 16mm 12mm; }}
* {{ box-sizing: border-box; }}
html, body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 0; background: #f4f6f8; color: #222; }}
body {{ font-size: 10.5pt; line-height: 1.35; }}
.container {{ width: 100%; max-width: 190mm; margin: auto; background: #fff; padding: 0; }}
h1 {{ border-bottom: 3px solid #2563eb; padding-bottom: 10px; margin: 0 0 8px; font-size: 21pt; }}
h2 {{ margin-top: 22px; color: #1e293b; font-size: 14pt; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; }}
h3 {{ font-size: 11.5pt; }}
.grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }}
.card, .disk-card {{ background: #f8fafc; padding: 10px; border-radius: 7px; border: 1px solid #e2e8f0; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 9px; font-size: 9pt; }}
th, td {{ padding: 7px 6px; text-align: left; border-bottom: 1px solid #e2e8f0; vertical-align: top; word-break: break-word; }}
th {{ background: #0f172a; color: #fff; }}
.progress {{ height: 14px; background: #e5e7eb; border-radius: 7px; overflow: hidden; margin: 6px 0; }}
.fill {{ height: 100%; }}
.ok {{ background: #16a34a; }}
.warn {{ background: #f59e0b; }}
.error {{ background: #dc2626; }}
.muted {{ color: #64748b; }}
.footer {{ margin-top: 24px; padding-top: 10px; border-top: 1px solid #ddd; color: #64748b; font-size: 8.5pt; }}
.summary-card {{ border: 1px solid #dbeafe; background: #eff6ff; border-radius: 10px; padding: 12px; }}
.section-break {{ break-before: auto; }}
@media print {{
    body {{ background: #fff; }}
    .container {{ max-width: none; padding: 0; }}
    h1, h2, h3 {{ break-after: avoid; }}
    .card, .disk-card, .historico-card, .central-card, .summary-card {{ box-shadow: none; break-inside: avoid; }}
    table {{ break-inside: auto; }}
    thead {{ display: table-header-group; }}
    tr {{ break-inside: avoid; break-after: auto; }}
    .no-print {{ display: none !important; }}
}}
.container {{ max-width: 1100px; margin: auto; background: #fff; padding: 30px; }}
h1 {{ border-bottom: 3px solid #3498db; padding-bottom: 12px; }}
h2 {{ margin-top: 35px; color: #34495e; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; }}
.card, .disk-card {{ background: #f7f9fb; padding: 14px; border-radius: 8px; border: 1px solid #e2e7eb; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #3498db; color: #fff; }}
.progress {{ height: 18px; background: #e5e7eb; border-radius: 9px; overflow: hidden; margin: 8px 0; }}
.fill {{ height: 100%; }}
.ok {{ background: #27ae60; }}
.warn {{ background: #f39c12; }}
.error {{ background: #e74c3c; }}
.muted {{ color: #667085; }}
.footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #ddd; color: #667085; }}

        .historico-card {{
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 14px;
            padding: 22px;
            margin-top: 18px;
            box-shadow: 0 8px 22px rgba(15, 23, 42, 0.06);
        }}
        .historico-resumo {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin: 14px 0 18px 0;
        }}
        .historico-badge {{
            background: #f1f5f9;
            border: 1px solid #e2e8f0;
            border-radius: 999px;
            padding: 8px 12px;
            font-size: 13px;
            font-weight: 600;
        }}
        .historico-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            overflow: hidden;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
        }}
        .historico-table th {{
            background: #0f172a;
            color: #ffffff;
            padding: 13px 12px;
            text-align: left;
            font-size: 13px;
            letter-spacing: .2px;
        }}
        .historico-table td {{
            padding: 13px 12px;
            border-top: 1px solid #eef2f7;
            vertical-align: top;
            font-size: 13px;
        }}
        .historico-table tr:nth-child(even) td {{ background: #f8fafc; }}
        .historico-area {{
            font-weight: 700;
            color: #334155;
            white-space: nowrap;
        }}
        .historico-servico {{
            font-weight: 700;
            color: #0f172a;
        }}
        .historico-detalhes {{
            color: #475569;
            line-height: 1.45;
        }}
        .central-card {{
            background: linear-gradient(135deg, #eff6ff, #f8fafc);
            border: 1px solid #bfdbfe;
            border-radius: 14px;
            padding: 20px;
            margin-top: 20px;
        }}
        .central-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin: 14px 0; }}
        .central-meta div {{ background: #fff; border: 1px solid #dbeafe; border-radius: 10px; padding: 12px; }}
        .central-meta b {{ display: block; color: #1e3a5f; margin-bottom: 4px; }}
        @media print {{
            body {{ background: #fff; }}
            .container {{ max-width: none; padding: 0; }}
            .card, .disk-card, .historico-card, .central-card {{ box-shadow: none; break-inside: avoid; }}
            h2 {{ break-after: avoid; }}
            table {{ break-inside: auto; }}
            tr {{ break-inside: avoid; break-after: auto; }}
        }}

    </style>
</head>
<body>
<div class="container">
<h1>🔧 Relatório Completo de Configuração TI</h1>
<p class="muted">Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>

<h2>📋 Sistema e Processador</h2>
<div class="grid">
<div class="card"><b>Hostname</b><br>{_html_seguro(info.get('HostName'))}</div>
<div class="card"><b>Usuário</b><br>{_html_seguro(info.get('Usuario'))}</div>
<div class="card"><b>Sistema</b><br>{_html_seguro(info.get('OS'))}</div>
<div class="card"><b>Versão do Windows</b><br>{_html_seguro(info.get('VersaoOS'))}</div>
<div class="card"><b>Processador</b><br>{_html_seguro(hardware.get('CPU') or info.get('CPU'))}</div>
<div class="card"><b>CPU / Núcleos</b><br>
{_html_seguro(hardware.get('CPUFabricante'))} |
{_html_seguro(hardware.get('Nucleos'))} núcleos /
{_html_seguro(hardware.get('ProcessadoresLogicos'))} threads
</div>
<div class="card"><b>Clock máximo</b><br>{_html_seguro(hardware.get('ClockMaxMHz'))} MHz</div>
<div class="card"><b>RAM total / livre</b><br>
{_html_seguro(info.get('RAMTotalGB'))} GB /
{_html_seguro(info.get('RAMLivreGB'))} GB
</div>
<div class="card"><b>Placa-mãe</b><br>{_html_seguro(info.get('PlacaMae'))}</div>
<div class="card"><b>BIOS</b><br>{_html_seguro(info.get('BIOS'))}</div>
</div>

<h2>🧠 Memória RAM</h2>
<table>
<tr><th>Banco</th><th>Fabricante</th><th>Tipo</th><th>Capacidade</th><th>Velocidade</th><th>Modelo</th></tr>
{linhas_ram}
</table></div>

<h2>🧠 CPU e memória</h2>
<div class="grid">
  <div class="card"><b>Processador</b><br>{cpu_nome}<br><span class="muted">{cpu_fab} | {cpu_nucleos} núcleos | {cpu_threads} threads | {cpu_clock} MHz</span></div>
  <div class="card"><b>Memória RAM</b><br>{ram_total} GB total<br><span class="muted">Livre: {ram_livre} GB | Uso atual: {ram_uso}%</span></div>
</div>
<h3>Módulos de memória instalados</h3>
<table><tr><th>Banco</th><th>Fabricante</th><th>Tipo</th><th>Capacidade</th><th>Velocidade</th><th>Modelo</th></tr>{linhas_ram}</table>

<h2>💾 Discos físicos</h2>
<table>
<tr><th>Nome</th><th>Tipo</th><th>Interface</th><th>Tamanho</th><th>Saúde</th></tr>
{linhas_discos}
</table>

<h2>📂 Uso das unidades</h2>
{linhas_volumes}

<h2>🌐 Adaptadores de rede</h2>
<table>
<tr><th>Nome</th><th>Status</th><th>IP</th><th>MAC</th></tr>
{linhas_rede}
</table>

<div class="central-card">
<h2>🏢 Centralização, Relatórios e E-mail</h2>
<p class="muted">Resumo das informações coletadas hoje pela central. Os dados abaixo são incluídos automaticamente neste relatório HTML.</p>
<div class="central-meta">
<div><b>Empresa</b>{central_empresa}</div>
<div><b>Unidade</b>{central_unidade}</div>
<div><b>Máquinas coletadas hoje</b>{len(central_dados)}</div>
<div><b>Ações centralizadas</b>{total_acoes_central}</div>
</div>
<div><b>Pasta central:</b> <span class="muted">{central_pasta}</span></div>
<table>
<tr><th>Máquina</th><th>Usuário</th><th>Última coleta</th><th>CPU</th><th>RAM</th><th>Ações</th></tr>
{linhas_central}
</table>
</div>

<div class="historico-card">
<h2>🌐 Inventário corporativo da rede</h2>
<p>{_html_seguro(inventario_resumo)}</p>
<table><thead><tr><th>Tipo</th><th>Nome / Host</th><th>IP</th><th>MAC</th><th>Status / Porta / Detalhes</th></tr></thead><tbody>{linhas_inventario}</tbody></table>

<h2>🛠️ Histórico de Serviços Executados</h2>
<p class="muted">Registro técnico das ações efetivamente executadas durante esta sessão.</p>
<div class="historico-resumo"><span class="historico-badge">Total de ações: {total_acoes}</span><span class="historico-badge">Sessão atual</span></div>
<table class="historico-table">
<tr><th>Data e hora</th><th>Área</th><th>Serviço executado</th><th>Resultado / detalhes</th></tr>
{linhas_acoes}
</table>
</div>

<div class="footer">
Gerado por Configurador de TI v2.3 — diagnóstico, hardware,
armazenamento, rede e histórico de operações.
</div>
</div>
</body>
</html>
"""

        _barra_progresso_relatorio(7, total_etapas, "Preparando arquivo")

        arquivo_publicado = _gravar_arquivo_atomico(arquivo_saida, html_relatorio)
        _validar_leitura_artefato(arquivo_publicado, exigir_conteudo=True)

        registrar_evento_instancia(
            "RELATORIO_ABERTURA_SOLICITADA",
            motivo="os.startfile",
            executavel_destino=os.path.abspath(arquivo_publicado),
            argumentos_destino=[],
        )
        try:
            os.startfile(os.path.abspath(arquivo_publicado))
        except Exception as exc:
            registrar_evento_instancia(
                "RELATORIO_ABERTURA_FALHOU",
                motivo=f"os.startfile:{type(exc).__name__}",
                executavel_destino=os.path.abspath(arquivo_publicado),
                argumentos_destino=[],
            )
            logger.exception("Falha ao abrir o relatório no aplicativo padrão")
            raise RuntimeError(
                f"O relatório foi publicado em {arquivo_publicado}, mas não pôde "
                "ser aberto no aplicativo padrão. Verifique o acesso ao arquivo."
            ) from exc

        _barra_progresso_relatorio(8, total_etapas, "Arquivo salvo com sucesso")
        registrar_log(
            "RELATORIO",
            "GERAR_RELATORIO_COMPLETO",
            f"Arquivo gerado: {arquivo_publicado}",
        )

        print(
            f"{Cores.VERDE}✅ Relatório completo gerado: "
            f"{arquivo_publicado}{Cores.RESET}"
        )

        return True, str(arquivo_publicado)

    except Exception as e:
        logger.exception("Erro ao gerar relatório completo")
        if interativo:
            print(f"\n{Cores.VERMELHO}❌ Erro ao gerar relatório: {e}{Cores.RESET}")
        return False, str(e)
    finally:
        if interativo:
            try:
                input("\nPressione Enter...")
            except (EOFError, OSError):
                pass



# ==========================================
# EMPRESA / INVENTÁRIO / MONITORAMENTO (ADICIONAL)
# ==========================================
ARQUIVO_EMPRESA = str(CAMINHOS.file("perfil_empresa.json"))
ARQUIVO_INVENTARIO = str(CAMINHOS.file("inventario_empresa.json"))
CAMINHOS.log_events(logger)

class ModuloEmpresa:
    @staticmethod
    def carregar_perfil():
        try:
            if Path(ARQUIVO_EMPRESA).exists():
                return json.loads(Path(ARQUIVO_EMPRESA).read_text(encoding="utf-8"))
        except Exception as e:
            logger.error(f"Perfil empresa: {e}")
        return {"empresa":"Não configurada","unidade":"Não configurada","tecnicos":[],"observacoes":"","ativos_manuais":[]}

    @staticmethod
    def salvar_perfil(d):
        Path(ARQUIVO_EMPRESA).write_text(json.dumps(d,ensure_ascii=False,indent=2),encoding="utf-8")
        registrar_log("EMPRESA","SALVAR_PERFIL",d.get("empresa","Sem nome"))

    @staticmethod
    def coletar_inventario_rede():
        script = r"""
$ErrorActionPreference='SilentlyContinue'
$h=@(Get-NetNeighbor -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch '^(0\.0\.0\.0|127\.)' -and $_.State -notin @('Unreachable','Incomplete')
} | ForEach-Object {
    [pscustomobject]@{IP=$_.IPAddress;MAC=$_.LinkLayerAddress;Interface=$_.InterfaceAlias;Estado=$_.State}
})
$p=@(Get-Printer | ForEach-Object {
    [pscustomobject]@{Nome=$_.Name;Driver=$_.DriverName;Porta=$_.PortName;Compartilhada=$_.Shared}
})
$i=@(foreach($cfg in @(Get-NetIPConfiguration | Where-Object {$_.IPv4Address})) {
    $adapter=Get-NetAdapter -InterfaceIndex $cfg.InterfaceIndex -ErrorAction SilentlyContinue
    $ip=@($cfg.IPv4Address | Where-Object {$_.IPAddress -and $_.IPAddress -notlike '127.*'} |
        Sort-Object @{Expression={if ($_.IPAddress -like '169.254.*') {1} else {0}}},IPAddress |
        Select-Object -First 1)
    if (-not $ip) { continue }
    $route=@(Get-NetRoute -InterfaceIndex $cfg.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1)
    $ipInterface=Get-NetIPInterface -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $interfaceMetric=if ($ipInterface) {[int]$ipInterface.InterfaceMetric} else {0}
    $gateway=if ($route -and $route[0].NextHop) {[string]$route[0].NextHop} else {''}
    $metric=if ($route) {[int]$route[0].RouteMetric + $interfaceMetric} else {$null}
    [pscustomobject]@{
        Interface=[string]$cfg.InterfaceAlias
        InterfaceAlias=[string]$cfg.InterfaceAlias
        InterfaceIndex=[int]$cfg.InterfaceIndex
        Status=if ($adapter) {[string]$adapter.Status} else {''}
        Descricao=if ($adapter) {[string]$adapter.InterfaceDescription} else {''}
        Virtual=if ($adapter) {[bool]$adapter.Virtual -or -not [bool]$adapter.HardwareInterface} else {$true}
        Tipo=if ($adapter) {[string]$adapter.ifType} else {''}
        IP=[string]$ip[0].IPAddress
        IPv4=[string]$ip[0].IPAddress
        PrefixLength=[int]$ip[0].PrefixLength
        Gateway=$gateway
        RouteMetric=$metric
        DNS=(@($cfg.DNSServer.ServerAddresses) -join ', ')
    }
})
[pscustomobject]@{Data=(Get-Date).ToString('s');Hosts=$h;Impressoras=$p;Interfaces=$i;Computador=$env:COMPUTERNAME}|ConvertTo-Json -Depth 6 -Compress
"""
        try:
            r=executar_powershell(script,timeout=30)
            if r.returncode: return False,{},r.stderr.strip() or 'Falha ao consultar a rede.'
            d=json.loads(r.stdout or '{}')
            for k in ('Hosts','Impressoras'):
                if isinstance(d.get(k),dict): d[k]=[d[k]]
                if d.get(k) is None: d[k]=[]
            d['Empresa']=ModuloEmpresa.carregar_perfil()
            d['Interfaces']=d.get('Interfaces') if isinstance(d.get('Interfaces'),list) else ([d.get('Interfaces')] if d.get('Interfaces') else [])
            d['Resumo']={'TotalHosts':len(d['Hosts']),'TotalImpressoras':len(d['Impressoras']),'TotalInterfaces':len(d['Interfaces']),'AtivosManuais':len(d['Empresa'].get('ativos_manuais',[]))}
            _salvar_inventario_empresa(d)
            registrar_log('EMPRESA','INVENTARIO_REDE',f"Hosts: {len(d['Hosts'])}; Impressoras: {len(d['Impressoras'])}")
            return True,d,'Inventário atualizado.'
        except Exception as e:
            logger.error(f'Inventário: {e}'); return False,{},str(e)

    @staticmethod
    def _avaliar_interfaces_varredura(interfaces):
        """Normaliza e classifica interfaces para a varredura IPv4 limitada.

        A regra é centralizada no backend para que GUI e console não dependam
        da ordem devolvida pelo Windows nem de nomes fixos como Wi-Fi/Ethernet.
        Somente uma /24 contida na rede local real é liberada para o scanner.
        """
        candidatas=[]
        rejeitadas=[]
        termos_tunel=('teredo','isatap','6to4','tunnel','tunel','pseudo-interface')

        def rejeitar(alias, ipv4, motivo):
            rejeitadas.append({'Alias':alias or 'Não identificado','IPv4':ipv4 or '', 'Motivo':motivo})

        for item in interfaces or []:
            if not isinstance(item,dict):
                continue
            alias=str(item.get('InterfaceAlias') or item.get('Interface') or item.get('Alias') or '').strip()
            descricao=str(item.get('Descricao') or item.get('Description') or '').strip()
            tipo=str(item.get('Tipo') or item.get('Type') or '').strip()
            status=str(item.get('Status') or '').strip()
            ipv4=str(item.get('IPv4') or item.get('IP') or '').split(',')[0].strip()
            texto_adaptador=f'{alias} {descricao} {tipo}'.casefold()

            if 'loopback' in texto_adaptador:
                rejeitar(alias,ipv4,'loopback')
                continue
            if any(termo in texto_adaptador for termo in termos_tunel):
                rejeitar(alias,ipv4,'tunel')
                continue
            if 'bluetooth' in texto_adaptador:
                rejeitar(alias,ipv4,'bluetooth')
                continue
            if status.casefold() not in ('up','connected','1','ativo'):
                rejeitar(alias,ipv4,'desconectada')
                continue
            try:
                endereco=ipaddress.IPv4Address(ipv4)
            except (ipaddress.AddressValueError,ValueError):
                rejeitar(alias,ipv4,'ipv4_invalido')
                continue
            if endereco.is_loopback:
                rejeitar(alias,ipv4,'loopback')
                continue
            if endereco.is_link_local:
                rejeitar(alias,ipv4,'apipa')
                continue
            if endereco.is_unspecified or endereco.is_multicast or not endereco.is_private:
                rejeitar(alias,ipv4,'ipv4_invalido')
                continue
            try:
                prefixo=int(item.get('PrefixLength',24))
                if not 0 <= prefixo <= 32:
                    raise ValueError
                rede_real=ipaddress.ip_network(f'{endereco}/{prefixo}',strict=False)
            except (TypeError,ValueError):
                rejeitar(alias,ipv4,'mascara_invalida')
                continue
            # Uma máscara mais restritiva que /24 não contém um bloco /24
            # inteiro. Expandir a descoberta poderia alcançar vizinhos fora da
            # rede real, portanto essa interface não é liberada nesta fase.
            if prefixo > 24:
                rejeitar(alias,ipv4,'mascara_mais_restritiva_que_/24')
                continue
            rede_scan=ipaddress.ip_network(f'{endereco}/24',strict=False)
            gateway=str(item.get('Gateway') or '').split(',')[0].strip()
            try:
                gateway_endereco=ipaddress.IPv4Address(gateway)
                if gateway_endereco.is_unspecified or gateway_endereco.is_loopback or gateway_endereco.is_multicast:
                    gateway=''
            except (ipaddress.AddressValueError,ValueError):
                gateway=''
            try:
                metrica=int(item.get('RouteMetric'))
            except (TypeError,ValueError):
                metrica=999999
            candidata={
                'Alias':alias or 'Interface sem nome',
                'InterfaceAlias':alias or 'Interface sem nome',
                'InterfaceIndex':item.get('InterfaceIndex'),
                'Status':status,
                'IPv4':str(endereco),
                'Mascara':str(rede_real.netmask),
                'PrefixLength':prefixo,
                'RedeReal':str(rede_real),
                'Rede':str(rede_scan),
                'Gateway':gateway,
                'RouteMetric':metrica,
                'DNS':item.get('DNS') or '',
                'Descricao':descricao,
                'Virtual':bool(item.get('Virtual')) or any(t in texto_adaptador for t in ('vpn','hyper-v','vethernet','wsl','docker','virtual','wireguard','tap-')),
            }
            candidatas.append(candidata)

        candidatas.sort(key=lambda item:(0 if item.get('Gateway') else 1,item.get('RouteMetric',999999),item.get('Alias','').casefold(),item.get('IPv4','')))
        selecionada=dict(candidatas[0]) if candidatas else None
        if selecionada:
            if len(candidatas)==1:
                motivo='unica_valida'
            elif selecionada.get('Gateway'):
                motivo='gateway'
            else:
                motivo='fallback'
            selecionada['MotivoSelecao']=motivo
            candidatas[0]=dict(selecionada)
        return {'Candidatas':candidatas,'Rejeitadas':rejeitadas,'Selecionada':selecionada}

    @staticmethod
    def _registrar_avaliacao_interfaces_varredura(avaliacao):
        candidatas=avaliacao.get('Candidatas',[]) if isinstance(avaliacao,dict) else []
        rejeitadas=avaliacao.get('Rejeitadas',[]) if isinstance(avaliacao,dict) else []
        registrar_log('EMPRESA','INTERFACES_SCAN_DETECTADAS',f'Total: {len(candidatas)+len(rejeitadas)}; Elegíveis: {len(candidatas)}')
        for item in rejeitadas[:8]:
            motivo=item.get('Motivo')
            if motivo in ('apipa','desconectada','loopback','tunel','ipv4_invalido','bluetooth'):
                registrar_log('EMPRESA','INTERFACE_SCAN_REJEITADA',f"Alias: {item.get('Alias')}; IPv4: {item.get('IPv4') or '—'}; Motivo: {motivo}")
        selecionada=avaliacao.get('Selecionada') if isinstance(avaliacao,dict) else None
        if selecionada:
            registrar_log('EMPRESA','INTERFACE_SCAN_SELECIONADA',f"Alias: {selecionada.get('Alias')}; IPv4: {selecionada.get('IPv4')}; Rede: {selecionada.get('Rede')}; Gateway: {selecionada.get('Gateway') or '—'}; Motivo: {selecionada.get('MotivoSelecao','fallback')}")

    @staticmethod
    def obter_interfaces_varredura():
        """Retorna somente interfaces seguras para a varredura detalhada."""
        ok,base,msg=ModuloEmpresa.coletar_inventario_rede()
        if not ok:
            return False,{},msg
        avaliacao=ModuloEmpresa._avaliar_interfaces_varredura(base.get('Interfaces',[]))
        ModuloEmpresa._registrar_avaliacao_interfaces_varredura(avaliacao)
        base['InterfacesVarredura']=avaliacao.get('Candidatas',[])
        base['InterfaceVarreduraSelecionada']=avaliacao.get('Selecionada')
        if not avaliacao.get('Candidatas'):
            return False,avaliacao,'Não foi encontrada interface IPv4 ativa adequada para a varredura /24. APIPA, túnel, Bluetooth, loopback e interfaces desconectadas não são selecionados automaticamente.'
        return True,avaliacao,f"{len(avaliacao.get('Candidatas',[]))} interface(s) elegível(is) para varredura."

    @staticmethod
    def _medir_ping_monitoramento(alvo, timeout_ms=800):
        """Mede um ping curto sem deixar a coleta de monitoramento travar.

        A chamada é usada apenas dentro de Worker/QThread pela GUI. O retorno
        separado de latência evita mostrar ``0 ms`` quando não houve resposta.
        """
        if not alvo:
            return None, None
        try:
            inicio=time.perf_counter()
            resultado=subprocess.run(
                ['ping','-n','1','-w',str(max(1,int(timeout_ms))),str(alvo)],
                capture_output=True,
                timeout=max(2,(max(1,int(timeout_ms))/1000)+1),
            )
            if resultado.returncode==0:
                return True,max(1,round((time.perf_counter()-inicio)*1000))
        except (OSError,subprocess.SubprocessError,ValueError):
            pass
        return False, None

    @staticmethod
    def _testar_internet_monitoramento(timeout=1.5):
        """Verifica uma conexão TCP externa curta, sem enviar conteúdo útil."""
        try:
            inicio=time.perf_counter()
            with socket.create_connection(('1.1.1.1',443),timeout=max(.1,float(timeout))):
                return True,max(1,round((time.perf_counter()-inicio)*1000))
        except (OSError,ValueError):
            return False, None

    @staticmethod
    def obter_snapshot_monitoramento(cancel_callback=None):
        """Coleta um retrato pequeno da conectividade para a GUI PyQt6.

        Não instancia Tkinter e não mantém loop próprio. A escolha da interface
        reutiliza a política robusta da varredura de inventário, mas a coleta é
        deliberadamente enxuta para poder rodar em ciclos curtos dentro de um
        Worker. Falhas de rede retornam um estado controlado, nunca traceback
        para a interface.
        """
        def cancelado():
            try:
                return bool(cancel_callback and cancel_callback())
            except Exception:
                return False

        vazio={
            'Status':'Offline','Motivo':'Sem dados de conectividade.',
            'Interface':'—','IPv4':'—','Gateway':'—','GatewayOk':None,
            'GatewayLatencia_ms':None,'DNS':[],'DNSOk':None,
            'DNSLatencia_ms':None,'InternetOk':None,
            'InternetLatencia_ms':None,
            'CPU':None,'RAM':None,'DISCO':None,
            'AtualizadoEm':datetime.now().strftime('%H:%M:%S'),
        }
        if cancelado():
            return False,vazio,'Coleta de monitoramento cancelada antes de iniciar.'

        script=r"""
$ErrorActionPreference='SilentlyContinue'
$interfaces=@(foreach($cfg in @(Get-NetIPConfiguration | Where-Object {$_.IPv4Address})) {
    $adapter=Get-NetAdapter -InterfaceIndex $cfg.InterfaceIndex -ErrorAction SilentlyContinue
    $ip=@($cfg.IPv4Address | Where-Object {$_.IPAddress -and $_.IPAddress -notlike '127.*'} |
        Sort-Object @{Expression={if ($_.IPAddress -like '169.254.*') {1} else {0}}},IPAddress |
        Select-Object -First 1)
    if (-not $ip) { continue }
    $route=@(Get-NetRoute -InterfaceIndex $cfg.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1)
    $ipInterface=Get-NetIPInterface -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $interfaceMetric=if ($ipInterface) {[int]$ipInterface.InterfaceMetric} else {0}
    [pscustomobject]@{
        Interface=[string]$cfg.InterfaceAlias
        InterfaceAlias=[string]$cfg.InterfaceAlias
        InterfaceIndex=[int]$cfg.InterfaceIndex
        Status=if ($adapter) {[string]$adapter.Status} else {''}
        Descricao=if ($adapter) {[string]$adapter.InterfaceDescription} else {''}
        Tipo=if ($adapter) {[string]$adapter.ifType} else {''}
        IP=[string]$ip[0].IPAddress
        IPv4=[string]$ip[0].IPAddress
        PrefixLength=[int]$ip[0].PrefixLength
        Gateway=if ($route -and $route[0].NextHop) {[string]$route[0].NextHop} else {''}
        RouteMetric=if ($route) {[int]$route[0].RouteMetric + $interfaceMetric} else {$null}
        DNS=(@($cfg.DNSServer.ServerAddresses) -join ', ')
    }
})
$os=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -ErrorAction SilentlyContinue |
    Where-Object {$_.Name -eq '_Total'} | Select-Object -First 1
$disco=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
[pscustomobject]@{
    Interfaces=@($interfaces)
    CPU=if ($cpu) {[math]::Round([double]$cpu.PercentProcessorTime,1)} else {$null}
    RAM=if ($os -and $os.TotalVisibleMemorySize -gt 0) {[math]::Round((1-($os.FreePhysicalMemory/$os.TotalVisibleMemorySize))*100,1)} else {$null}
    DISCO=if ($disco -and $disco.Size -gt 0) {[math]::Round((1-($disco.FreeSpace/$disco.Size))*100,1)} else {$null}
}|ConvertTo-Json -Depth 6 -Compress
"""
        try:
            resposta=executar_powershell(script,timeout=10)
            if resposta.returncode:
                detalhe=resposta.stderr.strip() or resposta.stdout.strip() or 'Falha ao consultar os adaptadores.'
                vazio['Motivo']=detalhe
                logger.warning('MONITORAMENTO_SNAPSHOT_FALHOU | %s',detalhe)
                return False,vazio,detalhe
            bruto=json.loads(resposta.stdout or '{}')
            if isinstance(bruto,dict) and 'Interfaces' in bruto:
                interfaces=bruto.get('Interfaces') or []
                metricas={chave:bruto.get(chave) for chave in ('CPU','RAM','DISCO')}
            else:
                interfaces=bruto if isinstance(bruto,list) else ([bruto] if isinstance(bruto,dict) else [])
                metricas={}
            if isinstance(interfaces,dict):
                interfaces=[interfaces]
            if not isinstance(interfaces,list):
                interfaces=[]
        except Exception as exc:
            detalhe=str(exc) or 'Falha ao consultar os adaptadores.'
            vazio['Motivo']=detalhe
            logger.warning('MONITORAMENTO_SNAPSHOT_FALHOU | %s',detalhe)
            return False,vazio,detalhe

        if cancelado():
            return False,vazio,'Coleta de monitoramento cancelada após consultar adaptadores.'

        avaliacao=ModuloEmpresa._avaliar_interfaces_varredura(interfaces)
        selecionada=avaliacao.get('Selecionada')
        if not selecionada:
            vazio['Motivo']='Nenhuma interface IPv4 ativa adequada (APIPA, túnel, Bluetooth, loopback e desconectadas são ignorados).'
            logger.debug('MONITORAMENTO_ATUALIZADO | status=Offline | interface=— | motivo=sem_interface')
            vazio.update(metricas)
            return True,vazio,vazio['Motivo']

        dns_bruto=selecionada.get('DNS') or ''
        if isinstance(dns_bruto,(list,tuple,set)):
            dns=[str(item).strip() for item in dns_bruto if str(item).strip()]
        else:
            dns=[item.strip() for item in str(dns_bruto).split(',') if item.strip()]
        gateway=selecionada.get('Gateway') or ''
        gateway_ok,gateway_latencia=ModuloEmpresa._medir_ping_monitoramento(gateway)
        if cancelado():
            return False,vazio,'Coleta de monitoramento cancelada durante o teste de gateway.'

        dns_ok=dns_latencia=None
        if dns:
            dns_ok,dns_latencia=testar_servidor_dns(dns[0],timeout=2)
        if cancelado():
            return False,vazio,'Coleta de monitoramento cancelada durante o teste de DNS.'

        internet_ok=internet_latencia=None
        if gateway:
            internet_ok,internet_latencia=ModuloEmpresa._testar_internet_monitoramento()

        if not gateway:
            status='Sem gateway'
            motivo='A interface ativa não possui rota padrão IPv4.'
        elif internet_ok and dns_ok is not False:
            status='Online'
            motivo='Conectividade externa e DNS disponíveis.'
        elif gateway_ok or internet_ok or dns_ok:
            status='Instável'
            motivo='Parte dos testes de conectividade não respondeu.'
        else:
            status='Offline'
            motivo='Gateway, DNS e conectividade externa não responderam.'

        snapshot={
            'Status':status,'Motivo':motivo,
            'Interface':selecionada.get('Alias') or '—',
            'IPv4':selecionada.get('IPv4') or '—',
            'Gateway':gateway or '—','GatewayOk':gateway_ok,
            'GatewayLatencia_ms':gateway_latencia,'DNS':dns,'DNSOk':dns_ok,
            'DNSLatencia_ms':dns_latencia,'InternetOk':internet_ok,
            'InternetLatencia_ms':internet_latencia,
            'CPU':metricas.get('CPU'),'RAM':metricas.get('RAM'),
            'DISCO':metricas.get('DISCO'),
            'AtualizadoEm':datetime.now().strftime('%H:%M:%S'),
            'InterfaceSelecionada':selecionada,
        }
        logger.debug(
            'MONITORAMENTO_ATUALIZADO | status=%s | interface=%s | gateway=%s | latencia_gateway=%s',
            status,snapshot['Interface'],snapshot['Gateway'],gateway_latencia,
        )
        return True,snapshot,motivo

    @staticmethod
    def exibir_inventario_rede():
        print(f'\n{Cores.CIANO}{Cores.NEGRITO}🌐 INVENTÁRIO PASSIVO DA REDE{Cores.RESET}')
        print(f'{Cores.CINZA}Consulta vizinhos conhecidos pelo Windows e impressoras instaladas. Não executa varredura agressiva.{Cores.RESET}')
        _barra_progresso_operacao(0, 4, 'Iniciando coleta')
        _barra_progresso_operacao(1, 4, 'Consultando vizinhos da rede')
        _barra_progresso_operacao(2, 4, 'Consultando impressoras')
        _barra_progresso_operacao(3, 4, 'Consultando interfaces')
        ok,d,msg=ModuloEmpresa.coletar_inventario_rede()
        _barra_progresso_operacao(4, 4, 'Salvando inventário')
        if not ok: print(f'{Cores.VERMELHO}❌ {msg}{Cores.RESET}'); return
        print(f'\n{Cores.VERDE}✅ {msg}{Cores.RESET}')
        print(f"Hosts/vizinhos: {len(d.get('Hosts',[]))}")
        for h in d.get('Hosts',[])[:30]: print(f"  • {h.get('IP','?'):<16} {h.get('MAC','N/A')} | {h.get('Interface','N/A')} | {h.get('Estado','N/A')}")
        print(f"\nImpressoras: {len(d.get('Impressoras',[]))}")
        for x in d.get('Impressoras',[]): print(f"  🖨️ {x.get('Nome','N/A')} | {x.get('Porta','N/A')}")

    @staticmethod
    def varredura_completa_rede(progress_callback=None, cancel_callback=None, interface_selecionada=None):
        """Descoberta detalhada, limitada à sub-rede IPv4 /24 atual.

        ICMP e TCP são evidências independentes: uma falha de ping não impede
        a verificação da lista pequena de portas TCP de inventário. A função
        permanece não invasiva: não autentica, não explora falhas e não procura
        portas fora da lista já usada pelo projeto.
        """
        def cancelado():
            try:
                return bool(cancel_callback and cancel_callback())
            except Exception:
                return False

        if cancelado():
            return False, [], 'Varredura cancelada antes da coleta inicial.'

        ok, base, msg = ModuloEmpresa.coletar_inventario_rede()
        if not ok:
            return False, [], msg
        if cancelado():
            return False, [], 'Varredura cancelada após a coleta inicial.'
        if interface_selecionada is None:
            avaliacao=ModuloEmpresa._avaliar_interfaces_varredura(base.get('Interfaces',[]))
            ModuloEmpresa._registrar_avaliacao_interfaces_varredura(avaliacao)
            selecionada=avaliacao.get('Selecionada')
            if not selecionada:
                return False, [], 'Não foi encontrada interface IPv4 ativa adequada para a varredura /24.'
        else:
            # A GUI entrega uma estrutura da interface escolhida. Ela é
            # revalidada, mas nunca é trocada silenciosamente por outra.
            avaliacao=ModuloEmpresa._avaliar_interfaces_varredura([interface_selecionada])
            selecionada=avaliacao.get('Selecionada')
            if not selecionada:
                return False, [], 'A interface selecionada não está adequada para uma varredura IPv4 /24. Atualize a lista e escolha outra interface.'
            selecionada['MotivoSelecao']=str(interface_selecionada.get('MotivoSelecao') or 'escolha_usuario')
            registrar_log('EMPRESA','INTERFACE_SCAN_SELECIONADA',f"Alias: {selecionada.get('Alias')}; IPv4: {selecionada.get('IPv4')}; Rede: {selecionada.get('Rede')}; Gateway: {selecionada.get('Gateway') or '—'}; Motivo: {selecionada.get('MotivoSelecao')}")
        ip_local=selecionada['IPv4']
        rede_varredura=ipaddress.ip_network(selecionada['Rede'],strict=False)
        candidatos=[
            str(endereco) for endereco in rede_varredura.hosts()
            if str(endereco) != ip_local
        ]
        # A coleta inicial já obteve a tabela de vizinhos por Get-NetNeighbor.
        # Ela é uma evidência local complementar: um IP conhecido não é listado
        # como livre somente porque não respondeu ao ping ou às portas testadas.
        vizinhos_cache=set()
        for item in base.get('Hosts',[]) if isinstance(base.get('Hosts',[]),list) else []:
            try:
                endereco=ipaddress.ip_address(str(item.get('IP') or '').strip())
            except (ValueError, AttributeError):
                continue
            if endereco.version==4 and endereco in rede_varredura:
                vizinhos_cache.add(str(endereco))
        gateway=''
        try:
            endereco_gateway=ipaddress.ip_address(str(selecionada.get('Gateway') or '').strip())
            if endereco_gateway.version==4 and endereco_gateway in rede_varredura:
                gateway=str(endereco_gateway)
        except ValueError:
            pass
        encontrados=[]
        analisados=0
        inicio=time.monotonic()
        portas_tcp={80:'HTTP',443:'HTTPS',445:'SMB',3389:'RDP',22:'SSH',9100:'RAW-PRINT',631:'IPP',515:'LPR'}

        def nome_host(ip):
            try: return socket.gethostbyaddr(ip)[0]
            except Exception: pass
            try:
                r=subprocess.run(['ping','-a','-n','1','-w','500',ip],capture_output=True,timeout=2)
                txt=(r.stdout or b'').decode('cp850',errors='ignore')
                m=re.search(r'(?:Disparando|Pinging)\s+([^\s\[]+)',txt,re.I)
                if m and m.group(1)!=ip: return m.group(1)
            except Exception: pass
            return ''
        def mac_por_arp(ip):
            try:
                r=subprocess.run(['arp','-a',ip],capture_output=True,timeout=3)
                txt=(r.stdout or b'').decode('cp850',errors='ignore')
                m=re.search(r'([0-9a-f]{2}(?:-[0-9a-f]{2}){5})',txt,re.I)
                return m.group(1).upper().replace('-',':') if m else 'Não identificado'
            except Exception: return 'Não identificado'
        def testar_porta(ip,porta):
            try:
                with socket.create_connection((ip,porta),timeout=.35):
                    return True,True,False
            except ConnectionRefusedError:
                # A recusa confirma que existe uma pilha TCP respondendo neste
                # endereço, embora a porta específica não esteja aberta.
                return False,True,False
            except socket.timeout:
                return False,False,False
            except OSError:
                # Falhas locais/de rota não devem gerar uma sugestão de IP livre.
                return False,False,True

        def testar(ip):
            if cancelado():
                return None
            icmp_ativo=False
            latencia=None
            erro_indeterminado=False
            try:
                ini=time.monotonic()
                r=subprocess.run(['ping','-n','1','-w','600',ip],capture_output=True,timeout=2)
                icmp_ativo=(r.returncode==0)
                if icmp_ativo:
                    latencia=max(1,int((time.monotonic()-ini)*1000))
            except Exception:
                # Ping é somente uma evidência. Falhas/timeout não impedem TCP.
                icmp_ativo=False
                erro_indeterminado=True

            portas=[]
            tcp_evidencia=False
            # TCP somente: rápido e suficiente para a classificação inicial.
            for porta,servico in portas_tcp.items():
                if cancelado():
                    return None
                porta_aberta,evidencia_uso,erro_porta=testar_porta(ip,porta)
                tcp_evidencia=tcp_evidencia or evidencia_uso
                erro_indeterminado=erro_indeterminado or erro_porta
                if porta_aberta:
                    portas.append(f'{porta}/{servico}')

            tcp_ativo=bool(portas)
            if not icmp_ativo and not tcp_ativo:
                return {
                    'IP':ip,'ICMP':False,'TCPEvidencia':tcp_evidencia,
                    'ErroIndeterminado':erro_indeterminado,'Cancelado':False,
                    'Host':None,
                }

            # Consultas potencialmente mais lentas ocorrem somente quando já há
            # evidência de host. O ping -a complementar só é útil quando o ICMP
            # respondeu; para host somente TCP, evita uma segunda espera ICMP.
            mac=mac_por_arp(ip)
            if cancelado():
                return None
            nome=''
            try:
                nome=socket.gethostbyaddr(ip)[0]
            except Exception:
                if icmp_ativo:
                    nome=nome_host(ip)

            ptxt='; '.join(portas) or 'Nenhum serviço TCP identificado'
            if icmp_ativo and tcp_ativo:
                estado='ICMP + TCP'
                evidencia='icmp+tcp'
            elif icmp_ativo:
                estado='Somente ICMP'
                evidencia='icmp'
            else:
                estado='Somente TCP'
                evidencia='tcp'
                latencia=None
            host_l=(nome+' '+ptxt).lower()
            impressora=any(x in host_l for x in ('print','printer','9100/raw-print','631/ipp','515/lpr'))
            tipo='Impressora de rede' if impressora else ('Servidor/Host' if any(x in ptxt for x in ('445/SMB','3389/RDP','22/SSH')) else 'Dispositivo de rede')
            logger.info('SCAN_HOST_DETECTADO | ip=%s | evidencia=%s | servicos=%s', ip, evidencia, ptxt)
            return {
                'IP':ip,'ICMP':icmp_ativo,'TCPEvidencia':tcp_evidencia,
                'ErroIndeterminado':erro_indeterminado,'Cancelado':False,
                'Host':{'Tipo':tipo,'Nome':nome or 'Não identificado','IP':ip,
                        'MAC':mac,'Estado':estado,'Latencia_ms':latencia,
                        'Servicos':ptxt,'Detalhes':ptxt,'Impressora':impressora},
            }

        print('\n🔎 Varredura detalhada da sub-rede /24...')
        _barra_progresso_operacao(0,len(candidatos),'Preparando descoberta detalhada')
        if progress_callback: progress_callback(0, 'Preparando descoberta detalhada')
        registrar_log('EMPRESA','SCAN_DETALHADO_INICIADO',f"Alias: {selecionada.get('Alias')}; IPv4: {ip_local}; Rede: {rede_varredura}; Gateway: {selecionada.get('Gateway') or '—'}; IPs planejados: {len(candidatos)}; Portas TCP: {', '.join(map(str,portas_tcp))}")
        # Mantém o limite já usado pelo projeto: concorrência previsível, sem
        # aumentar a pressão sobre a máquina/rede em uma varredura /24.
        resultados_por_ip={}
        with ThreadPoolExecutor(max_workers=min(32,len(candidatos))) as ex:
            futuros={ex.submit(testar,ip):ip for ip in candidatos}
            for futuro in as_completed(futuros):
                if cancelado():
                    for pendente in futuros:
                        pendente.cancel()
                    registrar_log('EMPRESA','SCAN_DETALHADO_CANCELADO',f'IPs concluídos antes do cancelamento: {analisados}/{len(candidatos)}')
                    return False, [], f'Varredura cancelada após analisar {analisados} de {len(candidatos)} IPs.'
                analisados+=1
                try:
                    resultado=futuro.result()
                except Exception as exc:
                    # Erro isolado de uma tarefa não invalida os demais hosts.
                    logger.debug('SCAN_HOST_FALHOU | ip=%s | erro=%s', futuros[futuro], exc)
                    resultado={
                        'IP':futuros[futuro],'ICMP':False,'TCPEvidencia':False,
                        'ErroIndeterminado':True,'Cancelado':False,'Host':None,
                    }
                resultados_por_ip[futuros[futuro]]=resultado
                item=resultado.get('Host') if isinstance(resultado,dict) else None
                if item:
                    encontrados.append(item)
                if analisados==len(candidatos) or analisados%3==0:
                    _barra_progresso_operacao(analisados,len(candidatos),f'Analisando hosts — encontrados: {len(encontrados)}')
                    if progress_callback:
                        progress_callback(int(analisados*100/len(candidatos)), f'Analisando hosts ({analisados}/{len(candidatos)}) — encontrados: {len(encontrados)}')
        encontrados.sort(key=lambda x: tuple(map(int,x['IP'].split('.'))))
        ips_disponiveis=[]
        for ip in candidatos:
            resultado=resultados_por_ip.get(ip)
            if not isinstance(resultado,dict):
                continue
            try:
                endereco=ipaddress.ip_address(ip)
            except ValueError:
                continue
            if (
                endereco not in rede_varredura or ip in {ip_local,gateway}
                or ip in vizinhos_cache or resultado.get('Cancelado')
                or resultado.get('ErroIndeterminado') or resultado.get('ICMP')
                or resultado.get('TCPEvidencia')
            ):
                continue
            ips_disponiveis.append(ip)
        base['Hosts']=encontrados
        base['InterfaceVarredura']=selecionada
        base['Impressoras']=[{'Nome':x['Nome'],'IP':x['IP'],'MAC':x['MAC'],'Porta':x['Servicos'],'Origem':'Varredura detalhada'} for x in encontrados if x.get('Impressora')]
        base['DisponibilidadeIPs']={
            'Concluida':True,'Rede':str(rede_varredura),'IPv4Local':ip_local,
            'Gateway':gateway,'Candidatos':ips_disponiveis,
        }
        base['ModoColeta']=f"Varredura detalhada IPv4 {rede_varredura} — {selecionada.get('Alias')}"; base['DataAtualizacao']=datetime.now().isoformat(timespec='seconds')
        base['Resumo']={'TotalHosts':len(encontrados),'TotalImpressoras':len(base['Impressoras']),'TotalInterfaces':len(base.get('Interfaces',[])),'AtivosManuais':len(base.get('Empresa',{}).get('ativos_manuais',[])),'IPsProvavelmenteDisponiveis':len(ips_disponiveis)}
        _salvar_inventario_empresa(base)
        somente_tcp=sum(1 for item in encontrados if item.get('Estado')=='Somente TCP')
        duracao=time.monotonic()-inicio
        registrar_log('EMPRESA','IPS_DISPONIVEIS_ANALISADOS',f"Rede: {rede_varredura}; IPs analisados: {analisados}; Candidatos prováveis: {len(ips_disponiveis)}; Vizinhos conhecidos: {len(vizinhos_cache)}")
        registrar_log('EMPRESA','VARREDURA_DETALHADA_REDE',f"Hosts: {len(encontrados)}; Somente TCP: {somente_tcp}; Impressoras detectadas: {len(base['Impressoras'])}; IPs analisados: {analisados}; IPs provavelmente disponíveis: {len(ips_disponiveis)}")
        logger.info('SCAN_DETALHADO_FINALIZADO | ips_analisados=%s | hosts=%s | somente_tcp=%s | ips_disponiveis=%s | duracao_s=%.2f', analisados, len(encontrados), somente_tcp, len(ips_disponiveis), duracao)
        _barra_progresso_operacao(len(candidatos),len(candidatos),'Inventário detalhado salvo')
        return True,encontrados,f"Varredura concluída em {rede_varredura} ({selecionada.get('Alias')}): {analisados} IPs examinados; {len(encontrados)} hosts encontrados; {somente_tcp} hosts somente TCP; {len(base['Impressoras'])} possíveis impressoras; {len(ips_disponiveis)} IPs provavelmente disponíveis."

    @staticmethod
    def obter_ips_provavelmente_disponiveis():
        """Lê a estimativa persistida pela última varredura detalhada concluída.

        Não inicia ping, ARP, TCP nem subprocesso adicional. A confirmação de
        disponibilidade para DHCP/reservas continua sendo responsabilidade do
        administrador no ambiente real.
        """
        try:
            caminho=Path(ARQUIVO_INVENTARIO)
            if not caminho.exists():
                return []
            dados=json.loads(caminho.read_text(encoding='utf-8'))
            disponibilidade=dados.get('DisponibilidadeIPs',{}) if isinstance(dados,dict) else {}
            if not isinstance(disponibilidade,dict) or not disponibilidade.get('Concluida'):
                return []
            candidatos=disponibilidade.get('Candidatos',[])
            if not isinstance(candidatos,list):
                return []
            resultado=[]
            vistos=set()
            for valor in candidatos:
                try:
                    endereco=ipaddress.ip_address(str(valor).strip())
                except ValueError:
                    continue
                if endereco.version!=4 or str(endereco) in vistos:
                    continue
                vistos.add(str(endereco))
                resultado.append({
                    'IP':str(endereco),'Estado':'Provavelmente disponível',
                    'Resumo':'Sem resposta ICMP/TCP observada na varredura.',
                })
            return sorted(resultado,key=lambda item:int(ipaddress.ip_address(item['IP'])))
        except Exception as exc:
            logger.warning('IPS_DISPONIVEIS_LEITURA_FALHOU | erro=%s',exc)
            return []

    @staticmethod
    def abrir_monitoramento_ativo():
        """Monitoramento fluido: coleta em thread e atualiza somente a UI no thread principal."""
        try:
            import tkinter as tk
            from tkinter import ttk
        except Exception as e:
            return False, str(e)
        root = tk.Tk(); root.title('Configurador TI - Monitoramento Ativo'); root.geometry('820x500'); root.minsize(700,430)
        vars = {k: tk.StringVar(value='Carregando...') for k in ('cpu','ram','disco','status')}
        running = {'v': True, 'after_id': None, 'poll_id': None, 'busy': False, 'data': None, 'erro': None}
        ttk.Label(root,text='📡 Monitoramento Ativo',font=('Segoe UI',18,'bold')).pack(pady=(14,4))
        ttk.Label(root,text='Atualização assíncrona — a interface permanece responsiva durante a coleta.').pack()
        box=ttk.Frame(root,padding=16); box.pack(fill='both',expand=True); bars={}
        for key,label in [('cpu','CPU'),('ram','Memória RAM'),('disco','Uso do disco C:')]:
            f=ttk.LabelFrame(box,text=label,padding=10); f.pack(fill='x',pady=6)
            ttk.Label(f,textvariable=vars[key]).pack(anchor='w')
            bars[key]=ttk.Progressbar(f,maximum=100); bars[key].pack(fill='x',pady=5)
        ttk.Label(root,textvariable=vars['status']).pack(pady=8)
        cmd = "$os=Get-CimInstance Win32_OperatingSystem;$c=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor|? Name -eq '_Total'|select -First 1;$v=Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\";[pscustomobject]@{CPU=$c.PercentProcessorTime;RAM=[math]::Round((1-($os.FreePhysicalMemory/$os.TotalVisibleMemorySize))*100,1);DISCO=[math]::Round((1-($v.FreeSpace/$v.Size))*100,1)}|ConvertTo-Json -Compress"
        def worker():
            try:
                r=executar_powershell(cmd,timeout=12)
                if r.returncode: raise RuntimeError(r.stderr.strip() or r.stdout.strip() or 'Falha na coleta')
                running['data']=json.loads(r.stdout or '{}'); running['erro']=None
            except Exception as e:
                running['erro']=str(e)
            finally:
                running['busy']=False
        def aplicar():
            if not running['v']: return
            if running['erro']:
                vars['status'].set('Erro na coleta: '+running['erro'])
            elif running['data'] is not None:
                d=running['data']; running['data']=None
                for k,n in [('cpu','CPU'),('ram','RAM'),('disco','DISCO')]:
                    val=max(0,min(100,float(d.get(n,0)))); bars[k]['value']=val
                    nivel='🟢 LEVE' if val<70 else ('🟡 MÉDIO' if val<90 else '🔴 GRAVE')
                    vars[k].set(f'{val:.1f}% — {nivel}')
                vars['status'].set('Atualizado: '+datetime.now().strftime('%H:%M:%S')+' | intervalo: 3 segundos')
            if running['v'] and root.winfo_exists():
                try: running['poll_id']=root.after(150,aplicar)
                except tk.TclError: running['poll_id']=None
        def iniciar_coleta():
            if not running['v']: return
            if not running['busy']:
                running['busy']=True
                vars['status'].set('Coletando dados em segundo plano...')
                threading.Thread(target=worker,daemon=True,name='MonitoramentoTI').start()
            if running['v'] and root.winfo_exists():
                try: running['after_id']=root.after(3000,iniciar_coleta)
                except tk.TclError: running['after_id']=None
        def fechar():
            running['v']=False
            for chave in ('after_id','poll_id'):
                job=running.get(chave)
                if job is not None:
                    try: root.after_cancel(job)
                    except tk.TclError: pass
                    running[chave]=None
            try: root.destroy()
            except tk.TclError: pass
        root.protocol('WM_DELETE_WINDOW',fechar)
        aplicar(); iniciar_coleta(); root.mainloop()
        return True,'OK'

def _barra_progresso_operacao(atual, total, texto, largura=32):
    """Barra simples para operações de rede longas."""
    total=max(int(total or 1),1); atual=min(max(int(atual),0),total)
    pct=int(atual*100/total); cheio=int(largura*pct/100)
    barra="█"*cheio+"░"*(largura-cheio)
    print(f"\r📊 [{barra}] {pct:3d}% - {texto:<35}", end="", flush=True)
    if atual>=total: print()

def _imprimir_tabela_inventario(itens):
    print("\n" + "─"*112)
    print(f"{'TIPO':<18} {'NOME / HOST':<28} {'IP':<16} {'MAC':<18} {'SERVIÇOS / DETALHES':<62}")
    print("─"*150)
    for x in itens:
        print(f"{str(x.get('Tipo','Host'))[:18]:<18} {str(x.get('Nome','Não identificado'))[:28]:<28} {str(x.get('IP','—'))[:16]:<16} {str(x.get('MAC','—'))[:18]:<18} {str(x.get('Servicos') or x.get('Detalhes','—'))[:62]:<62}")
    print("─"*150)


def sub_menu_empresa():
    while True:
        limpar_tela(); p=ModuloEmpresa.carregar_perfil()
        print(f"{Cores.CIANO}{'═'*60}{Cores.RESET}\n{Cores.CIANO}{Cores.NEGRITO}{'PERFIL DA EMPRESA & INVENTÁRIO':^60}{Cores.RESET}\n{Cores.CIANO}{'═'*60}{Cores.RESET}")
        print(f"Empresa: {p.get('empresa')} | Unidade: {p.get('unidade')}")
        print(f"\n 1 - ✏️  {Cores.AMARELO}Configurar perfil{Cores.RESET}")
        print(f" 2 - 🌐 {Cores.CIANO}Atualizar inventário passivo{Cores.RESET}")
        print(f" 3 - 📡 {Cores.VERDE}Descobrir hosts ativos na sub-rede atual{Cores.RESET}")
        print(f" 4 - ➕ {Cores.AZUL_CLARO}Cadastrar ativo manual{Cores.RESET}")
        print(f" 5 - 📊 {Cores.AZUL}Resumo{Cores.RESET}")
        print(f" 6 - 🔎 {Cores.MAGENTA}Varredura detalhada de dispositivos e impressoras{Cores.RESET}")
        print(f" 0 - ↩️  {Cores.VERMELHO}Voltar{Cores.RESET}")
        op=input('\nEscolha: ').strip()
        if op=='0': return
        if op=='1':
            p['empresa']=input('Empresa: ').strip() or p.get('empresa'); p['unidade']=input('Unidade/filial: ').strip() or p.get('unidade'); t=input('Técnicos (vírgula): ').strip(); p['tecnicos']=[x.strip() for x in t.split(',') if x.strip()] if t else p.get('tecnicos',[]); p['observacoes']=input('Observações: ').strip() or p.get('observacoes',''); ModuloEmpresa.salvar_perfil(p); print('✅ Perfil salvo.'); input('Enter...')
        elif op=='2': ModuloEmpresa.exibir_inventario_rede(); input('Enter...')
        elif op=='3':
            print('⚠️ A descoberta usa ping limitado a até 253 endereços da sub-rede /24 atual.')
            if confirmar_acao('Iniciar descoberta limitada?'):
                try:
                    ok_base,base,msg_base=ModuloEmpresa.coletar_inventario_rede()
                    if not ok_base: raise RuntimeError(msg_base)
                    avaliacao=ModuloEmpresa._avaliar_interfaces_varredura(base.get('Interfaces',[]))
                    ModuloEmpresa._registrar_avaliacao_interfaces_varredura(avaliacao)
                    selecionada=avaliacao.get('Selecionada')
                    if not selecionada: raise RuntimeError('Não foi encontrada interface IPv4 ativa adequada para a descoberta /24.')
                    ip_local=selecionada['IPv4']
                    rede=ipaddress.ip_network(selecionada['Rede'],strict=False)
                    prefixo='.'.join(str(rede.network_address).split('.')[:3]); encontrados=[]
                    def testar(ip):
                        try:
                            r=subprocess.run(['ping','-n','1','-w','350',ip],capture_output=True,text=False,timeout=2)
                            if r.returncode==0:
                                try: nome=socket.gethostbyaddr(ip)[0]
                                except Exception: nome=''
                                return {'IP':ip,'MAC':'Não identificado','Interface':'Descoberta ICMP','Estado':'Reachable','Nome':nome}
                        except Exception: pass
                        return None
                    candidatos=[f'{prefixo}.{i}' for i in range(1,255) if f'{prefixo}.{i}'!=ip_local]
                    print(f"\n🔎 Descobrindo hosts em {rede} ({selecionada.get('Alias')})...")
                    total_hosts=len(candidatos); _barra_progresso_operacao(0,total_hosts,'Preparando varredura')
                    with ThreadPoolExecutor(max_workers=24) as ex:
                        for idx,item in enumerate(ex.map(testar,candidatos),1):
                            if item: encontrados.append(item)
                            if idx==total_hosts or idx%3==0:
                                _barra_progresso_operacao(idx,total_hosts,f'Verificando hosts — encontrados: {len(encontrados)}')
                    _barra_progresso_operacao(total_hosts,total_hosts,'Salvando dispositivos encontrados')
                    existentes={str(x.get('IP')) for x in base.get('Hosts',[])}
                    base['Hosts'].extend(x for x in encontrados if x['IP'] not in existentes)
                    base['Resumo']={'TotalHosts':len(base.get('Hosts',[])),'TotalImpressoras':len(base.get('Impressoras',[])),'TotalInterfaces':len(base.get('Interfaces',[])),'AtivosManuais':len(base.get('Empresa',{}).get('ativos_manuais',[]))}
                    base['ModoColeta']=f"Descoberta ICMP limitada {rede} — {selecionada.get('Alias')}"; base['DataAtualizacao']=datetime.now().isoformat(timespec='seconds')
                    _salvar_inventario_empresa(base)
                    registrar_log('EMPRESA','DESCOBRIR_HOSTS',f"Rede: {rede}; Alias: {selecionada.get('Alias')}; Hosts ativos encontrados: {len(encontrados)}")
                    print(f'✅ Descoberta concluída. {len(encontrados)} hosts responderam.')
                    _imprimir_tabela_inventario([{'Tipo':'Host ativo','Nome':x.get('Nome') or 'Não identificado','IP':x.get('IP'),'MAC':x.get('MAC'),'Detalhes':x.get('Estado')} for x in encontrados])
                except Exception as e: print(f'❌ Erro na descoberta: {e}')
            input('Enter...')
        elif op=='6':
            print('🔎 A varredura detalhada identifica hosts ativos, hostname quando disponível, MAC via ARP e serviços TCP comuns.\n🖨️ Dispositivos com indícios de IPP/LPR/RAW-PRINT ou nome relacionado a impressão são marcados como possíveis impressoras.\n⚠️ Para manter o uso seguro e previsível, a descoberta é limitada à sub-rede IPv4 /24 atual.')
            if confirmar_acao('Iniciar varredura detalhada?'):
                try:
                    ok,encontrados,msg=ModuloEmpresa.varredura_completa_rede()
                    if ok:
                        print(f'\n{Cores.VERDE}✅ {msg}{Cores.RESET}')
                        _imprimir_tabela_inventario(encontrados)
                    else: print(f'\n{Cores.VERMELHO}❌ {msg}{Cores.RESET}')
                except Exception as e:
                    logger.exception('Erro na varredura detalhada'); print(f'❌ Erro: {e}')
            input('Enter...')
        elif op=='4':
            ativo={'nome':input('Nome: ').strip(),'tipo':input('Tipo (Servidor/Switch/Firewall/Antena/etc.): ').strip() or 'Outro','ip':input('IP/Host: ').strip(),'descricao':input('Descrição: ').strip()}
            p.setdefault('ativos_manuais',[]).append(ativo); ModuloEmpresa.salvar_perfil(p); print('✅ Ativo cadastrado.'); input('Enter...')
        elif op=='5':
            try:
                d=json.loads(Path(ARQUIVO_INVENTARIO).read_text(encoding='utf-8')); r=d.get('Resumo',{})
                print(f"Hosts: {r.get('TotalHosts',len(d.get('Hosts',[])))} | Impressoras: {r.get('TotalImpressoras',len(d.get('Impressoras',[])))} | Interfaces: {r.get('TotalInterfaces',len(d.get('Interfaces',[])))}")
                print(f"Ativos manuais: {len(p.get('ativos_manuais',[]))} | Coleta: {d.get('DataAtualizacao',d.get('Data','N/A'))}")
                itens=[]
                for h in d.get('Hosts',[]): itens.append({'Tipo':'Host / Dispositivo','Nome':h.get('Nome') or 'Não identificado','IP':h.get('IP'),'MAC':h.get('MAC'),'Detalhes':h.get('Estado') or h.get('Interface')})
                for x in d.get('Impressoras',[]): itens.append({'Tipo':'Impressora','Nome':x.get('Nome'),'IP':x.get('IP') or '—','MAC':'—','Detalhes':x.get('Porta')})
                for a in p.get('ativos_manuais',[]): itens.append({'Tipo':a.get('tipo') or 'Ativo','Nome':a.get('nome'),'IP':a.get('ip'),'MAC':'—','Detalhes':a.get('descricao')})
                _imprimir_tabela_inventario(itens)
            except Exception: print('Nenhum inventário salvo ainda.')
            input('Enter...')


# ==========================================
# CENTRALIZAÇÃO, RELATÓRIOS DIÁRIOS E E-MAIL
# ==========================================
class ModuloCentralizacao:
    """Centralização leve sem servidor obrigatório.

    As máquinas gravam um snapshot JSON em uma pasta compartilhada (ex.: \\SERVIDOR\\TI\\Coletas).
    Um técnico pode abrir este mesmo configurador em qualquer máquina com acesso à pasta e gerar
    um relatório consolidado. O envio por e-mail usa SMTP configurado pelo administrador.
    """

    @staticmethod
    def alternar_modo_central(cfg):
        """Ativa/desativa esta instalação como 'Central' (única responsável por
        guardar a senha de e-mail e enviar os relatórios consolidados).

        Máquinas 'Cliente' (padrão) só coletam e gravam na pasta compartilhada —
        nunca guardam segredo nenhum, e por isso não têm o que configurar aqui.
        """
        if cfg.get('modo_central'):
            if confirmar_acao("Esta é a instalação CENTRAL. Desativar e apagar a senha de e-mail salva aqui?", False):
                cfg['modo_central'] = False
                cfg['email'] = ModuloCentralizacao._padrao()['email']
                ModuloCentralizacao.salvar_config(cfg)
                print(f"{Cores.VERDE}✅ Modo Central desativado. Senha de e-mail removida desta máquina.{Cores.RESET}")
            return cfg
        print(f"\n{Cores.AMARELO}⚠️  Ativar o modo Central faz ESTA máquina guardar a senha de e-mail{Cores.RESET}")
        print(f"{Cores.AMARELO}   (criptografada com DPAPI) e ser responsável por enviar os relatórios{Cores.RESET}")
        print(f"{Cores.AMARELO}   consolidados de todas as coletas. Use isso em UMA única máquina de TI,{Cores.RESET}")
        print(f"{Cores.AMARELO}   nunca em cada máquina de usuário final que for configurada.{Cores.RESET}")
        if confirmar_acao("Ativar modo Central nesta instalação?", False):
            cfg['modo_central'] = True
            ModuloCentralizacao.salvar_config(cfg)
            print(f"{Cores.VERDE}✅ Esta instalação agora é a Central.{Cores.RESET}")
        return cfg

    @staticmethod
    def _padrao():
        return {
            'empresa': '', 'unidade': '', 'pasta_central': str(Path(PASTA_COLETAS).resolve()),
            'modo_central': False,  # v4.11: por padrão a instalação é "cliente" (não guarda senha de e-mail)
            'email': {'ativo': False, 'smtp': '', 'porta': 587, 'usuario': '', 'senha': '',
                      'remetente': '', 'destinatarios': [], 'ssl': False},
            'agendamento': {'ativo': False, 'horario': '18:00'}
        }

    @staticmethod
    def carregar_config():
        d = ModuloCentralizacao._padrao()
        salvo = {}
        try:
            if Path(ARQUIVO_CENTRAL).exists():
                salvo=json.loads(Path(ARQUIVO_CENTRAL).read_text(encoding='utf-8'))
                if not isinstance(salvo,dict):
                    raise ValueError('A configuração central deve ser um objeto JSON.')
                for k,v in salvo.items():
                    if isinstance(v,dict) and isinstance(d.get(k),dict): d[k].update(v)
                    else: d[k]=v
        except Exception as e: logger.warning('Configuração central inválida: %s', e)
        # Cliente nunca carrega nem utiliza segredo legado. O arquivo local só
        # é saneado quando for salvo novamente, evitando escrita colateral em
        # uma operação de simples leitura.
        if not d.get('modo_central'):
            email_salvo=salvo.get('email',{}) if isinstance(salvo,dict) else {}
            if isinstance(email_salvo,dict) and (email_salvo.get('ativo') or email_salvo.get('senha')):
                logger.info('EMAIL_LEGADO_IGNORADO | modo=Cliente | segredo_nao_carregado=true')
            d['email']=ModuloCentralizacao._padrao()['email']
        elif d.get('email',{}).get('senha'):
            # Na Central, a senha DPAPI é decifrada somente em memória.
            d['email']['senha'] = descriptografar_dpapi(d['email']['senha'])
        return d

    @staticmethod
    def salvar_config(d):
        if not isinstance(d,dict):
            raise ValueError('Configuração central inválida.')
        # Nunca grava a senha em texto puro. Cliente também não persiste
        # parâmetros SMTP, mesmo que uma configuração antiga ainda os possua.
        d_para_salvar = json.loads(json.dumps(d, default=str))
        if not d_para_salvar.get('modo_central'):
            d_para_salvar['email']=ModuloCentralizacao._padrao()['email']
        else:
            senha=d_para_salvar.get('email',{}).get('senha','')
            if senha and not str(senha).startswith(_PREFIXO_DPAPI):
                d_para_salvar['email']['senha'] = criptografar_dpapi(str(senha))
        Path(ARQUIVO_CENTRAL).write_text(json.dumps(d_para_salvar,ensure_ascii=False,indent=2),encoding='utf-8')
        restringir_acl_arquivo(ARQUIVO_CENTRAL)
        return True

    @staticmethod
    def _normalizar_pasta(caminho, criar=False):
        """Resolve a pasta configurada sem criar diretório durante leitura."""
        caminho=(caminho or '').strip()
        if not caminho: caminho=str(Path(PASTA_COLETAS).resolve())
        pasta=Path(os.path.expandvars(os.path.expanduser(caminho)))
        if criar:
            pasta.mkdir(parents=True,exist_ok=True)
        return pasta

    @staticmethod
    def _normalizar_snapshot(dados, arquivo=None):
        """Converte schema 1 e variantes legadas para um contrato de leitura."""
        if not isinstance(dados,dict):
            raise ValueError('Snapshot não é um objeto JSON.')

        bruto=dict(dados)
        maquina=str(
            bruto.get('maquina') or bruto.get('Computador')
            or bruto.get('computer') or bruto.get('HostName') or ''
        ).strip()
        if not maquina:
            raise ValueError('Snapshot sem identificação da máquina.')

        coletado=bruto.get('coletado_em') or bruto.get('Data') or bruto.get('data') or ''
        texto_coleta=str(coletado).strip()
        instante=None
        if texto_coleta:
            candidato=texto_coleta.replace('Z','+00:00')
            try:
                instante=datetime.fromisoformat(candidato)
            except ValueError:
                for formato in ('%d/%m/%Y %H:%M:%S','%d/%m/%Y','%Y-%m-%d %H:%M:%S','%Y-%m-%d'):
                    try:
                        instante=datetime.strptime(texto_coleta,formato)
                        break
                    except ValueError:
                        continue
        data=str(bruto.get('data') or '').strip()
        if instante is not None:
            coletado_normalizado=instante.isoformat(timespec='seconds')
            data_normalizada=instante.date().isoformat()
        else:
            coletado_normalizado=texto_coleta
            data_normalizada=data[:10] if re.fullmatch(r'\d{4}-\d{2}-\d{2}.*',data) else ''
        if not data_normalizada and arquivo:
            encontrado=re.match(r'(\d{4}-\d{2}-\d{2})',Path(arquivo).name)
            if encontrado:
                data_normalizada=encontrado.group(1)

        rede=bruto.get('rede')
        if rede is None:
            rede=bruto.get('Rede') or []
        if isinstance(rede,dict):
            rede=[rede]
        if not isinstance(rede,list):
            rede=[]
        ipv4=str(bruto.get('IP') or bruto.get('ip') or '').strip()
        if not ipv4:
            for adaptador in rede:
                if not isinstance(adaptador,dict):
                    continue
                candidato=str(
                    adaptador.get('ip') or adaptador.get('IPv4')
                    or adaptador.get('IP') or ''
                ).split(',')[0].strip()
                try:
                    endereco=ipaddress.ip_address(candidato)
                    if endereco.version==4 and not endereco.is_loopback and not endereco.is_link_local:
                        ipv4=candidato
                        break
                except ValueError:
                    continue

        normalizado=dict(bruto)
        try:
            schema=int(bruto.get('schema',0) or 0)
        except (TypeError,ValueError):
            schema=0
        normalizado.update({
            'schema':schema,
            'data':data_normalizada,
            'coletado_em':coletado_normalizado or data_normalizada,
            'maquina':maquina,
            'usuario':str(bruto.get('usuario') or bruto.get('Usuario') or bruto.get('user') or 'N/A'),
            'rede':rede,
            'ipv4_principal':ipv4 or '—',
            'sistema':bruto.get('sistema') if isinstance(bruto.get('sistema'),dict) else {},
            'hardware':bruto.get('hardware') if isinstance(bruto.get('hardware'),dict) else {},
            'empresa':bruto.get('empresa') if isinstance(bruto.get('empresa'),dict) else {},
            'inventario':bruto.get('inventario') if isinstance(bruto.get('inventario'),dict) else {},
            'acoes':bruto.get('acoes') if isinstance(bruto.get('acoes'),list) else [],
        })
        if arquivo:
            normalizado['_arquivo']=str(arquivo)
        return normalizado

    @staticmethod
    def _coletas_mais_recentes(coletas, data=None):
        ultimas={}
        for coleta in coletas or []:
            if not isinstance(coleta,dict):
                continue
            if data and coleta.get('data')!=data:
                continue
            maquina=str(coleta.get('maquina') or '').strip()
            if not maquina:
                continue
            chave=maquina.casefold()
            anterior=ultimas.get(chave)
            if anterior is None or str(coleta.get('coletado_em') or '')>str(anterior.get('coletado_em') or ''):
                ultimas[chave]=coleta
        return sorted(ultimas.values(),key=lambda item:str(item.get('maquina') or '').casefold())

    @staticmethod
    def coletar_snapshot():
        _barra_progresso_operacao(1,6,'Coletando identificação da máquina')
        info=ModuloSistema.obter_informacoes_sistema() or {}
        _barra_progresso_operacao(2,6,'Coletando hardware')
        hw=ModuloSistema.obter_hardware_detalhado() or {}
        _barra_progresso_operacao(3,6,'Coletando rede')
        try: rede=[asdict(a) for a in (ModuloRede.listar_adaptadores_detalhados() or [])]
        except Exception: rede=[]
        _barra_progresso_operacao(4,6,'Lendo inventário e perfil')
        try: perfil=ModuloEmpresa.carregar_perfil() or {}
        except Exception: perfil={}
        try: inv=json.loads(Path(ARQUIVO_INVENTARIO).read_text(encoding='utf-8')) if Path(ARQUIVO_INVENTARIO).exists() else {}
        except Exception: inv={}
        _barra_progresso_operacao(5,6,'Consolidando histórico do atendimento')
        acoes=[]
        for x in _historico_operacoes_sessao:
            if x.get('acao') not in {'GERAR_RELATORIO_COMPLETO','INICIALIZACAO','LIMPEZA_ENCERRAMENTO'}: acoes.append(x)
        _barra_progresso_operacao(6,6,'Finalizando coleta')
        return {
            'schema': 1, 'coletado_em': datetime.now().isoformat(timespec='seconds'),
            'data': datetime.now().strftime('%Y-%m-%d'),
            'maquina': info.get('HostName') or socket.gethostname(),
            'usuario': os.environ.get('USERNAME','N/A'), 'sistema': info, 'hardware': hw,
            'rede': rede, 'empresa': perfil, 'inventario': inv, 'acoes': acoes,
        }

    @staticmethod
    def salvar_snapshot():
        cfg=ModuloCentralizacao.carregar_config(); pasta=ModuloCentralizacao._normalizar_pasta(cfg.get('pasta_central'),criar=True)
        if not pasta.is_dir():
            raise RuntimeError(f'A pasta central não está disponível: {pasta}')
        snap=ModuloCentralizacao.coletar_snapshot(); nome=re.sub(r'[^A-Za-z0-9_.-]','_',str(snap['maquina']))
        instante=datetime.now().strftime('%H%M%S_%f')
        arquivo=pasta/f'{snap["data"]}_{nome}_{instante}.json'
        temporario=None
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',encoding='utf-8',dir=str(pasta),
                prefix=f'.{nome}_',suffix='.tmp',delete=False,
            ) as fluxo:
                temporario=Path(fluxo.name)
                json.dump(snap,fluxo,ensure_ascii=False,indent=2,default=str)
                fluxo.flush()
                os.fsync(fluxo.fileno())
            os.replace(str(temporario),str(arquivo))
            temporario=None
        finally:
            if temporario is not None:
                try: temporario.unlink(missing_ok=True)
                except OSError: pass
        registrar_log('CENTRAL','COLETA_DIARIA',str(arquivo))
        return arquivo,snap

    @staticmethod
    def carregar_coletas():
        cfg=ModuloCentralizacao.carregar_config(); pasta=ModuloCentralizacao._normalizar_pasta(cfg.get('pasta_central'))
        if not pasta.exists() or not pasta.is_dir():
            logger.warning('PASTA_CENTRAL_INDISPONIVEL | caminho=%s',pasta)
            return []
        itens=[]
        for arq in sorted(pasta.glob('*.json'), reverse=True):
            try:
                d=json.loads(arq.read_text(encoding='utf-8'))
                itens.append(ModuloCentralizacao._normalizar_snapshot(d,arq))
            except Exception as exc:
                logger.warning('SNAPSHOT_CENTRAL_IGNORADO | arquivo=%s | erro=%s',arq,type(exc).__name__)
        return itens

    @staticmethod
    def listar_maquinas_hoje():
        hoje=datetime.now().strftime('%Y-%m-%d')
        return ModuloCentralizacao._coletas_mais_recentes(
            ModuloCentralizacao.carregar_coletas(),hoje
        )

    @staticmethod
    def listar_relatorios_consolidados():
        cfg=ModuloCentralizacao.carregar_config()
        pasta=ModuloCentralizacao._normalizar_pasta(cfg.get('pasta_central'))
        if not pasta.exists() or not pasta.is_dir():
            return []
        return sorted(
            pasta.glob('relatorio_central_*.html'),
            key=lambda caminho:caminho.stat().st_mtime if caminho.exists() else 0,
            reverse=True,
        )

    @staticmethod
    def obter_status_centralizacao():
        cfg=ModuloCentralizacao.carregar_config()
        pasta=ModuloCentralizacao._normalizar_pasta(cfg.get('pasta_central'))
        acessivel=pasta.exists() and pasta.is_dir()
        coletas=ModuloCentralizacao.carregar_coletas() if acessivel else []
        relatorios=ModuloCentralizacao.listar_relatorios_consolidados() if acessivel else []
        tarefa=ModuloCentralizacao.consultar_agendamento()
        ultima_coleta=max(
            coletas,
            key=lambda item:str(item.get('coletado_em') or ''),
            default=None,
        )
        return {
            'modo':'Central' if cfg.get('modo_central') else 'Cliente',
            'pasta':str(pasta),
            'pasta_acessivel':acessivel,
            'pasta_gravavel':bool(acessivel and os.access(str(pasta),os.W_OK)),
            'ultimo_snapshot':ultima_coleta.get('_arquivo') if ultima_coleta else '',
            'ultimo_relatorio':str(relatorios[0]) if relatorios else '',
            'agendamento':tarefa,
        }

    @staticmethod
    def consultar_agendamento():
        cfg=ModuloCentralizacao.carregar_config()
        horario=str(cfg.get('agendamento',{}).get('horario') or '—')
        if os.name!='nt':
            return {'consultavel':False,'existe':None,'horario':horario,'mensagem':'Consulta disponível somente no Windows.'}
        codigo,mensagem=_executar_schtasks(['/Query','/TN',TAREFA_COLETA_DIARIA,'/FO','LIST','/V'])
        return {
            'consultavel':True,
            'existe':codigo==0,
            'horario':horario,
            'mensagem':mensagem or ('Tarefa encontrada.' if codigo==0 else 'Tarefa não encontrada.'),
        }

    @staticmethod
    def gerar_relatorio_consolidado():
        coletas=ModuloCentralizacao.carregar_coletas()
        hoje=datetime.now().strftime('%Y-%m-%d')
        dados=ModuloCentralizacao._coletas_mais_recentes(coletas,hoje)
        cfg=ModuloCentralizacao.carregar_config()
        pasta=ModuloCentralizacao._normalizar_pasta(cfg.get('pasta_central'),criar=True)
        linhas=''
        total_acoes=0
        for c in sorted(dados,key=lambda x:x.get('maquina','')):
            sis=c.get('sistema') or {}; hw=c.get('hardware') or {}; acoes=c.get('acoes') or []; total_acoes+=len(acoes)
            cpu=hw.get('Processador') or sis.get('Processador') or 'N/A'
            ram=sum(float(x.get('CapacidadeGB') or 0) for x in _normalizar_lista(hw.get('RAM')))
            linhas += '<tr>' + ''.join(f'<td>{_html_seguro(v)}</td>' for v in [c.get('maquina'),c.get('usuario'),c.get('coletado_em'),cpu,f'{ram:.1f} GB' if ram else 'N/A',len(acoes)]) + '</tr>'
        if not linhas: linhas='<tr><td colspan="6">Nenhuma coleta encontrada para hoje.</td></tr>'
        detalhes=''
        for c in sorted(dados,key=lambda x:x.get('maquina','')):
            detalhes+=f'<h2>{_html_seguro(c.get("maquina"))}</h2><p><b>Coleta:</b> {_html_seguro(c.get("coletado_em"))}</p><ul>'
            for a in c.get('acoes') or []:
                detalhes+=f'<li><b>{_html_seguro(formatar_acao_relatorio(a.get("acao","")))}</b> — {_html_seguro(a.get("detalhes",""))}</li>'
            detalhes+='</ul>'
        arquivo=pasta/f'relatorio_central_{hoje}_{datetime.now().strftime("%H%M%S_%f")}.html'
        html_out=f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Relatório Central TI</title><style>@page{{size:A4;margin:15mm}}body{{font-family:Segoe UI,Arial;color:#222}}h1{{color:#145da0}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #ccc;padding:8px;text-align:left}}th{{background:#145da0;color:white}}.card{{border:1px solid #ddd;padding:12px;margin:10px 0;border-radius:6px}}@media print{{body{{font-size:10pt}}h2{{break-after:avoid}}table{{break-inside:avoid}}}}</style></head><body><h1>Relatório Centralizado de TI</h1><div class="card"><b>Empresa:</b> {_html_seguro(cfg.get('empresa') or 'Não configurada')}<br><b>Unidade:</b> {_html_seguro(cfg.get('unidade') or 'Não configurada')}<br><b>Data:</b> {hoje}<br><b>Pasta central:</b> {_html_seguro(pasta)}<br><b>Máquinas monitoradas:</b> {len(dados)}<br><b>Ações registradas:</b> {total_acoes}</div><table><tr><th>Máquina</th><th>Usuário</th><th>Última coleta</th><th>CPU</th><th>RAM</th><th>Ações</th></tr>{linhas}</table>{detalhes}</body></html>"""
        arquivo.write_text(html_out,encoding='utf-8')
        registrar_log('CENTRAL','RELATORIO_CONSOLIDADO',str(arquivo))
        return arquivo,len(dados)

    @staticmethod
    def enviar_email(arquivo):
        cfg=ModuloCentralizacao.carregar_config(); e=cfg.get('email',{})
        if not cfg.get('modo_central'):
            return False,'Envio bloqueado: esta instalação está em modo Cliente.'
        if not e.get('ativo'): return False,'E-mail automático não está configurado.'
        if not e.get('smtp') or not e.get('destinatarios'): return False,'Preencha SMTP e destinatários.'
        pasta=ModuloCentralizacao._normalizar_pasta(cfg.get('pasta_central'))
        caminho=Path(arquivo)
        try:
            if caminho.suffix.casefold()!='.html' or caminho.resolve(strict=False).parent!=pasta.resolve(strict=False):
                return False,'Somente relatório consolidado da pasta central pode ser enviado.'
        except (OSError,RuntimeError):
            return False,'Caminho do relatório consolidado inválido.'
        if not caminho.is_file(): return False,'Relatório consolidado não encontrado.'
        msg=EmailMessage(); msg['Subject']=f'Relatório TI - {datetime.now().strftime("%d/%m/%Y")}'; msg['From']=e.get('remetente') or e.get('usuario'); msg['To']=', '.join(e.get('destinatarios',[])); msg.set_content('Relatório automático de TI em anexo.')
        data=caminho.read_bytes(); msg.add_attachment(data,maintype='text',subtype='html',filename=caminho.name)
        ctx=ssl.create_default_context(); porta=int(e.get('porta') or 587)
        try:
            if e.get('ssl'):
                with smtplib.SMTP_SSL(e['smtp'],porta,context=ctx,timeout=30) as s:
                    if e.get('usuario'): s.login(e['usuario'],e.get('senha',''))
                    s.send_message(msg)
            else:
                with smtplib.SMTP(e['smtp'],porta,timeout=30) as s:
                    s.ehlo();
                    if s.has_extn('starttls'): s.starttls(context=ctx); s.ehlo()
                    if e.get('usuario'): s.login(e['usuario'],e.get('senha',''))
                    s.send_message(msg)
            registrar_log('CENTRAL','EMAIL_RELATORIO',str(arquivo)); return True,'E-mail enviado com sucesso.'
        except Exception as ex:
            logger.exception('Erro no envio de e-mail'); return False,str(ex)

    @staticmethod
    def enviar_ultimo_relatorio():
        arquivos=ModuloCentralizacao.listar_relatorios_consolidados()
        if not arquivos:
            return False,'Nenhum relatório HTML consolidado encontrado na pasta central.'
        return ModuloCentralizacao.enviar_email(arquivos[0])

    @staticmethod
    def criar_agendamento(horario):
        if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d',horario or ''):
            return False,'Horário inválido. Use HH:MM.'
        comando,destino,args_log=_alvo_modo_agendado('--coleta-diaria')
        codigo,mensagem=_executar_schtasks([
            '/Create','/TN',TAREFA_COLETA_DIARIA,'/TR',comando,
            '/SC','DAILY','/ST',horario,'/F',
        ])
        registrar_evento_instancia(
            "AGENDAMENTO_INSTANCIA_CONFIGURADO",
            motivo=f"tarefa={TAREFA_COLETA_DIARIA};modo=--coleta-diaria;codigo={codigo}",
            executavel_destino=destino,
            argumentos_destino=args_log,
        )
        registrar_log('AUTOMACAO','AGENDAMENTO_CONFIGURADO',f'tarefa={TAREFA_COLETA_DIARIA};horario={horario};modo=--coleta-diaria;codigo={codigo}')
        cfg=ModuloCentralizacao.carregar_config()
        cfg.setdefault('agendamento',{})['horario']=horario
        cfg['agendamento']['ativo']=codigo==0
        cfg['agendamento']['tarefa']=TAREFA_COLETA_DIARIA
        try:
            ModuloCentralizacao.salvar_config(cfg)
        except Exception as exc:
            logger.exception('Tarefa configurada, mas o status local não pôde ser salvo')
            return False,f'Tarefa retornou código {codigo}, mas a configuração local falhou: {exc}'
        return codigo==0,mensagem or ('Agendamento configurado.' if codigo==0 else f'schtasks retornou código {codigo}.')


def executar_coleta_diaria_automatica():
    try:
        arquivo,_=ModuloCentralizacao.salvar_snapshot()
        cfg=ModuloCentralizacao.carregar_config()
        if not cfg.get('modo_central'):
            registrar_log('CENTRAL','EMAIL_AUTOMATICO_IGNORADO','modo=Cliente; coleta preservada')
            return True,str(arquivo)
        if cfg.get('email',{}).get('ativo'):
            relatorio,quantidade=ModuloCentralizacao.gerar_relatorio_consolidado()
            ok_email,msg_email=ModuloCentralizacao.enviar_email(relatorio)
            if not ok_email:
                return False,f'Snapshot salvo em {arquivo}; falha no envio consolidado: {msg_email}'
            return True,f'{arquivo}; relatório={relatorio}; máquinas={quantidade}'
        return True,str(arquivo)
    except Exception as e:
        logger.exception('Falha na coleta diária automática'); return False,str(e)


def executar_manutencao_programada_automatica():
    """Executa somente limpeza temporária e Defender, sem interação/UAC."""
    if not verificar_admin():
        return False,(
            'A manutenção programada requer privilégios administrativos. '
            'Recrie a tarefa com nível mais alto.'
        )
    try:
        _,mensagem_limpeza,removidos=ModuloSistema.limpar_arquivos_temporarios()
    except Exception as exc:
        logger.exception('Falha na limpeza temporária programada')
        return False,f'Limpeza de temporários falhou: {exc}'
    ok_defender,mensagem_defender=ModuloImplantacao.seguranca(
        True,permitir_elevacao=False
    )
    if not ok_defender:
        return False,(
            f'Limpeza concluída ({removidos} arquivo(s)); '
            f'Defender falhou: {mensagem_defender}'
        )
    return True,f'{mensagem_limpeza} Defender: {mensagem_defender}'


def executar_modo_saude_armazenamento_elevada(argumentos) -> int:
    """Executa exclusivamente a leitura Storage autorizada pela GUI normal."""
    argumentos = list(argumentos or [])
    formato_valido = (
        len(argumentos) == 5
        and argumentos[0] == MODO_SAUDE_ARMAZENAMENTO_ELEVADA
        and argumentos[1] == ARG_RESULTADO_SAUDE_ELEVADA
        and argumentos[3] == ARG_NONCE_SAUDE_ELEVADA
    )
    if not formato_valido:
        registrar_log(
            "HEADLESS",
            "MODO_HEADLESS_FALHOU",
            "modo=saude_armazenamento_elevada;tipo=ArgumentoInvalido",
        )
        return 2

    destino = argumentos[2]
    nonce = argumentos[4]
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce or ""):
        registrar_log(
            "HEADLESS",
            "MODO_HEADLESS_FALHOU",
            "modo=saude_armazenamento_elevada;tipo=NonceInvalido",
        )
        return 2

    try:
        _validar_destino_saude_armazenamento_elevada(destino)
    except Exception as exc:
        registrar_log(
            "HEADLESS",
            "MODO_HEADLESS_FALHOU",
            (
                "modo=saude_armazenamento_elevada;tipo=DestinoInvalido;"
                f"erro={type(exc).__name__}"
            ),
        )
        return 2

    if not verificar_admin():
        resultado = {
            "Sucesso": False,
            "Cancelada": False,
            "Mensagem": "O auxiliar não recebeu privilégio administrativo.",
            "Discos": [],
            "TipoFalha": "SemPrivilegioAdministrativo",
        }
    else:
        try:
            resultado = ModuloSistema.obter_saude_armazenamento()
            if not isinstance(resultado, dict):
                raise ValueError("Coleta Storage retornou formato inválido.")
            resultado = dict(resultado)
            resultado["ColetaElevada"] = True
        except Exception as exc:
            logger.exception("Falha no auxiliar elevado de saúde de armazenamento")
            resultado = {
                "Sucesso": False,
                "Cancelada": False,
                "Mensagem": "A leitura nativa elevada falhou; consulte o log.",
                "Discos": [],
                "TipoFalha": type(exc).__name__,
            }

    try:
        _gravar_envelope_saude_armazenamento_elevada(
            destino, nonce, resultado
        )
        return 0
    except Exception as exc:
        registrar_log(
            "HEADLESS",
            "MODO_HEADLESS_FALHOU",
            (
                "modo=saude_armazenamento_elevada;tipo=FalhaEscrita;"
                f"erro={type(exc).__name__}"
            ),
        )
        return 1


def executar_modo_windows_update_elevado(argumentos) -> int:
    """Executa somente o Windows Update allowlisted no processo elevado."""
    argumentos = list(argumentos or [])
    formato_valido = (
        len(argumentos) == 5
        and argumentos[0] == MODO_WINDOWS_UPDATE_ELEVADO
        and argumentos[1] == ARG_RESULTADO_WINDOWS_UPDATE
        and argumentos[3] == ARG_NONCE_WINDOWS_UPDATE
    )
    if not formato_valido:
        registrar_log(
            "HEADLESS", "MODO_HEADLESS_FALHOU",
            "modo=windows_update_elevado;tipo=ArgumentoInvalido",
        )
        return 2
    destino, nonce = argumentos[2], argumentos[4]
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce or ""):
        registrar_log(
            "HEADLESS", "MODO_HEADLESS_FALHOU",
            "modo=windows_update_elevado;tipo=NonceInvalido",
        )
        return 2
    try:
        _validar_destino_windows_update(destino)
    except Exception as exc:
        registrar_log(
            "HEADLESS", "MODO_HEADLESS_FALHOU",
            "modo=windows_update_elevado;tipo=DestinoInvalido;"
            f"erro={type(exc).__name__}",
        )
        return 2

    def progresso(percentual, mensagem):
        _gravar_estado_windows_update(
            destino, nonce, "RUNNING", percentual, mensagem
        )

    registrar_log(
        "SISTEMA", "WINDOWS_UPDATE_HELPER_STAGE",
        "etapa=helper_iniciado;status=ok",
    )
    try:
        if not verificar_admin():
            sucesso, mensagem = False, (
                "O helper do Windows Update não recebeu privilégio administrativo."
            )
        else:
            progresso(3, "Helper elevado iniciado.")
            sucesso, mensagem = ModuloSistema.executar_windows_update(
                progress_callback=progresso
            )
    except Exception as exc:
        logger.exception("Falha no modo elevado do Windows Update")
        sucesso, mensagem = False, (
            "O helper elevado falhou " f"({type(exc).__name__}). Consulte o log."
        )

    resultado = {"Sucesso": bool(sucesso), "Mensagem": str(mensagem)[:16000]}
    try:
        _gravar_estado_windows_update(
            destino, nonce, "COMPLETED", 100 if sucesso else 0,
            "Windows Update concluído." if sucesso else "Windows Update falhou.",
            resultado,
        )
    except Exception as exc:
        registrar_log(
            "HEADLESS", "MODO_HEADLESS_FALHOU",
            "modo=windows_update_elevado;tipo=FalhaEscrita;"
            f"erro={type(exc).__name__}",
        )
        return 1
    registrar_log(
        "SISTEMA", "WINDOWS_UPDATE_HELPER_STAGE",
        f"etapa=helper_finalizado;status={'ok' if sucesso else 'falha'}",
    )
    return 0 if sucesso else 1


def executar_modo_headless(modo):
    """Executa um modo autorizado com log e código de saída confiável."""
    if modo not in MODOS_HEADLESS_AUTORIZADOS:
        registrar_log('HEADLESS','MODO_HEADLESS_FALHOU',f'modo={modo};tipo=ArgumentoInvalido')
        return 2
    if modo in {
        MODO_SAUDE_ARMAZENAMENTO_ELEVADA,
        MODO_WINDOWS_UPDATE_ELEVADO,
    }:
        registrar_log(
            'HEADLESS','MODO_HEADLESS_FALHOU',
            f'modo={modo};tipo=ParametrosAusentes',
        )
        return 2
    detalhe=(
        f'modo={modo};pid={os.getpid()};admin={bool(verificar_admin())};'
        f'frozen={bool(getattr(sys,"frozen",False))}'
    )
    registrar_log('HEADLESS','MODO_HEADLESS_INICIADO',detalhe)
    try:
        if modo=='--coleta-diaria':
            ok,mensagem=executar_coleta_diaria_automatica()
        else:
            ok,mensagem=executar_manutencao_programada_automatica()
    except Exception as exc:
        logger.exception('Falha crítica no modo headless %s',modo)
        registrar_log(
            'HEADLESS','MODO_HEADLESS_FALHOU',
            f'modo={modo};tipo={type(exc).__name__};mensagem={_valor_log_instancia(exc,500)}',
        )
        registrar_instancia_encerrando(f'HEADLESS_FALHOU:{modo}')
        return 1
    evento='MODO_HEADLESS_CONCLUIDO' if ok else 'MODO_HEADLESS_FALHOU'
    registrar_log(
        'HEADLESS',evento,
        f'modo={modo};sucesso={bool(ok)};resultado={_valor_log_instancia(mensagem,800)}',
    )
    registrar_instancia_encerrando(
        f'HEADLESS_CONCLUIDO:{modo}' if ok else f'HEADLESS_FALHOU:{modo}'
    )
    return 0 if ok else 1


def despachar_modo_headless(argumentos=None):
    """Retorna None para GUI/menu normal ou exit code para modo especial."""
    argumentos=list(sys.argv[1:] if argumentos is None else argumentos)
    if MODO_SAUDE_ARMAZENAMENTO_ELEVADA in argumentos:
        if argumentos.count(MODO_SAUDE_ARMAZENAMENTO_ELEVADA) != 1:
            registrar_log(
                "HEADLESS",
                "MODO_HEADLESS_FALHOU",
                "modo=saude_armazenamento_elevada;tipo=ArgumentoDuplicado",
            )
            return 2
        return executar_modo_saude_armazenamento_elevada(argumentos)
    if MODO_WINDOWS_UPDATE_ELEVADO in argumentos:
        if argumentos.count(MODO_WINDOWS_UPDATE_ELEVADO) != 1:
            registrar_log(
                "HEADLESS", "MODO_HEADLESS_FALHOU",
                "modo=windows_update_elevado;tipo=ArgumentoDuplicado",
            )
            return 2
        return executar_modo_windows_update_elevado(argumentos)
    solicitados=[item for item in argumentos if item in MODOS_HEADLESS_AUTORIZADOS]
    if not solicitados:
        return None
    if len(argumentos)!=1 or len(solicitados)!=1:
        registrar_log(
            'HEADLESS','MODO_HEADLESS_FALHOU',
            'tipo=ArgumentoInvalido; combinação de argumentos não autorizada',
        )
        registrar_instancia_encerrando('HEADLESS_ARGUMENTO_INVALIDO')
        return 2
    return executar_modo_headless(solicitados[0])


def sub_menu_centralizacao():
    while True:
        limpar_tela(); cfg=ModuloCentralizacao.carregar_config()
        modo_txt = f"{Cores.VERDE}CENTRAL (guarda senha de e-mail){Cores.RESET}" if cfg.get('modo_central') else f"{Cores.CIANO}CLIENTE (apenas coleta, sem segredo local){Cores.RESET}"
        print(f"{Cores.VERDE}{'═'*60}{Cores.RESET}\n{Cores.NEGRITO}{'CENTRALIZAÇÃO, RELATÓRIOS E E-MAIL':^60}{Cores.RESET}\n{Cores.VERDE}{'═'*60}{Cores.RESET}")
        print(f"Empresa: {cfg.get('empresa') or 'Não configurada'} | Pasta central: {cfg.get('pasta_central')}")
        print(f"Modo desta instalação: {modo_txt}")
        print(f"\n 1 - 🏢 {Cores.CIANO}Configurar empresa e pasta compartilhada{Cores.RESET}")
        print(f" 2 - 💾 {Cores.VERDE}Enviar coleta desta máquina para a central{Cores.RESET}")
        print(f" 3 - 📊 {Cores.AZUL}Gerar relatório consolidado do dia{Cores.RESET}")
        print(f" 4 - 📧 {Cores.MAGENTA}Configurar e-mail automático (somente modo Central){Cores.RESET}")
        print(f" 5 - 📤 {Cores.AZUL_CLARO}Enviar último relatório consolidado por e-mail (somente modo Central){Cores.RESET}")
        print(f" 6 - ⏰ {Cores.VERDE}Agendar coleta diária{Cores.RESET}")
        print(f" 7 - 📋 {Cores.AMARELO}Listar máquinas coletadas hoje{Cores.RESET}")
        print(f" 8 - 🔐 {Cores.MAGENTA}Ativar/Desativar modo Central desta instalação{Cores.RESET}")
        print(f" 0 - ↩️  {Cores.VERMELHO}Voltar{Cores.RESET}")
        op=input('\nEscolha: ').strip()
        if op=='0': return
        if op=='1':
            cfg['empresa']=input(f"Empresa [{cfg.get('empresa','')}]: ").strip() or cfg.get('empresa',''); cfg['unidade']=input(f"Unidade [{cfg.get('unidade','')}]: ").strip() or cfg.get('unidade',''); pasta=input(f"Pasta central [{cfg.get('pasta_central','')}]: ").strip() or cfg.get('pasta_central'); cfg['pasta_central']=pasta
            try: ModuloCentralizacao._normalizar_pasta(pasta); ModuloCentralizacao.salvar_config(cfg); print('✅ Configuração salva.')
            except Exception as e: print(f'❌ Não foi possível acessar a pasta: {e}')
            input('Enter...')
        elif op=='2':
            try: arq,s=ModuloCentralizacao.salvar_snapshot(); print(f'\n✅ Coleta salva: {arq}')
            except Exception as e: print(f'❌ Erro: {e}')
            input('Enter...')
        elif op=='3':
            arq,n=ModuloCentralizacao.gerar_relatorio_consolidado(); print(f'\n✅ Relatório gerado: {arq} | Máquinas: {n}'); input('Enter...')
        elif op=='4':
            if not cfg.get('modo_central'):
                print(f"\n{Cores.AMARELO}⚠️  Esta instalação está em modo Cliente — ela não deve guardar a senha{Cores.RESET}")
                print(f"{Cores.AMARELO}   de e-mail. Configure o e-mail apenas na máquina Central (opção 8).{Cores.RESET}")
                input('Enter...'); continue
            e=cfg.setdefault('email',{}); e['ativo']=input('Ativar e-mail? (s/n): ').strip().lower() in ('s','sim'); e['smtp']=input(f"SMTP [{e.get('smtp','')}]: ").strip() or e.get('smtp',''); e['porta']=int(input(f"Porta [{e.get('porta',587)}]: ").strip() or e.get('porta',587)); e['usuario']=input(f"Usuário [{e.get('usuario','')}]: ").strip() or e.get('usuario',''); senha=input('Senha/app password (Enter mantém a atual): ').strip(); e['senha']=senha or e.get('senha',''); e['remetente']=input(f"Remetente [{e.get('remetente','')}]: ").strip() or e.get('remetente',''); ds=input('Destinatários separados por vírgula: ').strip(); e['destinatarios']=[x.strip() for x in ds.split(',') if x.strip()] if ds else e.get('destinatarios',[]); e['ssl']=input('Usar SSL direto? (s/n): ').strip().lower() in ('s','sim'); ModuloCentralizacao.salvar_config(cfg); print('✅ E-mail configurado.'); input('Enter...')
        elif op=='5':
            if not cfg.get('modo_central'):
                print(f"\n{Cores.AMARELO}⚠️  Esta instalação está em modo Cliente e não tem senha de e-mail configurada.{Cores.RESET}")
                print(f"{Cores.AMARELO}   Gere o relatório aqui (opção 3) e envie a partir da máquina Central.{Cores.RESET}")
                input('Enter...'); continue
            arq,n=ModuloCentralizacao.gerar_relatorio_consolidado(); ok,msg=ModuloCentralizacao.enviar_email(arq); print(('✅ ' if ok else '❌ ')+msg); input('Enter...')
        elif op=='6':
            h=input(f"Horário HH:MM [{cfg.get('agendamento',{}).get('horario','18:00')}]: ").strip() or cfg.get('agendamento',{}).get('horario','18:00')
            if not re.match(r'^(?:[01]\d|2[0-3]):[0-5]\d$',h): print('❌ Horário inválido.')
            else:
                ok,msg=ModuloCentralizacao.criar_agendamento(h); cfg.setdefault('agendamento',{})['horario']=h; cfg['agendamento']['ativo']=ok; ModuloCentralizacao.salvar_config(cfg); print(('✅ ' if ok else '❌ ')+msg)
            input('Enter...')
        elif op=='7':
            hoje=datetime.now().strftime('%Y-%m-%d'); itens=[x for x in ModuloCentralizacao.carregar_coletas() if x.get('data')==hoje]
            print('\n'+'─'*80); print(f"{'MÁQUINA':<25} {'USUÁRIO':<20} {'COLETA':<22}"); print('─'*80)
            for x in itens: print(f"{str(x.get('maquina',''))[:25]:<25} {str(x.get('usuario',''))[:20]:<20} {str(x.get('coletado_em',''))[:22]:<22}")
            print('─'*80+f'\nTotal: {len(itens)} máquina(s).'); input('Enter...')
        elif op=='8':
            ModuloCentralizacao.alternar_modo_central(cfg); input('Enter...')


# ==========================================
# VERIFICAÇÃO DE ADMINISTRADOR
# ==========================================
def verificar_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def solicitar_elevacao():
    """Reexecuta o script como administrador."""
    if not verificar_admin():
        print(f"{Cores.AMARELO}🔄 Solicitando privilégios de administrador...{Cores.RESET}")
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_SOLICITADO",
            motivo="CONSOLE_LEGADO",
            executavel_destino=sys.executable,
            argumentos_destino=list(sys.argv),
        )
        try:
            resultado = executar_relancamento_uac(
                sys.executable,
                " ".join(sys.argv),
                None,
                motivo="CONSOLE_LEGADO",
            )
        except Exception as exc:
            registrar_evento_instancia(
                "RELANCAMENTO_UAC_FALHOU",
                motivo=f"CONSOLE_LEGADO:{type(exc).__name__}",
                executavel_destino=sys.executable,
                argumentos_destino=list(sys.argv),
            )
            try:
                logger.exception("Falha ao solicitar UAC no console legado")
            except Exception:
                pass
            print(f"{Cores.VERMELHO}❌ Não foi possível elevar: {exc}{Cores.RESET}")
            return
        registrar_evento_instancia(
            "RELANCAMENTO_UAC_ACEITO" if resultado > 32 else "RELANCAMENTO_UAC_FALHOU",
            motivo=f"CONSOLE_LEGADO:codigo={resultado}",
            executavel_destino=sys.executable,
            argumentos_destino=list(sys.argv),
        )
        if resultado > 32:
            registrar_instancia_encerrando("RELANCAMENTO_UAC_CONSOLE_LEGADO")
            sys.exit(0)

# ==========================================
# MENU PRINCIPAL
# ==========================================
def menu_principal():
    if not verificar_admin():
        print(f"{Cores.VERMELHO}❌ Este programa requer privilégios de Administrador!{Cores.RESET}")
        print(f"{Cores.AMARELO}🔄 Reiniciando com privilégios elevados...{Cores.RESET}")
        time.sleep(2)
        solicitar_elevacao()
        return
    
    # Criar pastas necessárias
    Path(PASTA_BACKUP).mkdir(exist_ok=True)
    
    while True:
        limpar_tela()
        print(f"{Cores.AZUL_CLARO}{'═' * 60}{Cores.RESET}")
        print(f"{Cores.AZUL_CLARO}{Cores.NEGRITO}{'CONFIGURADOR DE TI':^60}{Cores.RESET}")
        print(f"{Cores.CINZA}{'v3.5 - Monitoramento, Inventário, Centralização e Relatórios Corporativos':^60}{Cores.RESET}")
        print(f"{Cores.AZUL_CLARO}{'═' * 60}{Cores.RESET}\n")
        
        print(f" {MenuPrincipal.REDE.value} - 🌐 {Cores.CIANO}Configurações de Rede & DNS{Cores.RESET}")
        print(f" {MenuPrincipal.SISTEMA.value} - 🛠️  {Cores.MAGENTA}Manutenção do Sistema{Cores.RESET}")
        print(f" {MenuPrincipal.LOGS.value} - 📋 {Cores.AMARELO}Logs de Operações{Cores.RESET}")
        print(f" {MenuPrincipal.RELATORIO.value} - 📊 {Cores.AZUL}Gerar Relatório HTML{Cores.RESET}")
        print(f" {MenuPrincipal.EMPRESA.value} - 🏢 {Cores.CIANO}Perfil da Empresa & Inventário{Cores.RESET}")
        print(f" {MenuPrincipal.MONITORAMENTO.value} - 📡 {Cores.VERDE}Monitoramento Ativo{Cores.RESET}")
        print(f" {MenuPrincipal.CENTRAL.value} - 🏢📊 {Cores.VERDE}Centralização, Relatórios e E-mail{Cores.RESET}")
        print(f" {MenuPrincipal.SAIR.value} - 🚪 {Cores.VERMELHO}Sair{Cores.RESET}")
        
        print(f"\n{Cores.AZUL_CLARO}{'─' * 60}{Cores.RESET}")
        op = input("Selecione uma opção: ").strip()
        
        if op == MenuPrincipal.REDE.value:
            sub_menu_rede()
        elif op == MenuPrincipal.SISTEMA.value:
            sub_menu_sistema()
        elif op == MenuPrincipal.LOGS.value:
            sub_menu_logs()
        elif op == MenuPrincipal.RELATORIO.value:
            gerar_relatorio()
        elif op == MenuPrincipal.EMPRESA.value:
            sub_menu_empresa()
        elif op == MenuPrincipal.CENTRAL.value:
            sub_menu_centralizacao()
        elif op == MenuPrincipal.MONITORAMENTO.value:
            ok, msg = ModuloEmpresa.abrir_monitoramento_ativo()
            if not ok:
                print(f"{Cores.VERMELHO}❌ {msg}{Cores.RESET}")
                input("Pressione Enter...")
        elif op == MenuPrincipal.SAIR.value:
            arqs, pastas = ModuloSistema.limpar_cache_do_programa()
            print(f"\n{Cores.VERDE}✅ Até logo!{Cores.RESET}")
            print(f"{Cores.CINZA}🧹 Cache do Configurador removido: {arqs} arquivos e {pastas} pastas. Logs, relatórios e backups foram preservados.{Cores.RESET}")
            break
        else:
            print(f"{Cores.VERMELHO}Opção inválida!{Cores.RESET}")
            time.sleep(1)


# ==========================================
# IMPLANTAÇÃO CORPORATIVA E AUTOMAÇÃO (v3.8)
# ==========================================
class ModuloImplantacao:
    @staticmethod
    def _run(args, timeout=300):
        try:
            r=subprocess.run(args,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=timeout)
            return r.returncode==0,normalizar_texto_console((r.stdout or r.stderr or "").strip())
        except Exception as e:return False,str(e)
    @staticmethod
    def criar_usuario(nome,senha,admin=False):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,20}",(nome or "").strip()): return False,"Nome inválido."
        if not senha:return False,"Senha vazia."
        if not elevacao_sob_demanda("criar usuário local"): return False,"Operação cancelada (privilégio de administrador necessário)."
        n=escapar_ps_string(nome.strip()); pw=escapar_ps_string(senha)
        cmd=f"$p=ConvertTo-SecureString '{pw}' -AsPlainText -Force; New-LocalUser -Name '{n}' -Password $p -ErrorAction Stop|Out-Null;"
        if admin: cmd+=f"Add-LocalGroupMember -Group 'Administrators' -Member '{n}' -ErrorAction Stop;"
        # Usa executor via arquivo .ps1 temporário (ACL restrita) para a senha
        # não aparecer como argumento de linha de comando (Get-Process etc.).
        r=executar_powershell_com_senha(cmd,30)
        if r.returncode==0: registrar_log("IMPLANTACAO","CRIAR_USUARIO_LOCAL",nome); return True,"Usuário criado."
        return False,r.stderr.strip() or r.stdout.strip() or "Falha."
    @staticmethod
    def workgroup(grupo):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}",(grupo or "").strip()):return False,"Grupo inválido."
        if not elevacao_sob_demanda("alterar grupo de trabalho"): return False,"Operação cancelada (privilégio de administrador necessário)."
        r=executar_powershell(f"Add-Computer -WorkGroupName '{escapar_ps_string(grupo)}' -Force",45)
        if r.returncode==0: registrar_log("IMPLANTACAO","ALTERAR_GRUPO_TRABALHO",grupo);return True,"Grupo alterado. Reinicie o computador."
        return False,r.stderr.strip() or r.stdout.strip()
    @staticmethod
    def winget(nome,pacote):
        ok,msg=ModuloImplantacao._run(["winget","install","--id",pacote,"-e","--accept-source-agreements","--accept-package-agreements"],900)
        if ok:registrar_log("IMPLANTACAO","INSTALAR_SOFTWARE",f"{nome}|{pacote}")
        return ok,msg or ("Instalação concluída." if ok else "Falha.")
    @staticmethod
    def dominio(dominio,usuario,senha):
        if not all([dominio,usuario,senha]):return False,"Preencha domínio, usuário e senha."
        if not elevacao_sob_demanda("ingressar no domínio"): return False,"Operação cancelada (privilégio de administrador necessário)."
        cmd=f"$p=ConvertTo-SecureString '{escapar_ps_string(senha)}' -AsPlainText -Force;$c=New-Object System.Management.Automation.PSCredential('{escapar_ps_string(usuario)}',$p);Add-Computer -DomainName '{escapar_ps_string(dominio)}' -Credential $c -Force"
        # Idem: senha nunca vai na linha de comando do processo powershell.exe.
        r=executar_powershell_com_senha(cmd,90)
        if r.returncode==0:registrar_log("IMPLANTACAO","INGRESSAR_DOMINIO",dominio);return True,"Ingressado no domínio. Reinicie."
        return False,r.stderr.strip() or r.stdout.strip()
    @staticmethod
    def mapear_unidade(letra,caminho):
        letra=(letra or "").upper().rstrip(":")
        if not re.fullmatch("[D-Z]",letra) or not (caminho or "").startswith("\\\\"):return False,"Letra ou caminho UNC inválido."
        ok,msg=ModuloImplantacao._run(["net","use",letra+":",caminho,"/persistent:yes"],60)
        if ok:registrar_log("IMPLANTACAO","MAPEAR_UNIDADE",f"{letra}: -> {caminho}")
        return ok,msg
    @staticmethod
    def mapear_impressora(caminho):
        if not (caminho or "").startswith("\\\\"):return False,"Informe um caminho UNC."
        ok,msg=ModuloImplantacao._run(["rundll32","printui.dll,PrintUIEntry","/in","/n",caminho],120)
        if ok:registrar_log("IMPLANTACAO","MAPEAR_IMPRESSORA",caminho)
        return ok,msg
    @staticmethod
    def criar_atalho(nome,destino):
        if not nome or not destino:return False,"Preencha nome e destino."
        if not elevacao_sob_demanda("criar atalho na Área de Trabalho Pública"): return False,"Operação cancelada (privilégio de administrador necessário)."
        arq=Path(os.environ.get("PUBLIC",r"C:\Users\Public"))/"Desktop"/f"{nome}.lnk"
        cmd=f"$w=New-Object -ComObject WScript.Shell;$s=$w.CreateShortcut('{escapar_ps_string(str(arq))}');$s.TargetPath='{escapar_ps_string(destino)}';$s.Save()"
        r=executar_powershell(cmd,30)
        if r.returncode==0:registrar_log("IMPLANTACAO","CRIAR_ATALHO",f"{nome}->{destino}");return True,str(arq)
        return False,r.stderr.strip()
    @staticmethod
    def seguranca(quick=False, permitir_elevacao=True):
        if quick and not verificar_admin():
            if not permitir_elevacao:
                return False,"Privilégio de administrador ausente no modo não interativo."
            if not elevacao_sob_demanda("executar verificação do Microsoft Defender"):
                return False,"Operação cancelada (privilégio de administrador necessário)."
        cmd="Start-MpScan -ScanType QuickScan" if quick else "Get-MpComputerStatus|Select AntivirusEnabled,RealTimeProtectionEnabled,AMServiceEnabled,AntispywareEnabled|ConvertTo-Json -Compress"
        r=executar_powershell(cmd,300)
        if r.returncode:return False,r.stderr.strip() or r.stdout.strip()
        registrar_log("SEGURANCA","DEFENDER_QUICK_SCAN" if quick else "STATUS_DEFENDER","OK")
        return True,normalizar_texto_console(r.stdout.strip() or "Concluído.")
    @staticmethod
    def reset_windows():
        if not elevacao_sob_demanda("iniciar a redefinição do Windows"): return False,"Operação cancelada (privilégio de administrador necessário)."
        ok,msg=ModuloImplantacao._run(["systemreset","-factoryreset"],30)
        if ok:registrar_log("SISTEMA","INICIAR_RESET_WINDOWS","Assistente nativo aberto")
        return ok,msg or "Assistente nativo aberto."
    @staticmethod
    def agendar_manutencao(h):
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d",h or ""):return False,"Horário inválido."
        if not elevacao_sob_demanda("agendar manutenção automática"): return False,"Operação cancelada (privilégio de administrador necessário)."
        cmd,destino,args_log=_alvo_modo_agendado('--manutencao-programada')
        codigo,msg=_executar_schtasks([
            '/Create','/TN',TAREFA_MANUTENCAO,'/TR',cmd,
            '/SC','DAILY','/ST',h,'/RL','HIGHEST','/F',
        ])
        ok=codigo==0
        registrar_evento_instancia(
            "AGENDAMENTO_INSTANCIA_CONFIGURADO",
            motivo=f"tarefa={TAREFA_MANUTENCAO};modo=--manutencao-programada;codigo={codigo}",
            executavel_destino=destino,
            argumentos_destino=args_log,
        )
        registrar_log('AUTOMACAO','AGENDAMENTO_CONFIGURADO',f'tarefa={TAREFA_MANUTENCAO};horario={h};modo=--manutencao-programada;codigo={codigo};nivel=HIGHEST')
        if ok:registrar_log("AUTOMACAO","AGENDAR_MANUTENCAO",h)
        return ok,msg or ('Manutenção agendada.' if ok else f'schtasks retornou código {codigo}.')

def _submenu_instalar_aplicacoes():
    apps={"1":("Microsoft 365","Microsoft.Office"),"2":("Google Chrome","Google.Chrome"),"3":("Adobe Reader","Adobe.Acrobat.Reader.64-bit"),"4":("WinRAR","RARLab.WinRAR")}
    while True:
        limpar_tela()
        print(f"{Cores.MAGENTA}{'═'*60}{Cores.RESET}\n{Cores.NEGRITO}{'INSTALAÇÃO DE APLICATIVOS':^60}{Cores.RESET}\n{Cores.MAGENTA}{'═'*60}{Cores.RESET}")
        print(f"1 - 📦 {Cores.CIANO}Microsoft 365{Cores.RESET}")
        print(f"2 - 🌐 {Cores.AZUL}Google Chrome{Cores.RESET}")
        print(f"3 - 📄 {Cores.AMARELO}Adobe Reader{Cores.RESET}")
        print(f"4 - 🗜️  {Cores.VERDE}WinRAR{Cores.RESET}")
        print(f"0 - ↩️  {Cores.VERMELHO}Voltar{Cores.RESET}")
        op=input("Escolha: ").strip()
        if op=='0': return
        if op not in apps: print('❌ Opção inválida.'); time.sleep(1); continue
        nome,pacote=apps[op]
        if confirmar_acao(f"Instalar {nome}?",False):
            ok,msg=ModuloImplantacao.winget(nome,pacote); print(('✅ ' if ok else '❌ ')+str(msg)); input('Pressione Enter...')

def _submenu_seguranca():
    while True:
        limpar_tela()
        print(f"{Cores.MAGENTA}{'═'*60}{Cores.RESET}\n{Cores.NEGRITO}{'SEGURANÇA E MICROSOFT DEFENDER':^60}{Cores.RESET}\n{Cores.MAGENTA}{'═'*60}{Cores.RESET}")
        print(f"1 - 🛡️  {Cores.CIANO}Verificar status do Microsoft Defender{Cores.RESET}")
        print(f"2 - 🔍 {Cores.VERMELHO}Executar verificação rápida{Cores.RESET}")
        print(f"0 - ↩️  {Cores.VERMELHO}Voltar{Cores.RESET}")
        op=input('Escolha: ').strip()
        if op=='0': return
        if op=='1': ok,msg=ModuloImplantacao.seguranca(False)
        elif op=='2': ok,msg=ModuloImplantacao.seguranca(True)
        else: print('❌ Opção inválida.'); time.sleep(1); continue
        print(('✅ ' if ok else '❌ ')+str(msg)); input('Pressione Enter...')

def sub_menu_implantacao():
    """Menu compacto: mantém todas as funções, agrupando operações relacionadas."""
    while True:
        limpar_tela()
        print(f"{Cores.MAGENTA}{'═'*60}{Cores.RESET}\n{Cores.NEGRITO}{'IMPLANTAÇÃO CORPORATIVA':^60}{Cores.RESET}\n{Cores.MAGENTA}{'═'*60}{Cores.RESET}")
        print(f"1 - 👤 {Cores.CIANO}Usuários, grupo de trabalho e domínio{Cores.RESET}")
        print(f"2 - 📦 {Cores.AZUL}Instalação de aplicativos{Cores.RESET}")
        print(f"3 - 🌐 {Cores.CIANO}Mapear recursos de rede (unidade/impressora){Cores.RESET}")
        print(f"4 - 🔗 {Cores.MAGENTA}Criar atalhos corporativos{Cores.RESET}")
        print(f"5 - 🛡️  {Cores.VERMELHO}Segurança e Microsoft Defender{Cores.RESET}")
        print(f"6 - ⏰ {Cores.VERDE}Automação e manutenção programada{Cores.RESET}")
        print(f"7 - ♻️  {Cores.AMARELO}Redefinição nativa do Windows{Cores.RESET}")
        print(f"0 - ↩️  {Cores.VERMELHO}Voltar{Cores.RESET}")
        op=input('Escolha: ').strip()
        if op=='0': return
        try:
            if op=='1':
                limpar_tela(); print(f'{Cores.CIANO}1 - Criar usuário local{Cores.RESET}'); print(f'{Cores.AMARELO}2 - Alterar grupo de trabalho{Cores.RESET}'); print(f'{Cores.AZUL_CLARO}3 - Ingressar no domínio{Cores.RESET}'); print(f'{Cores.VERMELHO}0 - Voltar{Cores.RESET}'); x=input('Escolha: ').strip()
                if x=='1': ok,msg=ModuloImplantacao.criar_usuario(input('Usuário: '),input('Senha: '),confirmar_acao('Administrador?',False))
                elif x=='2': ok,msg=ModuloImplantacao.workgroup(input('Grupo: '))
                elif x=='3': ok,msg=ModuloImplantacao.dominio(input('Domínio: '),input('Usuário autorizado: '),input('Senha: '))
                else: continue
            elif op=='2': _submenu_instalar_aplicacoes(); continue
            elif op=='3':
                limpar_tela(); print(f'{Cores.CIANO}1 - 💽 Mapear unidade de rede{Cores.RESET}'); print(f'{Cores.AZUL}2 - 🖨️  Mapear impressora{Cores.RESET}'); print(f'{Cores.VERMELHO}0 - Voltar{Cores.RESET}'); x=input('Escolha: ').strip()
                if x=='1': ok,msg=ModuloImplantacao.mapear_unidade(input('Letra: '),input('UNC: '))
                elif x=='2': ok,msg=ModuloImplantacao.mapear_impressora(input('UNC da impressora: '))
                else: continue
            elif op=='4': ok,msg=ModuloImplantacao.criar_atalho(input('Nome: '),input('Destino: '))
            elif op=='5': _submenu_seguranca(); continue
            elif op=='6': ok,msg=ModuloImplantacao.agendar_manutencao(input('HH:MM: '))
            elif op=='7':
                if not confirmar_acao('Abrir redefinição do Windows? Pode causar perda de dados.',False): continue
                ok,msg=ModuloImplantacao.reset_windows()
            else: print('❌ Opção inválida.'); time.sleep(1); continue
            print(('✅ ' if ok else '❌ ')+str(msg))
        except Exception as e: logger.exception('Implantação'); print(f'❌ {e}')
        input('Pressione Enter...')

def preparar_ambiente_portatil():
    """Prepara o ambiente local sem exigir instalação de Python ou VS Code.

    Em modo .exe, o PyInstaller fornece sys.executable; em modo .py, usamos
    a pasta do próprio script. Nenhum caminho depende do diretório atual.
    """
    for pasta in (DIRETORIO_BASE, Path(PASTA_BACKUP), Path(PASTA_COLETAS)):
        try:
            Path(pasta).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(f"Não foi possível preparar a pasta portátil: {pasta}\n{exc}") from exc
    # Backups de DNS e coletas de inventário contêm dados sensíveis de rede/host;
    # restringe a NTFS quando o disco suportar (sem efeito em pendrive FAT32/exFAT).
    restringir_acl_arquivo(PASTA_BACKUP)
    restringir_acl_arquivo(PASTA_COLETAS)


def menu_principal():
    inicializar_terminal()
    preparar_ambiente_portatil()
    # v4.11: não força mais elevação UAC logo na abertura. O programa abre em
    # modo normal e só pede admin no momento em que uma ação específica exige
    # (ver elevacao_sob_demanda). Isso permite usar consultas/relatórios sem UAC.
    Path(PASTA_BACKUP).mkdir(parents=True, exist_ok=True)
    while True:
        limpar_tela()
        status_admin = f"{Cores.VERDE}Administrador{Cores.RESET}" if verificar_admin() else f"{Cores.AMARELO}Usuário padrão (será pedido admin se necessário){Cores.RESET}"
        # Interface restaurada no padrão visual da v4.4.
        # A lógica e as funções da versão segura permanecem intactas.
        print(f"{Cores.AZUL_CLARO}{'═' * 60}{Cores.RESET}")
        print(f"{Cores.AZUL_CLARO}{Cores.NEGRITO}{'CONFIGURADOR DE TI':^60}{Cores.RESET}")
        print(f"{Cores.CINZA}{'v4.10 Seguro • Interface v4.4 • Portátil':^60}{Cores.RESET}")
        print(f"{Cores.AZUL_CLARO}{'═' * 60}{Cores.RESET}")
        print(f"Modo atual: {status_admin}\n")

        print(f"1 - 🌐 {Cores.CIANO}Configurações de Rede & DNS{Cores.RESET}")
        print(f"2 - 🛠️ {Cores.MAGENTA}Manutenção do Sistema{Cores.RESET}")
        print(f"3 - 📋 {Cores.AMARELO}Logs de Operações{Cores.RESET}")
        print(f"4 - 📊 {Cores.AZUL}Gerar Relatório HTML{Cores.RESET}")
        print(f"5 - 🏢 {Cores.CIANO}Perfil da Empresa & Inventário{Cores.RESET}")
        print(f"6 - 📡 {Cores.VERDE}Monitoramento Ativo{Cores.RESET}")
        print(f"7 - 🏢📊 {Cores.VERDE}Centralização, Relatórios e E-mail{Cores.RESET}")
        print(f"8 - 🚀 {Cores.AZUL_CLARO}Implantação Corporativa & Automação{Cores.RESET}")
        print(f"0 - 🚪 {Cores.VERMELHO}Sair{Cores.RESET}")

        print(f"\n{Cores.AZUL_CLARO}{'─' * 60}{Cores.RESET}")
        op = input(f"{Cores.NEGRITO}Selecione uma opção: {Cores.RESET}").strip()
        if op=="1":sub_menu_rede()
        elif op=="2":sub_menu_sistema()
        elif op=="3":sub_menu_logs()
        elif op=="4":gerar_relatorio()
        elif op=="5":sub_menu_empresa()
        elif op=="6":
            ok,msg=ModuloEmpresa.abrir_monitoramento_ativo()
            if not ok:print(f"{Cores.VERMELHO}❌ {msg}{Cores.RESET}");input("Enter...")
        elif op=="7":sub_menu_centralizacao()
        elif op=="8":sub_menu_implantacao()
        elif op=="0":
            arqs,pastas=ModuloSistema.limpar_cache_do_programa();print(f"{Cores.VERDE}✅ Até logo!{Cores.RESET} Cache removido: {arqs} arquivos e {pastas} pastas.");break
        else:print(f"{Cores.VERMELHO}❌ Opção inválida.{Cores.RESET}");time.sleep(1)

# ==========================================
# PONTO DE ENTRADA
# ==========================================
if __name__ == "__main__":
    codigo_headless=despachar_modo_headless(sys.argv[1:])
    if codigo_headless is not None:
        sys.exit(codigo_headless)
    inicializar_terminal()
    try:
        menu_principal()
        registrar_instancia_encerrando("MENU_CONSOLE_ENCERRADO")
    except KeyboardInterrupt:
        print(f"\n\n{Cores.AMARELO}Operação cancelada pelo usuário.{Cores.RESET}")
        registrar_instancia_encerrando("INTERRUPCAO_TECLADO")
        sys.exit(0)
    except Exception as e:
        logger.exception("Erro fatal na aplicação")
        print(f"\n{Cores.VERMELHO}❌ Erro fatal: {e}{Cores.RESET}")
        input("Pressione Enter para sair...")
        registrar_instancia_encerrando(f"ERRO_FATAL:{type(e).__name__}")
        sys.exit(1)
