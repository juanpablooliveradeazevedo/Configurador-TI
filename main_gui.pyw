# -*- coding: utf-8 -*-
"""Launcher gráfico opcional do Configurador TI.

O Windows associa arquivos ``.pyw`` ao ``pythonw.exe``. Assim, o código-fonte
pode ser aberto com duplo clique sem criar uma janela de console. Para
depuração, continue usando ``python main_gui.py`` ou defina
``CONFIGURADOR_TI_DEBUG_CONSOLE=1`` antes de iniciar.
"""

import ctypes
import os
import sys
import tempfile
import traceback
from pathlib import Path


os.environ.setdefault("CONFIGURADOR_TI_GUI_MODE", "1")

_MODOS_HEADLESS_BOOTSTRAP = {
    "--coleta-diaria",
    "--manutencao-programada",
    "--saude-armazenamento-elevada",
    "--windows-update-elevado",
}


def _bootstrap_em_modo_headless():
    """Evita diálogos se a falha ocorrer antes do dispatch do backend."""
    return any(arg in _MODOS_HEADLESS_BOOTSTRAP for arg in sys.argv[1:])


def _registrar_excecao_bootstrap(exc_type, exc_value, exc_traceback):
    """Registra falhas ocorridas antes de a GUI instalar seu handler global."""
    detalhe = "".join(
        traceback.format_exception(exc_type, exc_value, exc_traceback)
    )
    candidatos = [
        (Path(sys.executable).resolve().parent if getattr(sys, "frozen", False)
         else Path(__file__).resolve().parent) / "logs" / "configurador_ti.log",
        Path(tempfile.gettempdir()) / "ConfiguradorTI" / "configurador_ti.log",
    ]
    caminho_log = None
    for candidato in candidatos:
        try:
            candidato.parent.mkdir(parents=True, exist_ok=True)
            with candidato.open("a", encoding="utf-8") as arquivo:
                arquivo.write("\n[BOOTSTRAP] Falha ao iniciar a GUI\n")
                arquivo.write(detalhe)
            caminho_log = candidato
            break
        except Exception:
            continue

    destino = str(caminho_log) if caminho_log else "nenhum arquivo de log pôde ser criado"
    mensagem = (
        "O Configurador TI não pôde iniciar.\n\n"
        f"O detalhe foi registrado em: {destino}\n\n"
        f"{exc_type.__name__}: {exc_value}"
    )
    try:
        if os.name == "nt" and not _bootstrap_em_modo_headless():
            ctypes.windll.user32.MessageBoxW(
                None, mensagem[:4000], "Configurador TI — erro de inicialização", 0x10
            )
    except Exception:
        pass

    # Em modo de desenvolvimento (python.exe), mantém a informação visível
    # no terminal. Em pythonw.exe stderr pode ser None, por isso é opcional.
    try:
        if sys.stderr is not None and hasattr(sys.stderr, "write"):
            sys.stderr.write(detalhe)
            sys.stderr.flush()
    except Exception:
        pass


sys.excepthook = _registrar_excecao_bootstrap

from main_gui import main


if __name__ == "__main__":
    sys.exit(main())
