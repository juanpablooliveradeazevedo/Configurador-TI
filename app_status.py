"""Identificação da edição e verificação local de diretórios, sem coleta técnica.

Recebe somente caminhos/flags explícitos. Nunca lê JSONs, credenciais ou ambiente.
A prova de escrita cria e remove apenas seu próprio arquivo temporário vazio.
"""
from pathlib import Path
import logging
import ntpath
import os
import struct
import sys
import tempfile

from release_metadata import BUILD_DATE, PRODUCT, VERSION, RUNTIME_BUILD_METADATA

def check_directory(path):
    """Verifica acesso e escrita sem alterar arquivos preexistentes ou ACLs."""
    path = Path(path)
    # Não sondar UNC/unidades remotas para preencher este painel local.
    try:
        if os.name == 'nt':
            import ctypes
            drive = ntpath.splitdrive(str(path))[0]
            if str(path).startswith(('\\\\', '//')) or (drive and ctypes.windll.kernel32.GetDriveTypeW(drive+'\\') == 4):
                return {'path': str(path), 'ok': False, 'message': 'Caminho remoto: não verificado localmente'}
        if not path.is_dir():
            return {'path': str(path), 'ok': False, 'message': 'Pasta indisponível'}
        # Abrir o iterador verifica acesso; não enumera nem lê dados persistentes.
        with os.scandir(path):
            pass
        with tempfile.TemporaryFile(prefix='.configurador-ti-status-', dir=path):
            pass
        return {'path': str(path), 'ok': True, 'message': 'OK'}
    except OSError:
        return {'path': str(path), 'ok': False,
                'message': 'Sem acesso ou escrita. Verifique a permissão da pasta.'}


def environment_status(*, root, data_paths, log_path, report_path, collection_path,
                       qss_loaded, administrator, log_active):
    """Snapshot local. Não promete a gravabilidade de cada JSON/store individual."""
    root = Path(root)
    paths = list(dict.fromkeys(str(Path(p)) for p in data_paths))
    data = [check_directory(p) for p in paths]
    logs = check_directory(Path(log_path).parent)
    if not log_active:
        logs.update(ok=False, message='Log em disco indisponível. Verifique as permissões.')
    reports = check_directory(report_path)
    collections = check_directory(collection_path)
    portable = bool(paths) and all(Path(p).is_relative_to(root/'dados') for p in paths)
    warnings = []
    if not data or not all(item['ok'] for item in data):
        warnings.append('Uma pasta de dados está indisponível ou sem escrita.')
    if not logs['ok']: warnings.append('O log em disco não está disponível para gravação.')
    if not reports['ok']: warnings.append('A pasta de relatórios não está disponível para gravação.')
    if not collections['ok']: warnings.append('A pasta de coletas não está disponível para gravação.')
    if not portable: warnings.append('Dados usam caminho legado ou alternativo; consulte os caminhos abaixo.')
    if Path(log_path).parent != root/'logs':
        warnings.append('Logs usam um caminho alternativo; consulte o caminho efetivo abaixo.')
    if Path(report_path) != root/'relatorios':
        warnings.append('Relatórios usam um caminho alternativo; consulte o caminho efetivo abaixo.')
    if not qss_loaded: warnings.append('O tema style.qss não foi carregado.')
    build_metadata = RUNTIME_BUILD_METADATA
    return {'product': PRODUCT, 'version': VERSION, 'build': BUILD_DATE,
            'build_profile': build_metadata.get('profile') or 'SOURCE',
            'build_backend': build_metadata.get('backend') or 'pyinstaller',
            'mode': 'EXE' if getattr(sys, 'frozen', False) else 'Fonte',
            'architecture': f'{struct.calcsize("P") * 8} bits (processo)',
            'administrator': 'Sim' if administrator else 'Não',
            'data': data, 'data_ok': bool(data) and all(item['ok'] for item in data),
            'logs': logs, 'log_file': str(log_path), 'reports': reports,
            'collections': collections, 'qss_ok': bool(qss_loaded),
            'warnings': warnings}


def active_log_file(logger, expected):
    """Obtém o destino real do handler existente, incluindo fallback TEMP."""
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler) and handler.stream is not None:
            return Path(handler.baseFilename), True
    return Path(expected), False
