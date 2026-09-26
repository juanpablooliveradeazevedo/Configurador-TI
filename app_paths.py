"""Caminhos portáteis e migração de arquivos conhecidos, sem alterar schemas.

Runtime permanece na raiz. Não modifica caminhos explícitos de coletas/servidores.
Feche versões anteriores antes de transferir os dados para esta revisão.
"""
from pathlib import Path
import os
import sys

BASELINE_DEFENSIVO_RELATIVO = Path("dados") / "defensiva" / "baseline_defensivo.json"

FILE_MAP = {
    'perfis_dns.json': 'dados/dns/perfis_dns.json',
    'configurador_ti_config.json': 'dados/configuracoes/configurador_ti_config.json',
    'centralizacao_ti.json': 'dados/configuracoes/centralizacao_ti.json',
    'perfil_empresa.json': 'dados/empresa/perfil_empresa.json',
    'inventario_empresa.json': 'dados/empresa/inventario_empresa.json',
    'inteligencia_rede.json': 'dados/rede/inteligencia_rede.json',
    'triagem_tecnica.json': 'dados/triagem/triagem_tecnica.json',
    'benchmark_configurador_ti_historico.json': 'dados/configuracoes/benchmark_configurador_ti_historico.json',
    'configurador_ti.log': 'logs/configurador_ti.log',
}
DIRECTORY_MAP = {'backups_dns': 'dados/backups/dns', 'coletas_centralizadas': 'coletas'}


def runtime_root():
    return Path(sys.executable if getattr(sys, 'frozen', False) else __file__).resolve().parent


def asset_root():
    """Raiz somente leitura dos assets, inclusive extração ``_MEIPASS``.

    Persistências continuam usando :func:`runtime_root`; esta separação impede
    que dados, logs ou relatórios sejam escritos no diretório temporário do
    PyInstaller onefile.
    """
    if getattr(sys, 'frozen', False) and getattr(sys, '_MEIPASS', None):
        return Path(sys._MEIPASS).resolve()
    return Path(__file__).resolve().parent


def asset_path(relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Caminho de asset deve ser relativo e permanecer na raiz.')
    return asset_root() / relative


class PortablePaths:
    """Novo tem precedência; conflito nunca mescla nem apaga arquivos.

    Arquivo legado: rename sem sobrescrita no Windows; hardlink/unlink no POSIX.
    Mesma unidade, mesmos bytes e metadados. Falha mantém o legado como caminho
    efetivo. Diretórios legados continuam no lugar para preservar referências.
    Fallbacks dos consumidores (TEMP/LOCALAPPDATA) continuam sob seu controle.
    """
    def __init__(self, root=None):
        self.root = Path(root).resolve() if root is not None else runtime_root()
        self.events = []
        self.files = {}

    def _event(self, state, old, new):
        self.events.append(f'PATHS_{state} | {old} -> {new}')

    def _parent(self, path):
        # Não seguir links/junções introduzidos dentro da estrutura de dados.
        for item in (path, *path.parents):
            if item == self.root:
                break
            if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
                raise RuntimeError('Caminho de dados é link/junção; preservado: ' + str(item))
        path.mkdir(parents=True, exist_ok=True, mode=0o700)

    def file(self, name):
        if name in self.files:
            return self.files[name]
        relative = FILE_MAP[name]
        old, new = self.root/name, self.root/relative
        if old.is_symlink() or new.is_symlink():
            raise RuntimeError('Arquivo de dados é link; preservado: ' + name)
        try:
            self._parent(new.parent)
        except OSError:
            self._event('FALLBACK_LEGADO', name, relative)
            self.files[name] = old
            return old
        if new.exists():
            if old.exists():
                self._event('CONFLITO_PRESERVADO_NOVO_ATIVO', name, relative)
            self.files[name] = new
            return new
        if old.exists():
            if not old.is_file():
                raise RuntimeError('Persistência esperada como arquivo: ' + name)
            # Interopera com os dois padrões de lock já usados pelos stores.
            locks = list(dict.fromkeys((old.with_suffix('.lock'), old.with_name(old.name+'.lock'))))
            owned = []
            try:
                for lock in locks:
                    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.close(fd);owned.append(lock)
                if os.name == 'nt':
                    os.rename(old, new)  # Windows recusa destino existente; mantém ACL.
                else:
                    os.link(old, new, follow_symlinks=False)  # O_EXCL atômico no destino.
                    if not os.path.samefile(old, new):
                        raise RuntimeError('Origem mudou durante migração; ambos preservados.')
                    old.unlink()
                self._event('MIGRADO', name, relative)
            except FileExistsError:
                if new.exists():
                    self._event('CONFLITO_PRESERVADO_NOVO_ATIVO', name, relative)
                else:
                    # Não continuar com localização instável enquanto outro store grava.
                    raise RuntimeError('Dados em uso; feche outras instâncias e tente novamente: ' + name)
            except OSError:
                # Falha de rename/link (permissão, FS sem hardlinks, arquivo aberto).
                # Se o novo link existe, ambos apontam ao mesmo conteúdo e novo prevalece.
                self._event('DUPLICATA_PRESERVADA_NOVO_ATIVO' if new.exists() else 'LEGADO_RECONHECIDO', name, relative)
                if not new.exists():new = old
            finally:
                for lock in reversed(owned):lock.unlink()
        self.files[name] = new
        return new

    def directory(self, relative, legacy=None):
        new = self.root/relative
        # Mesmo na seleção de legado, não aceitar um destino que redirecione escrita.
        for item in (new, *new.parents):
            if item == self.root:break
            if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
                raise RuntimeError('Diretório de dados é link/junção; preservado: ' + relative)
        if legacy and (self.root/legacy).exists():
            old = self.root/legacy
            if old.is_symlink() or (hasattr(old, 'is_junction') and old.is_junction()):
                raise RuntimeError('Diretório legado é link/junção; preservado: ' + legacy)
            # Pasta vazia do pacote não deve ocultar dados legados.
            if new.exists() and any(new.iterdir()):
                self._event('CONFLITO_DIRETORIO_NOVO_ATIVO', legacy, relative)
                return new
            # Arquivos dentro podem ter caminhos gravados em configurações. Não mesclar.
            self._event('DIRETORIO_LEGADO_ATIVO', legacy, relative)
            return old
        try:
            self._parent(new)
        except OSError:
            self._event('DIRETORIO_FALLBACK', legacy or relative, relative)
            return self.root/(legacy or '')
        return new

    def log_events(self, logger):
        for event in self.events:
            if 'CONFLITO' in event or 'FALLBACK' in event:
                logger.warning(event)
            else:
                logger.info(event)
        self.events.clear()
