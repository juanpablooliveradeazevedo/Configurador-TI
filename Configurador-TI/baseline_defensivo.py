"""Referência temporal local. Não classifica, revisa ou remedia itens.

Chave lógica != identidade da triagem != fingerprint das evidências.
Cobertura parcial nunca confirma ausência. Nenhum arquivo analisado é aberto.
"""
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import uuid

from app_paths import PortablePaths, BASELINE_DEFENSIVO_RELATIVO
from triagem_interativa import texto_seguro

SCHEMA = 2
MAX_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 3000
MAX_TOTAL = 12000
MAX_SCOPES = 16
STATES = ('Novo', 'Alterado', 'Ausente', 'Sem alteração', 'Indeterminado')
TEXT_FIELDS = ('Tipo', 'Nome', 'Caminho', 'Comando', 'Fonte', 'ContextoUsuario',
               'Usuario', 'NomeTecnico', 'CaminhoTarefa', 'ArquivoStartup',
               'OrigemTipo', 'OrigemNome', 'Assinatura', 'Publisher',
               'ModificadoUtc', 'CriadoUtc', 'Inicializacao', 'TipoAcao',
               'ClassIdAcao', 'DiretorioTrabalho', 'Gatilhos', 'NivelExecucao', 'TipoLogon')
BOOL_FIELDS = ('Existe', 'PersistenciaAtiva', 'Habilitada')
FIELDS = set(TEXT_FIELDS + BOOL_FIELDS + ('TamanhoBytes',))
PATH_FIELDS = {'Caminho', 'ArquivoStartup', 'DiretorioTrabalho', 'CaminhoTarefa'}
EMPTY = {'', '—', 'Não disponível'}


class BaselineError(ValueError):
    """Mensagem fixa e segura para GUI/log; nunca inclui conteúdo do arquivo."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def stopped(callback):
    if callback and callback(): raise BaselineError('Operação de baseline cancelada.')


def logical_key(evidence):
    """Proveniência forte por tipo. Campos mutáveis ficam na fingerprint."""
    e=evidence; kind=e.get('Tipo'); source=e.get('Fonte')
    path=e.get('Caminho'); user=e.get('ContextoUsuario') or e.get('Usuario')
    if kind=='Processo': parts=(kind,source,path,user)
    elif kind=='Serviço': parts=(kind,source,e.get('NomeTecnico'))
    elif kind=='Tarefa agendada': parts=(kind,source,e.get('CaminhoTarefa'),e.get('Nome'))
    elif kind in {'Run','RunOnce'}: parts=(kind,source,user,e.get('Nome'))
    elif kind=='Startup': parts=(kind,source,user,e.get('ArquivoStartup'))
    elif kind=='Arquivo associado':
        parts=(kind,source,path,e.get('OrigemTipo'),e.get('OrigemNome'),user)
    else: return None
    if any(not isinstance(x,str) or not x.strip() or '<mascarado>' in x for x in parts): return None
    # Caminhos de entidades baseadas em arquivo precisam ser absolutos, sem abrir disco.
    if kind in {'Processo','Arquivo associado','Startup'}:
        target=e.get('ArquivoStartup') if kind=='Startup' else path
        if not re.match(r'^[a-zA-Z]:\\',target or ''): return None
    return digest([part.casefold() for part in parts])


def snapshot(item, sanitize):
    if type(item) is not dict: raise BaselineError('Item defensivo inválido.')
    evidence={}
    for field in TEXT_FIELDS:
        value=item.get(field)
        if value is not None and type(value) is not str: raise BaselineError('Tipo de evidência inválido.')
        # Não truncar uma identidade silenciosamente e depois declarar pareamento.
        if value is not None and len(value)>1200: raise BaselineError('Evidência acima do limite de texto.')
        text=texto_seguro(value,sanitize,1200)
        if field in PATH_FIELDS and text not in EMPTY:
            text=ntpath.normpath(text.replace('/','\\')).casefold()
        evidence[field]=None if text in EMPTY else text
    for field in BOOL_FIELDS:
        value=item.get(field)
        if value is not None and type(value) is not bool: raise BaselineError('Tipo de evidência inválido.')
        evidence[field]=value
    size=item.get('TamanhoBytes')
    if size is not None and (type(size) is not int or size<0 or size>2**63-1): raise BaselineError('Tamanho de evidência inválido.')
    evidence['TamanhoBytes']=size
    # Nenhuma leitura de ComandoOriginal, hash de arquivo, notas ou classificação.
    return {'key':logical_key(evidence),'fingerprint':digest(evidence),'evidence':evidence}



# Fontes do coletor existente, sem novas coletas. Registro agrega as visões
# 32/64-bit por hive/tipo: o backend agrupa itens e não expõe a arquitetura do SO.
SOURCES = ('Win32_Process', 'Win32_Service', 'Get-ScheduledTask',
           'Registro:HKCU:Run', 'Registro:HKLM:Run',
           'Registro:HKCU:RunOnce', 'Registro:HKLM:RunOnce',
           'Startup:Usuário', 'Startup:Comum', 'Defender')
COVERAGE_STATES = ('Disponível', 'Parcial', 'Indisponível', 'Desconhecida')
UNKNOWN_ERROR = 'Erro de fonte não reconhecido; alcance desconhecido (conteúdo omitido).'
MISSING_REPORT = 'Relato de fontes ausente ou inválido.'
LEGACY = 'Baseline legado sem metadados de cobertura; substituição explícita necessária.'
DEFENDER_UNKNOWN = 'Defender:disponibilidade_nao_avaliada'
DEFENDER_MISSING = 'Defender:nao_disponivel'
STARTUP_UNKNOWN = 'Startup:pasta_nao_informada'
ERROR_MAP = {
    'Processos:usuario_indisponivel': (('Win32_Process',), 'Parcial'),
    'Processos:coleta_indisponivel': (('Win32_Process',), 'Indisponível'),
    'Servicos:coleta_indisponivel': (('Win32_Service',), 'Indisponível'),
    # foreach pode ter produzido parte das tarefas antes da exceção.
    'TarefasAgendadas:coleta_indisponivel': (('Get-ScheduledTask',), 'Parcial'),
    'Startup:atalhos_indisponiveis': (('Startup:Usuário', 'Startup:Comum'), 'Parcial'),
    'Startup:Usuário': (('Startup:Usuário',), 'Parcial'),
    'Startup:Comum': (('Startup:Comum',), 'Parcial'),
    'Defender:status_indisponivel': (('Defender',), 'Indisponível'),
}
for _hive in ('HKCU', 'HKLM'):
    for _kind in ('Run', 'RunOnce'):
        for _view in ('32-bit', '64-bit'):
            ERROR_MAP[f'Registro:{_hive}:{_view}:{_kind}'] = ((f'Registro:{_hive}:{_kind}',), 'Parcial')


def unknown_coverage(reason=LEGACY):
    return {'version': 1, 'sources': {name: {'state': 'Desconhecida', 'reasons': [reason]} for name in SOURCES}}


def coverage_from_result(result):
    """Somente códigos conhecidos são retidos; erros arbitrários nunca persistem."""
    errors = result.get('FontesIndisponiveis')
    if type(errors) is not list or len(errors) > 64 or any(type(e) is not str or len(e)>256 for e in errors):
        return unknown_coverage(MISSING_REPORT)
    sources = {name: {'state': 'Disponível', 'reasons': []} for name in SOURCES}
    unknown = False
    def mark(names, state, reason):
        for name in names:
            entry = sources[name]
            if COVERAGE_STATES.index(state) > COVERAGE_STATES.index(entry['state']):
                entry['state'] = state
            if reason not in entry['reasons']: entry['reasons'].append(reason)
    for error in errors:
        mapped = ERROR_MAP.get(error)
        if mapped is None:
            unknown = True
        else:
            names, state = mapped
            mark(names, state, error)
    defender = result.get('Defender')
    available = defender.get('Disponivel') if type(defender) is dict else None
    if available is False: mark(('Defender',), 'Indisponível', DEFENDER_MISSING)
    elif available is not True: mark(('Defender',), 'Desconhecida', DEFENDER_UNKNOWN)
    context = result.get('Contexto')
    for field, name in (('StartupUser', 'Startup:Usuário'), ('StartupCommon', 'Startup:Comum')):
        folder = context.get(field) if type(context) is dict else None
        if type(folder) is not str or not folder.strip():
            mark((name,), 'Desconhecida', STARTUP_UNKNOWN)
    if unknown: mark(SOURCES, 'Desconhecida', UNKNOWN_ERROR)
    return {'version': 1, 'sources': sources}


def coverage_complete(coverage):
    return all(entry['state'] == 'Disponível' for entry in coverage['sources'].values())


def required_sources(evidence):
    """Associações herdam a origem. Nunca usar classificação como cobertura."""
    kind = evidence.get('Tipo'); source = evidence.get('Fonte')
    associated = kind == 'Arquivo associado'
    if associated:
        kind = evidence.get('OrigemTipo')
        if source != f"Associado a {kind}: {evidence.get('OrigemNome')}": return ()
    direct = {'Processo': 'Win32_Process', 'Serviço': 'Win32_Service', 'Tarefa agendada': 'Get-ScheduledTask'}
    if kind in direct:
        return (direct[kind],) if associated or source == direct[kind] else ()
    scope = evidence.get('ContextoUsuario') or evidence.get('Usuario')
    if kind in ('Run', 'RunOnce') and scope in ('HKCU', 'HKLM'):
        if associated or (isinstance(source, str) and source.startswith(scope + ' / ')):
            return (f'Registro:{scope}:{kind}',)
    if kind == 'Startup' and scope in ('Usuário', 'Comum'):
        if associated or source == 'Pasta Startup': return (f'Startup:{scope}',)
    return ()


def coverage_gap(reference, evidence):
    names = required_sources(evidence)
    if not names: return 'Origem da evidência sem mapeamento seguro.'
    coverage = reference.get('coverage') or unknown_coverage()
    sources = coverage['sources']
    return '; '.join(f"{name}: {sources[name]['state']}" for name in names if sources[name]['state'] != 'Disponível')


def coverage_summary(coverage):
    counts = Counter(e['state'] for e in coverage['sources'].values())
    return ('Completo' if coverage_complete(coverage) else 'Parcial') + f" — {counts['Disponível']}/{len(SOURCES)} fontes disponíveis; " + ', '.join(f'{counts[s]} {s.lower()}' for s in COVERAGE_STATES[1:])


def coverage_reason_text(reason):
    labels = {
        'Processos:usuario_indisponivel': 'Usuário dos processos não pôde ser coletado integralmente',
        'Processos:coleta_indisponivel': 'Coleta de processos indisponível',
        'Servicos:coleta_indisponivel': 'Coleta de serviços indisponível',
        'TarefasAgendadas:coleta_indisponivel': 'Coleta de tarefas não concluída integralmente',
        'Startup:atalhos_indisponiveis': 'Resolução dos atalhos Startup indisponível',
        'Startup:Usuário': 'Leitura da pasta Startup do usuário não concluída integralmente',
        'Startup:Comum': 'Leitura da pasta Startup comum não concluída integralmente',
        'Defender:status_indisponivel': 'Consulta do estado do Defender indisponível',
        DEFENDER_MISSING: 'Defender não disponibilizou seu estado',
        DEFENDER_UNKNOWN: 'Disponibilidade do Defender não avaliada',
        STARTUP_UNKNOWN: 'Pasta Startup não informada pelo coletor',
    }
    if reason.startswith('Registro:') and reason in ERROR_MAP:
        _, hive, view, kind = reason.split(':')
        return f'Leitura {kind} de {hive}, visão {view}, não concluída [{reason}]'
    return f'{labels[reason]} [{reason}]' if reason in labels else reason


def coverage_details(coverage):
    return '\n'.join(f"{name}: {entry['state']}" + (' — ' + '; '.join(coverage_reason_text(r) for r in entry['reasons']) if entry['reasons'] else ' — sem falha reportada pelo coletor')
                     for name, entry in coverage['sources'].items())


def validate_coverage(coverage):
    if type(coverage) is not dict or set(coverage) != {'version', 'sources'} or type(coverage['version']) is not int or coverage['version'] != 1:
        raise BaselineError('Versão/formato de cobertura inválido.')
    sources = coverage['sources']
    if type(sources) is not dict or set(sources) != set(SOURCES): raise BaselineError('Fontes de cobertura inválidas.')
    for name, entry in sources.items():
        if type(entry) is not dict or set(entry) != {'state', 'reasons'}: raise BaselineError('Cobertura de fonte inválida.')
        state = entry['state']; reasons = entry['reasons']
        allowed = {code for code, (names, _) in ERROR_MAP.items() if name in names} | {UNKNOWN_ERROR, MISSING_REPORT, LEGACY}
        if name == 'Defender': allowed |= {DEFENDER_UNKNOWN, DEFENDER_MISSING}
        if name.startswith('Startup:'): allowed.add(STARTUP_UNKNOWN)
        if type(state) is not str or state not in COVERAGE_STATES or type(reasons) is not list or len(reasons) > 16:
            raise BaselineError('Estado/limite de cobertura inválido.')
        if any(type(reason) is not str or reason not in allowed for reason in reasons) or len(set(reasons)) != len(reasons):
            raise BaselineError('Motivos de cobertura não permitidos.')
        if (state == 'Disponível') != (not reasons): raise BaselineError('Estado de cobertura inconsistente.')
    return coverage


def prepare(result, sanitize, cancel_callback=None):
    if type(result) is not dict or result.get('Sucesso') is not True or result.get('Cancelada') is not False:
        raise BaselineError('É necessária uma análise concluída com sucesso, não cancelada.')
    items=result.get('Itens')
    if type(items) is not list or len(items)>MAX_ITEMS: raise BaselineError('Lista inválida ou limite de 3000 itens excedido.')
    coverage=coverage_from_result(result)
    records=[]
    for item in items:
        stopped(cancel_callback);records.append(snapshot(item,sanitize))
    return {'complete':coverage_complete(coverage),'coverage':coverage,'records':records}


def can_reference(result):
    return (type(result) is dict and result.get('Sucesso') is True and result.get('Cancelada') is False
            and type(result.get('Itens')) is list and len(result['Itens'])<=MAX_ITEMS
            and all(type(item) is dict for item in result['Itens']))


def compare(reference, current, cancel_callback=None):
    """O(n) por grupos; duplicatas dos dois lados nunca são pareadas à força."""
    old=reference['records'];new=current['records'];a=defaultdict(list);b=defaultdict(list)
    for i,record in enumerate(old):a[record['key']].append(i)
    for i,record in enumerate(new):b[record['key']].append(i)
    weak_old={old[i]['evidence']['Tipo'] for i in a.get(None,[])}
    weak_new={new[i]['evidence']['Tipo'] for i in b.get(None,[])}
    rows=[]
    def row(state,oi=None,ni=None,reason='',changes=None):
        rows.append({'state':state,'before':old[oi]['evidence'] if oi is not None else None,
                     'after':new[ni]['evidence'] if ni is not None else None,'index':ni,
                     'reason':reason,'changes':changes or []})
    for key in dict.fromkeys([*b,*a]):
        stopped(cancel_callback);left=a.get(key,[]);right=b.get(key,[])
        if key is None or len(left)>1 or len(right)>1:
            reason='Identidade insuficiente ou duplicada; pareamento não confirmado.'
            for i in right:row('Indeterminado',ni=i,reason=reason)
            for i in left:row('Indeterminado',oi=i,reason=reason)
            continue
        if not left:
            i=right[0];kind=new[i]['evidence']['Tipo']
            gap=coverage_gap(reference,new[i]['evidence'])
            safe=not gap and kind not in weak_old and None not in weak_old
            row('Novo' if safe else 'Indeterminado',ni=i,reason='Não observado na referência; não implica ameaça.' if safe else ('Baseline sem cobertura suficiente nesta fonte; novidade não confirmada. '+gap) if gap else 'Identidade insuficiente na referência; novidade não confirmada.')
        elif not right:
            i=left[0];kind=old[i]['evidence']['Tipo']
            gap=coverage_gap(current,old[i]['evidence'])
            safe=not gap and kind not in weak_new and None not in weak_new
            row('Ausente' if safe else 'Indeterminado',oi=i,reason='Não observado nesta coleta; não confirma remoção.' if safe else ('Fonte atual sem cobertura suficiente; ausência não confirmada. '+gap) if gap else 'Identidade atual insuficiente; ausência não confirmada.')
        else:
            oi,ni=left[0],right[0];before=old[oi]['evidence'];after=new[ni]['evidence']
            changes=[(field,before[field],after[field]) for field in sorted(FIELDS)
                     if before[field] is not None and after[field] is not None and before[field]!=after[field]]
            gaps=any((before[f] is None)!=(after[f] is None) for f in FIELDS)
            # Metadados básicos ausentes dos dois lados não atestam estabilidade do arquivo.
            basic=all(e['Existe'] is not None and (e['Existe'] is False or
                      (e['TamanhoBytes'] is not None and e['ModificadoUtc'] is not None)) for e in (before,after))
            nonexec=all(e['Tipo']=='Tarefa agendada' and e['TipoAcao'] and e['TipoAcao'].casefold()!='exec' for e in (before,after))
            if changes:state='Alterado';reason='Diferenças em evidências disponíveis.'
            elif gaps or not (basic or nonexec):state='Indeterminado';reason='Evidências incompletas ou disponibilidade diferente; estabilidade não confirmada.'
            else:state='Sem alteração';reason='Sem alteração nas evidências disponíveis; não comprova legitimidade.'
            if changes and gaps:reason+=' Outros campos têm cobertura diferente.'
            row(state,oi,ni,reason,changes)
    counts=Counter(row['state'] for row in rows)
    return {'rows':rows,'counts':{state:counts[state] for state in STATES}}


def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise BaselineError('JSON com campos duplicados; arquivo preservado.')
        result[key]=value
    return result


def validate(document, sanitize):
    if type(document) is not dict or set(document)!={'schema','scopes'} or type(document['schema']) is not int or document['schema'] not in (1,SCHEMA):
        raise BaselineError('Schema de baseline inválido ou incompatível; arquivo preservado.')
    legacy=document['schema']==1
    scopes=document['scopes']
    if type(scopes) is not dict or len(scopes)>MAX_SCOPES: raise BaselineError('Limite/formato de escopos inválido.')
    total=0
    for scope,reference in scopes.items():
        if not re.fullmatch('[0-9a-f]{64}',scope):raise BaselineError('Escopo inválido.')
        if type(reference) is not dict or set(reference)!=({'created','updated','complete','records'} if legacy else {'created','updated','complete','coverage','records'}):raise BaselineError('Referência inválida.')
        for field in ('created','updated'):
            try:
                value=reference[field]
                if type(value) is not str or len(value)>40 or datetime.fromisoformat(value).tzinfo is None:raise ValueError()
            except (TypeError,ValueError):raise BaselineError('Data de referência inválida.') from None
        if legacy:
            if reference['complete'] is not True:raise BaselineError('Referência legada inválida.')
        else:
            validate_coverage(reference['coverage'])
            if type(reference['complete']) is not bool or reference['complete'] != coverage_complete(reference['coverage']):
                raise BaselineError('Cobertura global inconsistente.')
        records=reference['records']
        if type(records) is not list or len(records)>MAX_ITEMS:raise BaselineError('Limite/formato de registros inválido.')
        total+=len(records)
        if total>MAX_TOTAL:raise BaselineError('Limite total de registros excedido.')
        for record in records:
            if type(record) is not dict or set(record)!={'key','fingerprint','evidence'}:raise BaselineError('Registro inválido.')
            e=record['evidence']
            if type(e) is not dict or set(e)!=FIELDS:raise BaselineError('Campos de evidência não permitidos.')
            normalized=snapshot(e,sanitize)
            if record!=normalized:raise BaselineError('Evidência ou fingerprint inválida; arquivo preservado.')
    if legacy:
        # Normalização somente em memória. Nenhuma escrita ao carregar. Outros
        # escopos mantêm cobertura desconhecida na próxima substituição explícita.
        return {'schema':SCHEMA,'scopes':{scope:{**ref,'complete':False,'coverage':unknown_coverage()} for scope,ref in scopes.items()}}
    return document


def _regular(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or getattr(info,'st_file_attributes',0)&0x400:
        raise BaselineError('Link ou arquivo não regular recusado; preservado.')


@contextmanager
def safe_directory(path, create=False):
    """Ancestres sem links; POSIX usa dir_fd; Windows prende diretórios sem DELETE share."""
    path=Path(path).absolute();held=[];fd=None
    try:
        if os.name=='nt':
            import ctypes
            from ctypes import wintypes as w
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            kernel.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE]
            kernel.CreateFileW.restype=w.HANDLE
            kernel.CloseHandle.argtypes=[w.HANDLE]
            class Info(ctypes.Structure):
                _fields_=[('attributes',w.DWORD),('created',w.FILETIME),('accessed',w.FILETIME),('written',w.FILETIME),('volume',w.DWORD),('high',w.DWORD),('low',w.DWORD),('links',w.DWORD),('indexhigh',w.DWORD),('indexlow',w.DWORD)]
            kernel.GetFileInformationByHandle.argtypes=[w.HANDLE,ctypes.POINTER(Info)]
            for directory in reversed((path,*path.parents)):
                if create and not directory.exists():directory.mkdir(mode=0o700)
                handle=kernel.CreateFileW(str(directory),0,3,None,3,0x02200000,None)
                if handle==w.HANDLE(-1).value:raise ctypes.WinError(ctypes.get_last_error())
                held.append(handle);info=Info()
                if not kernel.GetFileInformationByHandle(handle,ctypes.byref(info)):raise ctypes.WinError(ctypes.get_last_error())
                if info.attributes&0x400 or not info.attributes&0x10:raise BaselineError('Link/junção de diretório recusado.')
            yield None
        else:
            fd=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY)
            for part in path.parts[1:]:
                if create:
                    try:os.mkdir(part,mode=0o700,dir_fd=fd)
                    except FileExistsError:pass
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=child
            yield fd
    finally:
        if fd is not None:os.close(fd)
        for handle in reversed(held):kernel.CloseHandle(handle)


class BaselineStore:
    def __init__(self, root, scope, sanitize, logger):
        if not re.fullmatch('[0-9a-f]{64}',scope):raise BaselineError('Escopo local inválido.')
        self.path=PortablePaths(root).root/BASELINE_DEFENSIVO_RELATIVO
        self.scope=scope;self.sanitize=sanitize;self.logger=logger

    def _read(self, directory):
        name=str(self.path) if directory is None else self.path.name
        try:
            info=os.stat(name,dir_fd=directory,follow_symlinks=False);_regular(info)
            flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0)
            fd=self._windows_read_fd(name) if os.name=='nt' else os.open(name,flags,dir_fd=directory)
        except FileNotFoundError:return None
        with os.fdopen(fd,'rb') as stream:
            actual=os.fstat(stream.fileno());_regular(actual)
            if not os.path.samestat(info,actual):raise BaselineError('Arquivo mudou durante a leitura.')
            raw=stream.read(MAX_BYTES+1)
        if len(raw)>MAX_BYTES:raise BaselineError('Baseline excede 8 MiB; arquivo preservado.')
        return raw

    @staticmethod
    def _windows_read_fd(name):
        # Abrir o próprio reparse point em vez de seguir uma troca concorrente.
        import ctypes, msvcrt
        from ctypes import wintypes as w
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE]
        api.CreateFileW.restype=w.HANDLE
        api.CloseHandle.argtypes=[w.HANDLE]
        api.GetFileInformationByHandle.argtypes=[w.HANDLE,w.LPVOID]
        handle=api.CreateFileW(name,0x80000000,3,None,3,0x00200000,None)
        if handle==w.HANDLE(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        try:
            info=ctypes.create_string_buffer(52)
            if not api.GetFileInformationByHandle(handle,info):raise ctypes.WinError(ctypes.get_last_error())
            attributes=int.from_bytes(info.raw[:4],'little')
            if attributes&0x400 or attributes&0x10:raise BaselineError('Link/arquivo inválido recusado.')
            fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
            handle=None
            return fd
        finally:
            if handle is not None:api.CloseHandle(handle)

    def _decode(self, raw):
        if raw is None:return {'schema':SCHEMA,'scopes':{}}
        try:
            document=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,
                                parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
            return validate(document,self.sanitize)
        except (UnicodeError,ValueError,TypeError,RecursionError):
            raise BaselineError('Baseline inválido/incompatível; comparação e escrita bloqueadas. Arquivo preservado.') from None

    def load(self):
        try:
            try:
                with safe_directory(self.path.parent) as directory:raw=self._read(directory)
            except FileNotFoundError:raw=None
            document=self._decode(raw);reference=document['scopes'].get(self.scope)
            state='disponível' if reference is not None else ('incompatível' if document['scopes'] else 'inexistente')
            return {'state':state,'reference':reference,'token':hashlib.sha256(raw).hexdigest() if raw is not None else None,
                    'other_scopes':len(document['scopes'])-(1 if reference else 0)}
        except (OSError,ValueError):
            self.logger.warning('BASELINE_LEITURA_RECUSADA | sem conteúdo sensível')
            raise BaselineError('Baseline inacessível, inválido ou link; arquivo preservado. Consulte o log.') from None

    def save(self, prepared, expected, *, explicit=False, replace=False, cancel_callback=None):
        if explicit is not True:raise BaselineError('Criação exige ação explícita.')
        if type(prepared) is not dict or set(prepared)!={'complete','coverage','records'}:
            raise BaselineError('Referência exige resultado preparado com cobertura explícita.')
        temp=None;owned_lock=False
        try:
            with safe_directory(self.path.parent,create=True) as directory:
                def target(name):return str(self.path.parent/name) if directory is None else name
                lock=target(self.path.name+'.lock')
                fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=directory);os.close(fd);owned_lock=True
                try:
                    raw=self._read(directory);document=self._decode(raw)
                    token=hashlib.sha256(raw).hexdigest() if raw is not None else None
                    if token!=expected:raise BaselineError('Baseline mudou em outra instância; recarregue antes de salvar.')
                    prior=document['scopes'].get(self.scope)
                    if prior is not None and replace is not True:raise BaselineError('Substituição exige confirmação explícita.')
                    now=datetime.now(timezone.utc).isoformat(timespec='seconds')
                    document['scopes'][self.scope]={'created':prior['created'] if prior else now,'updated':now,**prepared}
                    validate(document,self.sanitize)
                    data=json.dumps(document,ensure_ascii=True,sort_keys=True,allow_nan=False).encode()
                    if len(data)>MAX_BYTES:raise BaselineError('Baseline excede limite de armazenamento.')
                    stopped(cancel_callback)
                    temp=target('.baseline-'+uuid.uuid4().hex+'.tmp')
                    fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=directory)
                    with os.fdopen(fd,'wb') as stream:
                        if raw is not None and os.name!='nt':os.fchmod(stream.fileno(),stat.S_IMODE(os.stat(target(self.path.name),dir_fd=directory,follow_symlinks=False).st_mode)&0o777)
                        stream.write(data);stream.flush();os.fsync(stream.fileno())
                    if raw is not None and os.name=='nt':self._copy_dacl(str(self.path),temp)
                    stopped(cancel_callback)
                    if self._read(directory)!=raw:raise BaselineError('Conflito antes da gravação; arquivo anterior preservado.')
                    os.replace(temp,target(self.path.name),src_dir_fd=directory,dst_dir_fd=directory);temp=None
                    self.logger.info('BASELINE_SALVO | referência temporal; não altera classificação/triagem')
                finally:
                    if temp is not None:
                        try:os.unlink(temp,dir_fd=directory)
                        except OSError:self.logger.warning('BASELINE_TEMPORARIO_PROPRIO_PRESERVADO')
                    if owned_lock:os.unlink(lock,dir_fd=directory)
            return self.load()
        except (OSError,ValueError):
            self.logger.warning('BASELINE_GRAVACAO_RECUSADA | estado anterior preservado quando não confirmado')
            raise BaselineError('Baseline não confirmado. Recarregue; verifique cobertura, conflito, limite e permissões. Nenhuma correção automática foi executada.') from None

    @staticmethod
    def _copy_dacl(source, target):
        import ctypes
        from ctypes import wintypes as w
        api=ctypes.WinDLL('advapi32',use_last_error=True);size=w.DWORD()
        api.GetFileSecurityW.argtypes=[w.LPCWSTR,w.DWORD,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
        api.SetFileSecurityW.argtypes=[w.LPCWSTR,w.DWORD,w.LPVOID]
        api.GetFileSecurityW(source,4,None,0,ctypes.byref(size))
        if not size.value:raise ctypes.WinError(ctypes.get_last_error())
        buffer=ctypes.create_string_buffer(size.value)
        if not api.GetFileSecurityW(source,4,buffer,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        control=w.WORD();revision=w.DWORD()
        api.GetSecurityDescriptorControl.argtypes=[w.LPVOID,ctypes.POINTER(w.WORD),ctypes.POINTER(w.DWORD)]
        if not api.GetSecurityDescriptorControl(buffer,ctypes.byref(control),ctypes.byref(revision)):raise ctypes.WinError(ctypes.get_last_error())
        flags=4 | (0x80000000 if control.value&0x1000 else 0x20000000)
        if not api.SetFileSecurityW(target,flags,buffer):raise ctypes.WinError(ctypes.get_last_error())
