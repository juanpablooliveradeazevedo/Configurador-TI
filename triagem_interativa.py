"""Revisão humana local, separada do motor defensivo. Nenhuma remediação."""
import hashlib
import ctypes
import json
import ntpath
import os
import re
import socket
import stat
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

AVALIACOES = (
    "Não revisado", "Legítimo", "Falso positivo", "Manter em observação",
    "Requer investigação", "Suspeito confirmado",
)
FILTROS = (
    "Todos", "Não revisados", "Revisados", "Com nota",
    "Com avaliação manual", "Priorizados",
)
FOCOS = (
    "Relevância / ordem original", "Severidade", "Nome", "Tipo",
    "Revisão técnica", "Prioridade técnica",
)
SEVERIDADES = (
    "Suspeito", "Requer análise", "Atenção", "Informativo", "Normal",
    "Não disponível",
)
LIMITE_NOTA = 500
LIMITE_BYTES = 2 * 1024 * 1024
LIMITE_REGISTROS = 3000


def texto_seguro(valor, sanitizar, limite=1200):
    """Texto simples, sem controles/bidi; usa o mascaramento aprovado."""
    texto = "".join(
        " " if unicodedata.category(c).startswith("C") else c
        for c in str(valor or "")[:12000]
    ).strip()
    return str(sanitizar(texto))[:limite] if texto else ""


def caminho_local(valor):
    """Validação puramente lexical: não abre UNC, drive relativo, ADS ou argumentos."""
    if not isinstance(valor, str) or not re.match(r"^[A-Za-z]:[\\/]", valor):
        return None
    if any(ord(c) < 32 or c in '\"<>|?*' for c in valor) or ":" in valor[2:]:
        return None
    partes = valor.replace("/", "\\").split("\\")[1:]
    if any(p in {"", ".", ".."} or p.endswith((" ", ".")) for p in partes):
        return None
    if any(re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", p) for p in partes):
        return None
    return ntpath.normpath(valor)


def identidade(item, escopo):
    """Digest de contexto + metadados da coleta, nunca apenas nome/PID.

    Não consulta disco nem calcula hash do arquivo. SHA sob demanda não muda
    esta chave; ausência de metadados suficientes implica revisão só na sessão.
    """
    caminho = caminho_local(item.get("Caminho"))
    tipo, nome = item.get("Tipo"), item.get("Nome")
    assinatura = item.get("Assinatura")
    modificado = str(item.get("ModificadoUtc") or "")
    tamanho = item.get("TamanhoBytes")
    if (not caminho or not tipo or not nome or item.get("Existe") is not True
            or type(tamanho) is not int or tamanho < 0
            or not re.match(r"^\d{4}-\d{2}-\d{2}T", modificado)
            or assinatura not in {"Válida", "Não assinada", "Inválida"}):
        return None
    publisher = str(item.get("Publisher") or "")
    if assinatura == "Válida" and publisher in {"", "—"}:
        return None
    # Proveniência diferencia serviço/tarefa/Run/Startup e usuários. O comando
    # JÁ sanitizado só participa do digest para distinguir invocações; nunca é
    # gravado em texto nem lido de ComandoOriginal. Não inclui PID/classificação.
    contexto = [
        escopo, tipo, nome, caminho.casefold(), assinatura, publisher, tamanho,
        modificado, item.get("CriadoUtc"), item.get("Comando"),
    ]
    contexto.extend(item.get(k) for k in (
        "Fonte", "ContextoUsuario", "Usuario", "NomeTecnico", "CaminhoTarefa",
        "TipoAcao", "ClassIdAcao", "ArquivoStartup", "OrigemTipo", "OrigemNome",
    ))
    return hashlib.sha256(json.dumps(contexto, ensure_ascii=True).encode()).hexdigest()


def validar_local_existente(valor):
    """Só após clique: recusa rede e reparse points antes de abrir Explorer."""
    caminho = caminho_local(valor)
    if os.name != "nt" or caminho is None:
        raise ValueError("Somente caminho local Windows.")
    raiz = caminho[:3]
    if ctypes.windll.kernel32.GetDriveTypeW(raiz) not in {2, 3, 5, 6}:
        raise ValueError("Unidade não local ou indisponível.")
    atual = raiz
    for parte in caminho[3:].split("\\"):
        atual = ntpath.join(atual, parte)
        info = os.lstat(atual)
        if getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Link/junção não é aberto pela triagem.")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Não é arquivo regular.")
    return caminho


def estado_vazio():
    return {"avaliacao": AVALIACOES[0], "nota": "", "prioridade": False, "atualizado": ""}


def revisado(estado):
    return bool(estado["avaliacao"] != AVALIACOES[0] or estado["nota"] or estado["prioridade"])


def bate_revisao(estado, filtro):
    return {
        "Todos": True, "Não revisados": not revisado(estado),
        "Revisados": revisado(estado), "Com nota": bool(estado["nota"]),
        "Com avaliação manual": estado["avaliacao"] != AVALIACOES[0],
        "Priorizados": estado["prioridade"],
    }.get(filtro, False)


def chave_foco(cache, estado, modo, linha):
    """Chave de mínimo calculada no passe hide/show; não ordena a tabela."""
    if modo == "Severidade":
        severidade = cache.get("classificacao", "")
        return (next((i for i, s in enumerate(SEVERIDADES) if s.casefold() == severidade), 6), linha)
    if modo in {"Nome", "Tipo"}:
        return (cache.get(modo.casefold(), ""), linha)
    if modo == "Revisão técnica":
        return (revisado(estado), linha)  # ainda não revisados primeiro
    return (not estado["prioridade"], linha)


class RevisoesLocais:
    """JSON limitado, atômico e conservador; erro não vira sucesso/whitelist."""

    def __init__(self, base, sanitizar, logger, candidatos=None, escopo=None):
        self.sanitizar, self.logger = sanitizar, logger
        self.candidatos = candidatos or [
            Path(base) / "triagem_tecnica.json",
            (Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA"))
             if os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
             else Path.home() / ".config") / "ConfiguradorTI" / "triagem_tecnica.json",
        ]
        # O mesmo pendrive não transfere decisões entre máquinas/usuários.
        self.escopo = escopo or hashlib.sha256("|".join((
            socket.gethostname(), os.environ.get("USERDOMAIN", ""),
            os.environ.get("USERNAME") or os.environ.get("USER", ""),
            os.environ.get("USERPROFILE") or str(Path.home()),
        )).encode()).hexdigest()
        self.registros = {}
        self.estados = {}
        self.identidades = {}
        self.caminho = None
        self.digest = None
        self.carregado = False
        self.erro = ""
        self.bloqueado = False

    def _ler(self, caminho):
        if caminho.is_symlink():
            raise ValueError("Arquivo de revisão é link; gravação recusada.")
        try:
            with caminho.open("rb") as arquivo:
                dados = arquivo.read(LIMITE_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(dados) > LIMITE_BYTES:
            raise ValueError("Arquivo de revisão excede o limite de 2 MiB.")
        return dados

    def _carregar(self):
        if self.carregado:
            return
        self.carregado = True
        try:
            for candidato in self.candidatos:
                dados = self._ler(candidato)
                if dados is None:
                    continue
                bruto = json.loads(dados)
                if not isinstance(bruto, dict) or bruto.get("schema") != 1 or not isinstance(bruto.get("registros"), dict):
                    raise ValueError("Formato de revisão inválido; original preservado.")
                registros = bruto["registros"]
                if len(registros) > LIMITE_REGISTROS:
                    raise ValueError("Limite de registros excedido.")
                for chave, estado in registros.items():
                    if (not re.fullmatch(r"[0-9a-f]{64}", chave)
                            or not isinstance(estado, dict)
                            or set(estado) != set(estado_vazio())
                            or estado.get("avaliacao") not in AVALIACOES
                            or not isinstance(estado.get("nota"), str)
                            or len(estado["nota"]) > LIMITE_NOTA
                            or type(estado.get("prioridade")) is not bool
                            or not isinstance(estado.get("atualizado"), str)
                            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", estado["atualizado"])):
                        raise ValueError("Registro de revisão inválido; original preservado.")
                    estado["nota"] = texto_seguro(estado["nota"], self.sanitizar, LIMITE_NOTA)
                self.registros = registros
                self.caminho, self.digest = candidato, hashlib.sha256(dados).digest()
                break
        except (OSError, ValueError, TypeError) as exc:
            self.erro = "Revisões não carregadas; arquivo preservado. Consulte o log."
            self.bloqueado = True
            self.logger.warning("Triagem: carga recusada (%s)", type(exc).__name__)

    def reaplicar(self, itens):
        self._carregar()
        self.estados, self.identidades = {}, {}
        chaves = [identidade(item, self.escopo) for item in itens]
        # Colisões dentro da coleta (ex.: duas ações indistinguíveis) não herdam.
        from collections import Counter
        contagens = Counter(chaves)
        for item, chave in zip(itens, chaves):
            chave = chave if chave and contagens[chave] == 1 else None
            self.identidades[id(item)] = chave
            self.estados[id(item)] = dict(self.registros.get(chave, estado_vazio()))

    def estado(self, item):
        return self.estados.get(id(item), estado_vazio())

    def alterar(self, item, avaliacao=None, nota=None, prioridade=None):
        anterior = self.estado(item)
        novo = dict(anterior)
        if avaliacao is not None:
            if avaliacao not in AVALIACOES:
                raise ValueError("Avaliação inválida.")
            novo["avaliacao"] = avaliacao
        if nota is not None:
            novo["nota"] = texto_seguro(nota, self.sanitizar, LIMITE_NOTA)
        if prioridade is not None:
            novo["prioridade"] = bool(prioridade)
        if novo == anterior:
            return "Revisão sem alteração."
        novo["atualizado"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.estados[id(item)] = novo
        chave = self.identidades.get(id(item))
        if not chave:
            return "Revisão apenas nesta sessão: identidade insuficiente ou ambígua."
        if self.bloqueado:
            return "Revisão apenas nesta sessão: armazenamento indisponível; consulte o log."
        propostos = dict(self.registros)
        if revisado(novo):
            propostos[chave] = novo
        else:
            propostos.pop(chave, None)
        try:
            self._salvar(propostos)
            self.registros = propostos
            self.logger.info("Triagem: revisão salva; identidade=%s", chave[:12])
            return "Revisão técnica salva localmente (não altera a classificação automática)."
        except (OSError, ValueError) as exc:
            self.erro = "Há revisão não salva; mantida somente nesta sessão. Consulte o log."
            self.registros = propostos
            self.logger.warning("Triagem: gravação não concluída (%s)", type(exc).__name__)
            return "Revisão apenas nesta sessão: não foi salva. Consulte o log e reabra para tentar novamente."

    def _salvar(self, registros):
        if len(registros) > LIMITE_REGISTROS:
            raise ValueError("Limite de revisões atingido; nada foi descartado.")
        dados = json.dumps({"schema": 1, "registros": registros}, ensure_ascii=True).encode()
        if len(dados) > LIMITE_BYTES:
            raise ValueError("Limite de armazenamento atingido.")
        candidatos = [self.caminho] if self.caminho else self.candidatos
        for indice, caminho in enumerate(candidatos):
            temporario = None
            try:
                caminho.parent.mkdir(parents=True, exist_ok=True)
                atual = self._ler(caminho)
                if (hashlib.sha256(atual).digest() if atual is not None else None) != self.digest:
                    self.bloqueado = True
                    raise ValueError("Revisões mudaram em outra instância; escrita recusada.")
                # Lock exclusivo e curto, sem esperas. Nunca apagar lock de outra instância.
                lock = caminho.with_name(caminho.name + ".lock")
                with lock.open("x"):
                    pass  # Fechar handle antes do unlink também funciona em Windows.
                try:
                    atual = self._ler(caminho)
                    if (hashlib.sha256(atual).digest() if atual is not None else None) != self.digest:
                        self.bloqueado = True
                        raise ValueError("Conflito de revisão.")
                    with tempfile.NamedTemporaryFile(dir=caminho.parent, prefix=".triagem-", suffix=".tmp", delete=False) as arq:
                        temporario = Path(arq.name)
                        arq.write(dados)
                        arq.flush()
                        os.fsync(arq.fileno())
                    os.replace(temporario, caminho)
                    temporario = None
                finally:
                    lock.unlink()
                self.caminho, self.digest = caminho, hashlib.sha256(dados).digest()
                self.erro = ""
                return
            except PermissionError:
                if self.caminho or indice == len(candidatos) - 1:
                    raise
                self.logger.warning("Triagem: pasta principal sem escrita; usando fallback do usuário.")
            finally:
                if temporario is not None:
                    try:
                        temporario.unlink()
                    except OSError:
                        self.logger.warning("Triagem: arquivo temporário próprio não removido.")


def detalhes_copiaveis(item, estado, sanitizar):
    """Whitelist de campos de saída; não copia Comando/SHA nem o painel inteiro."""
    linhas = [f"{rotulo}: {texto_seguro(item.get(chave), sanitizar) or '—'}" for rotulo, chave in (
        ("Classificação automática", "Classificacao"), ("Tipo", "Tipo"),
        ("Nome", "Nome"), ("PID", "PID"), ("Caminho/alvo", "CaminhoExibicao"),
        ("Assinatura", "Assinatura"), ("Publisher", "Publisher"),
        ("Motivo principal", "MotivoPrincipal"),
    )]
    linhas.extend((
        "Avaliação técnica: " + estado["avaliacao"],
        "Status de revisão: " + ("Revisado" if revisado(estado) else "Não revisado"),
        "Prioridade técnica: " + ("Sim" if estado["prioridade"] else "Não"),
        "Nota: " + texto_seguro(estado["nota"], sanitizar, LIMITE_NOTA),
        "Última revisão (UTC): " + estado["atualizado"],
    ))
    return "\n".join(linhas)


def resumo_investigacao(itens, revisoes):
    linhas = ["CONFIGURADOR TI — RESUMO DA INVESTIGAÇÃO", f"Total: {len(itens)}", "Análise automática:"]
    linhas.extend(f"- {s}: {sum(i.get('Classificacao') == s for i in itens)}" for s in SEVERIDADES)
    estados = [revisoes.estado(i) for i in itens]
    linhas.extend(("", "Revisão técnica:", f"- Não revisados: {sum(not revisado(e) for e in estados)}"))
    linhas.extend(f"- {s}: {sum(e['avaliacao'] == s for e in estados)}" for s in AVALIACOES[1:])
    linhas.extend((f"- Priorizados: {sum(e['prioridade'] for e in estados)}", "", "Itens com revisão técnica:"))
    for item, estado in zip(itens, estados):
        if revisado(estado):
            linhas.extend((detalhes_copiaveis(item, estado, revisoes.sanitizar), ""))
    linhas.append("Decisões humanas não substituem a classificação automática. Sem comandos ou hashes.")
    return "\n".join(linhas)
