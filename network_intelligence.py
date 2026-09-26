"""Configurador TI Network Intelligence: metadados locais, sem remediação ou elevação.

Providers retornam evidências, nunca um booleano "IP livre". Módulo sem Qt.
"""
from hostname_identification import NetBIOSProvider, metadata
import copy
import ctypes
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import struct
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from datetime import datetime, timezone

LOG = logging.getLogger("ConfiguradorTI.Network")
PORTS = (80, 443, 445, 3389, 22, 9100, 631, 515)
STATES = ("Em uso agora", "Conhecido, atualmente offline", "Reservado",
          "Provavelmente em uso", "Candidato a livre", "Desconhecido")
MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 8192
# Política conservadora centralizada, configurável por integração sem mudar
# providers. Histórico antigo nunca expira para transformar conhecido em livre.
DEFAULT_POLICY = {"fresh_minutes": 5, "recent_days": 2, "relevant_days": 30}


def clean(value, limit=300):
    """Texto simples, sem controles, URLs ou campos de segredo nas observações."""
    text = re.sub(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", " ", str(value or ""))
    text = re.sub(r"(?i)(?:https?|ftp)://\S+", "[URL omitida]", text)
    text = re.sub(r"(?i)\b(password|senha|token|secret)\s*[:=]\s*\S+", r"\1=[omitido]", text)
    return text.strip()[:limit]


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def age_days(timestamp, now=None):
    try:
        stamp = datetime.fromisoformat(timestamp)
        if stamp.tzinfo is None:
            return float("inf")
        return max(0, ((now or datetime.now(timezone.utc)) - stamp).total_seconds() / 86400)
    except (TypeError, ValueError):
        return float("inf")


def mac(value):
    compact = re.sub(r"[:-]", "", str(value or "").strip())
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        return ""
    if int(compact[:2], 16) & 1 or int(compact, 16) == 0:
        return ""
    return ":".join(compact[i:i+2] for i in range(0, 12, 2)).upper()


def scope_id(context, site):
    site = clean(site, 100).casefold()
    if not site:
        raise ValueError("Informe uma identificação exclusiva da rede/cliente.")
    keys = [site, context["Rede"], context.get("Gateway", ""),
            context.get("InterfaceGuid", ""), context.get("Profile", ""),
            socket.gethostname().casefold()]
    return hashlib.sha256(json.dumps(keys, ensure_ascii=True).encode()).hexdigest()


def evidence(provider, status="ok", strength=0, **data):
    return {"provider": provider, "status": status, "strength": strength,
            "observed_at": utc(), **data}


class HistoryStore:
    """Lock exclusivo + leitura atualizada sob lock + replace atômico.

    Corrupção/limites/conflitos bloqueiam escrita sem apagar o original.
    Nenhuma leitura ou escrita é feita em repaint da GUI.
    """
    def __init__(self, base_dir, fallback=None):
        self.paths = [Path(base_dir) / "inteligencia_rede.json"]
        fallback = fallback or os.environ.get("LOCALAPPDATA")
        if fallback:
            self.paths.append(Path(fallback) / "ConfiguradorTI" / "inteligencia_rede.json")

    def read(self):
        for path in self.paths:
            try:
                path.stat()
            except FileNotFoundError:
                continue
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Histórico acima do limite; arquivo preservado.")
            value = json.loads(raw)
            if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("scopes"), dict):
                raise ValueError("Histórico inválido ou incompatível; arquivo preservado.")
            count = 0
            for key, scope in value["scopes"].items():
                if not re.fullmatch(r"[a-f0-9]{64}", key) or not isinstance(scope, dict):
                    raise ValueError("Escopo inválido; histórico preservado.")
                records = scope.get("records")
                if not isinstance(records, dict):
                    raise ValueError("Registros inválidos; histórico preservado.")
                count += len(records)
                for ip, record in records.items():
                    ipaddress.ip_address(ip)
                    if not isinstance(record, dict) or record.get("ip") != ip:
                        raise ValueError("Identidade inválida no histórico.")
                    if not isinstance(record.get("events", []), list) or not isinstance(record.get("macs", []), list):
                        raise ValueError("Eventos inválidos no histórico.")
                    for name in ("evidence", "hostnames", "ports"):
                        if not isinstance(record.get(name, []), list):
                            raise ValueError("Coleção inválida no histórico; arquivo preservado.")
                    for ev in record.get("evidence", []):
                        if not isinstance(ev, dict) or not isinstance(ev.get("provider"), str) or ev.get("status") not in ("ok", "error", "unavailable", "cancelled", "not_queried"):
                            raise ValueError("Evidência inválida no histórico; arquivo preservado.")
                    identities = record.get("identifications", [])
                    if not isinstance(identities, list) or len(identities)>64 or any(not isinstance(v, dict) or any(not isinstance(v.get(k,""),str) for k in ("name","source","observed_at","confidence","mac")) for v in identities):
                        raise ValueError("Identificação inválida; histórico preservado.")
                    if record.get("reservation") is not None and not isinstance(record["reservation"], dict):
                        raise ValueError("Reserva inválida no histórico; arquivo preservado.")
                    if not all(isinstance(v, str) for v in record.get("hostnames", []) + record.get("macs", [])):
                        raise ValueError("Identidade inválida no histórico; arquivo preservado.")
            if count > MAX_RECORDS:
                raise ValueError("Limite de registros atingido; histórico preservado.")
            return value, path
        return {"schema": 1, "scopes": {}}, None

    def transaction(self, change):
        _, existing = self.read()
        candidates = [existing] if existing else self.paths
        last = None
        for path in candidates:
            lock = path.with_suffix(".lock")
            fd = None
            tmp = None
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                # Outra instância pode ter criado o fallback enquanto aguardávamos.
                data, current = self.read()
                if current is not None and current != path:
                    raise RuntimeError("Histórico mudou de local; atualize antes de repetir.")
                change(data)
                if sum(len(s["records"]) for s in data["scopes"].values()) > MAX_RECORDS:
                    raise ValueError("Limite de registros atingido; nada foi descartado.")
                payload = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
                if len(payload) > MAX_BYTES:
                    raise ValueError("Limite de histórico atingido; nada foi descartado.")
                with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".configurador_ti_net_", delete=False) as out:
                    tmp = Path(out.name)
                    out.write(payload)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(tmp, path)
                LOG.info("NETWORK_HISTORY_SAVED | local=%s", path)
                return data
            except FileExistsError as exc:
                raise RuntimeError("Histórico ocupado por outra instância (lock); tente novamente.") from exc
            except OSError as exc:
                last = exc
                if existing or path.exists():
                    raise
                LOG.warning("NETWORK_HISTORY_FALLBACK | %s", type(exc).__name__)
            finally:
                if tmp and tmp.exists():
                    tmp.unlink()
                if fd is not None:
                    os.close(fd)
                    lock.unlink()
        raise OSError("Não foi possível persistir o histórico em nenhum local permitido.") from last


class ICMPProvider:
    name, timeout, kind, strength = "ICMP", .6, "resposta atual", 80

    def collect(self, ip, source, cancel):
        if cancel():
            return evidence(self.name, "cancelled")
        if os.name != "nt":
            return evidence(self.name, "unavailable", error="Requer Windows")
        try:
            # DLL integrante do Windows; nunca carregada do pendrive/PATH.
            api = ctypes.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x800)
            api.IcmpCreateFile.restype = ctypes.c_void_p
            api.IcmpCreateFile.argtypes = []
            api.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
            api.IcmpSendEcho2Ex.argtypes = [ctypes.c_void_p] * 4 + [ctypes.c_uint32] * 2 + [ctypes.c_void_p, ctypes.c_ushort, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
            api.IcmpSendEcho2Ex.restype = ctypes.c_uint32
            handle = api.IcmpCreateFile()
            if handle in (None, ctypes.c_void_p(-1).value):
                raise OSError(ctypes.get_last_error(), "IcmpCreateFile")
            try:
                reply = ctypes.create_string_buffer(256)
                request = ctypes.create_string_buffer(b"ping")
                count = api.IcmpSendEcho2Ex(handle, None, None, None,
                    struct.unpack("=I", socket.inet_aton(source))[0],
                    struct.unpack("=I", socket.inet_aton(ip))[0], request, 4, None, reply, 256, 600)
                if not count:
                    code = ctypes.get_last_error()
                    return evidence(self.name, "ok" if code == 11010 else "error", responded=False, error="" if code == 11010 else str(code))
                address, status, rtt = struct.unpack_from("=III", reply.raw)
                responded = status == 0 and address == struct.unpack("=I", socket.inet_aton(ip))[0]
                return evidence(self.name, "ok" if status in (0, 11010) else "error",
                                self.strength if responded else 0, responded=responded,
                                latency_ms=rtt if responded else None, error="" if responded else str(status))
            finally:
                api.IcmpCloseHandle(handle)
        except (OSError, AttributeError) as exc:
            return evidence(self.name, "error", error=clean(exc))


class TCPProvider:
    name, timeout, kind, strength = "TCP", .35, "resposta atual", 90

    def collect(self, ip, source, cancel, interface_index=None):
        ports, responded, errors = [], False, []
        for port in PORTS:
            if cancel():
                return evidence(self.name, "cancelled")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.bind((source, 0))
                    if os.name == "nt" and interface_index:
                        # IP_UNICAST_IF: índice em ordem de rede. Impede que
                        # uma rota sobreposta de VPN capture as conexões TCP.
                        sock.setsockopt(socket.IPPROTO_IP, 31, struct.pack("!I", int(interface_index)))
                    sock.connect((ip, port))
                    ports.append(port)
                    responded = True
            except ConnectionRefusedError:
                responded = True  # RST também é resposta; não abre sessão.
            except socket.timeout:
                pass
            except OSError as exc:
                errors.append(str(exc.errno))
        return evidence(self.name, "error" if errors else "ok", self.strength if responded else 0,
                        responded=responded, ports=ports, error=",".join(sorted(set(errors))))


class NeighborProvider:
    name, timeout, kind, strength = "ARP/Neighbor", 8, "cache da interface", 55

    def __init__(self, powershell):
        self.ps = powershell

    def collect(self, index):
        try:
            index = int(index)
            if index <= 0:
                raise ValueError("Interface inválida")
            script = f"Get-NetNeighbor -InterfaceIndex {index} -AddressFamily IPv4 -ErrorAction Stop | Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress"
            response = self.ps(script, timeout=self.timeout)
            if response.returncode:
                raise OSError(clean(response.stderr))
            rows = json.loads(response.stdout or "[]")
            rows = rows if isinstance(rows, list) else [rows]
            result = {}
            for row in rows:
                value = mac(row.get("LinkLayerAddress"))
                state = str(row.get("State", ""))
                state = {"0": "Unreachable", "1": "Incomplete", "2": "Probe", "3": "Delay", "4": "Stale", "5": "Reachable", "6": "Permanent"}.get(state, state)
                if value and state not in ("Incomplete", "Unreachable", "0", "1"):
                    result.setdefault(str(row.get("IPAddress")), []).append({"mac": value, "neighbor_state": state})
            return evidence(self.name, entries=result)
        except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
            return evidence(self.name, "unavailable", entries={}, error=clean(exc))


class DNSProvider:
    name, timeout, kind, strength = "Reverse DNS", 4, "nome indireto", 30

    def __init__(self, powershell):
        self.ps = powershell

    def collect(self, ip, server, cancel):
        if cancel():
            return evidence(self.name, "cancelled")
        if not server:
            return evidence(self.name, "unavailable", error="DNS da interface não disponível")
        # Ambos são IPs validados; nomes livres nunca são interpolados.
        ip, server = str(ipaddress.ip_address(ip)), str(ipaddress.ip_address(server))
        # IPv6 com zone ID pode conter aspas; preserve o literal PowerShell.
        ip, server = ip.replace("'", "''"), server.replace("'", "''")
        script = f"try {{$v=@(Resolve-DnsName -Name '{ip}' -Type PTR -Server '{server}' -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop); @($v | ForEach-Object {{$_.NameHost}}) | ConvertTo-Json -Compress}} catch {{ [pscustomobject]@{{error=$_.CategoryInfo.Category.ToString()}} | ConvertTo-Json -Compress }}"
        try:
            result = self.ps(script, timeout=self.timeout)
            if result.returncode:
                raise OSError(clean(result.stderr))
            value = json.loads(result.stdout or "[]")
            if isinstance(value, dict):
                return evidence(self.name, "unavailable", error=clean(value.get("error")))
            names = value if isinstance(value, list) else [value]
            names = [clean(n, 253) for n in names if isinstance(n, str) and n]
            return evidence(self.name, strength=30 if names else 0, hostname=names[0] if names else "")
        except (OSError, ValueError, RuntimeError) as exc:
            return evidence(self.name, "unavailable", error=clean(exc))


class FutureProvider:
    """Contrato opt-in futuro, sem transporte, credenciais ou autodiscovery."""
    timeout, strength, kind = 0, 0, "integração não configurada"

    def __init__(self, name):
        self.name = name

    def collect(self):
        return evidence(self.name, "unavailable", error="Não integrado nesta fase; nenhuma consulta realizada")


class HistoryProvider:
    name, timeout, kind, strength = "Histórico Configurador TI", 0, "evidência temporal local", 85

    def collect(self, previous, available):
        return evidence(self.name, "ok" if available else "unavailable",
                        self.strength if previous and previous.get("last_seen") else 0,
                        last_seen=(previous or {}).get("last_seen"),
                        error="" if available else "Histórico indisponível")


def active_reservation(record, now=None):
    reservation = record.get("reservation") or {}
    expiry = reservation.get("expires")
    if not reservation or reservation.get("removed"):
        return None
    if expiry:
        try:
            if datetime.fromisoformat(expiry) <= (now or datetime.now(timezone.utc)):
                return None
        except (ValueError, TypeError):
            return None
    return reservation


def consolidate(record, current=None, history_ok=True, now=None, policy=None):
    """Prioridades/recência determinísticas; silêncio nunca apaga o passado."""
    value = copy.deepcopy(record)
    policy = dict(DEFAULT_POLICY, **(policy or {}))
    ev = current if current is not None else value.get("evidence", [])
    recent_check = age_days(value.get("checked"), now) <= float(policy["fresh_minutes"]) / 1440
    strong = [e for e in ev if e.get("responded") and e["provider"] in ("ICMP", "TCP", "Local")]
    indirect = [e for e in ev if e.get("mac") or e.get("hostname")]
    reservation = active_reservation(value, now)
    old_age = age_days(value.get("last_seen"), now)
    score = max([e.get("strength", 0) for e in strong] or [0]) if recent_check else 0
    if reservation:
        state, score = "Reservado", 100
    elif strong and recent_check:
        state = "Em uso agora"
    elif indirect and recent_check:
        state, score = "Provavelmente em uso", 55
    elif value.get("last_seen"):
        state = "Conhecido, atualmente offline"
        score = 85 if old_age <= policy["recent_days"] else 70 if old_age <= policy["relevant_days"] else 40
    elif (history_ok and recent_check and value.get("complete") and not value.get("protected")
          and all(any(e["provider"] == p and e["status"] == "ok" for e in ev) for p in ("ICMP", "TCP", "ARP/Neighbor"))):
        state, score = "Candidato a livre", 50
    else:
        state, score = "Desconhecido", 20
    limitations = ["Ausência de resposta não garante IP livre. DHCP/leases e reservas externas não consultados."]
    if not history_ok:
        limitations.append("Histórico ou contexto não confirmado: não é seguro recomendar atribuição.")
    if not recent_check:
        limitations.append(f"Verificação atual vencida ({policy['fresh_minutes']} minutos); execute nova verificação antes de usar.")
    if state == "Conhecido, atualmente offline":
        limitations.append("Offline significa sem confirmação atual; pode estar ligado e filtrando sondas.")
    for e in ev:
        if e["status"] != "ok":
            limitations.append(f"{e['provider']}: {e['status']} — {clean(e.get('error'))}")
    if mac(value.get("mac")) and int(value["mac"][:2], 16) & 2:
        limitations.append("MAC administrado localmente: pode ser virtual ou aleatório.")
    alert = value.get("identity_alert", "")
    if alert:
        limitations.append("Troca de MAC pode ser substituição legítima ou reutilização DHCP; não prova conflito.")
    if alert and state == "Candidato a livre":
        state, score = "Desconhecido", 20
    value.update(state=state, score=score, confidence="Alta" if score >= 75 else "Média" if score >= 45 else "Baixa",
                 limitations=limitations, active_reservation=reservation,
                 recommendation="Candidato condicional: confirme DHCP/reservas com o responsável antes de atribuir."
                 if state == "Candidato a livre" else "Não recomendado para nova atribuição sem investigação.")
    return value


def observe(ip, context, previous, observations, complete=True, now=None):
    stamp = now or utc()
    value = copy.deepcopy(previous or {"ip": ip, "version": ipaddress.ip_address(ip).version,
        "first_seen": None, "last_seen": None, "last_online": None, "macs": [], "hostnames": [], "events": []})
    value.update(checked=stamp, evidence=observations, complete=complete,
                 network_scope_id=context.get("network_scope_id"),
                 network=context["Rede"], interface=context.get("Alias"), gateway=context.get("Gateway"),
                 protected=ip in (context.get("IPv4"), context.get("Gateway")))
    seen = any(e.get("responded") or e.get("mac") or e.get("hostname") for e in observations)
    online = any(e.get("responded") for e in observations)
    if seen:
        value["first_seen"] = value.get("first_seen") or stamp
        value["last_seen"] = stamp
    if online:
        value["last_online"] = stamp
    observed_macs = sorted({mac(e.get("mac")) for e in observations if mac(e.get("mac"))})
    prior_mac = value.get("mac")
    changes = []
    for address in observed_macs:
        if address not in value["macs"]:
            value["macs"].append(address)
        if prior_mac and address != prior_mac:
            changes.append(f"{prior_mac} → {address}")
    if observed_macs:
        value["mac"] = observed_macs[0] if len(observed_macs) == 1 else ""
    if changes or len(observed_macs) > 1:
        value["identity_alert"] = "Mudança de identidade / possível conflito"
        value["identity_change"] = {"at": stamp, "macs": sorted(set(observed_macs + ([prior_mac] if prior_mac else []))), "sources": [e["provider"] for e in observations if e.get("mac")]}
        LOG.info("NETWORK_IDENTITY_CHANGED | ip=%s", ip)
    for e in observations:
        name = clean(e.get("hostname"), 253)
        if name:
            value["hostname"] = name
            if name not in value["hostnames"]:
                value["hostnames"].append(name)
    value["ports"] = sorted({p for e in observations for p in e.get("ports", [])})
    value["type"] = "Impressora (inferido)" if set(value["ports"]) & {9100, 631, 515} else "Servidor/host (inferido)" if set(value["ports"]) & {445, 3389, 22} else "Desconhecido"
    value["manufacturer"] = "Não disponível — sem base OUI local"
    event = {"at": stamp, "kind": "Online" if online else "Evidência indireta" if seen else "Sem resposta atual",
             "macs": observed_macs, "hostname": value.get("hostname", ""), "sources": [e["provider"] for e in observations if e.get("responded") or e.get("mac") or e.get("hostname")]}
    value["events"] = (value["events"] + [event])[-64:]
    return value


class NetworkEngine:
    def __init__(self, base_dir, powershell, logger=None, inventory_path=None):
        self.store = HistoryStore(base_dir)
        self.ps = powershell
        self.logger = logger or LOG
        self.inventory_path = Path(inventory_path) if inventory_path else None
        self.icmp, self.tcp = ICMPProvider(), TCPProvider()
        self.neighbor, self.dns = NeighborProvider(powershell), DNSProvider(powershell)
        self.future = [FutureProvider(n) for n in ("DHCP", "mDNS/WSD", "SNMP/infraestrutura", "Agent heartbeat")]
        self.history = HistoryProvider()
        self.netbios = NetBIOSProvider()

    def context(self, interface):
        index = int(interface.get("InterfaceIndex", 0))
        if index <= 0:
            raise ValueError("Interface sem índice válido; atualize a lista.")
        script = f"""$a=Get-NetAdapter -InterfaceIndex {index} -ErrorAction Stop
$ips=@(Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 -ErrorAction Stop | Select-Object IPAddress,PrefixLength)
$g=@(Get-NetRoute -InterfaceIndex {index} -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1)
$p=@(Get-NetConnectionProfile -InterfaceIndex {index} -ErrorAction SilentlyContinue)
$dns=@(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
[pscustomobject]@{{Status=[string]$a.Status;Guid=[string]$a.InterfaceGuid;MAC=[string]$a.MacAddress;IPs=$ips;Gateway=if($g){{[string]$g[0].NextHop}}else{{''}};Profile=if($p){{[string]$p[0].Name}}else{{''}};DNS=@($dns)}} | ConvertTo-Json -Depth 5 -Compress
"""
        response = self.ps(script, timeout=10)
        if response.returncode:
            raise OSError("Falha ao revalidar interface: " + clean(response.stderr))
        data = json.loads(response.stdout)
        source = str(ipaddress.IPv4Address(interface["IPv4"]))
        address = ipaddress.ip_address(source)
        if address.is_link_local or address.is_loopback or address.is_unspecified or address.is_multicast or address.is_reserved or not address.is_private:
            raise ValueError("Interface APIPA/loopback/pública não elegível.")
        rows = data.get("IPs", [])
        rows = rows if isinstance(rows, list) else [rows]
        matched = next((r for r in rows if r.get("IPAddress") == source), None)
        if data.get("Status", "").lower() != "up" or not matched or not data.get("Guid"):
            raise ValueError("A interface mudou ou ficou inativa; atualize as interfaces.")
        prefix = int(matched["PrefixLength"])
        if prefix > 24:
            raise ValueError("Não expandimos a rede real para além de sua máscara.")
        network = ipaddress.ip_network(f"{source}/24", strict=False)
        if str(network) != interface.get("Rede"):
            raise ValueError("A rede selecionada mudou; atualize as interfaces.")
        context = dict(interface, IPv4=source, Rede=str(network), InterfaceGuid=data["Guid"],
                       Gateway=data.get("Gateway", ""), Profile=clean(data.get("Profile")), LocalMAC=mac(data.get("MAC")))
        context["DNS_servers"] = [str(ipaddress.ip_address(s)) for s in data.get("DNS", []) if s]
        return context

    def run(self, interface, site, focused_ip=None, history_only=False, progress_callback=None, cancel_callback=None):
        cancel = cancel_callback or (lambda: False)
        start = time.monotonic()
        if cancel():
            return {"Sucesso": False, "message": "Cancelado"}
        context = self.context(interface)
        before = self.neighbor.collect(context["InterfaceIndex"])
        gateways = before.get("entries", {}).get(context.get("Gateway"), [])
        context["GatewayMAC"] = gateways[0]["mac"] if len(gateways) == 1 else ""
        scope = scope_id(context, site)
        context["network_scope_id"] = scope
        network = ipaddress.ip_network(context["Rede"])
        if focused_ip:
            addr = ipaddress.ip_address(focused_ip)
            if addr not in network or addr in (network.network_address, network.broadcast_address):
                raise ValueError("IP fora dos hosts da /24 selecionada.")
            ips = [str(addr)]
        else:
            ips = [str(a) for a in network.hosts()]
        warnings = []
        history_ok = True
        try:
            history, _ = self.store.read()
        except (OSError, ValueError, TypeError) as exc:
            history, history_ok = {"scopes": {}}, False
            warnings.append("Histórico não acessível; original preservado: " + clean(exc))
        prior_scope = history["scopes"].get(scope, {})
        prior = prior_scope.get("records", {})
        old_gateway_mac = prior_scope.get("context", {}).get("GatewayMAC")
        if old_gateway_mac and context["GatewayMAC"] and old_gateway_mac != context["GatewayMAC"]:
            raise ValueError("Identidade do gateway mudou. Histórico preservado; confirme a rede/cliente e use um identificador distinto se for outra rede.")
        anchor_ok = not context.get("Gateway") or bool(context["GatewayMAC"])
        related = any(key != scope and value.get("site", "").casefold() == clean(site, 100).casefold()
                      and value.get("context", {}).get("Rede") == context["Rede"] for key, value in history["scopes"].items())
        ambiguous_context = bool(prior_scope.get("ambiguous_context") or related and not prior_scope)
        if ambiguous_context:
            anchor_ok = False
            warnings.append("Há contexto anterior com este identificador/CIDR, mas perfil ou interface mudou. Históricos não foram misturados; confirme a identidade antes de recomendar IPs.")
        if not anchor_ok:
            warnings.append("Contexto não confirmado (gateway/identidade): nenhum IP será recomendado como candidato.")
        if history_only:
            return {"Sucesso": history_ok, "scope": scope, "context": context, "site": clean(site, 100),
                    "records": [consolidate(r, history_ok=history_ok and anchor_ok) for r in prior.values()],
                    "unavailable": [p.collect() for p in self.future], "history_ok": history_ok and anchor_ok,
                    "warnings": warnings, "focused": False,
                    "message": f"{len(prior)} registros locais carregados. Nenhuma sonda ativa enviada. " + " ".join(warnings)}
        observations = {}
        identifications = {}
        self.logger.info("NETWORK_SCAN_START | rede=%s | interface=%s | hosts=%s", context["Rede"], context["Alias"], len(ips))

        def probe(ip):
            if ip == context["IPv4"]:
                return [evidence("Local", strength=100, responded=True, mac=context["LocalMAC"])]
            return [self.icmp.collect(ip, context["IPv4"], cancel), self.tcp.collect(ip, context["IPv4"], cancel, context["InterfaceIndex"])]

        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="configurador_ti_net") as pool:
            futures = {pool.submit(probe, ip): ip for ip in ips}
            for future in as_completed(futures):
                if cancel():
                    for pending in futures:
                        pending.cancel()
                    break
                ip = futures[future]
                try:
                    observations[ip] = future.result()
                except Exception as exc:
                    observations[ip] = [evidence("Coleta", "error", error=clean(exc))]
                if progress_callback:
                    progress_callback(int(70 * len(observations) / len(ips)), f"Verificados {len(observations)}/{len(ips)} IPs")
        if cancel():
            self.logger.info("NETWORK_SCAN_CANCELLED | sem persistência parcial")
            return {"Sucesso": False, "message": "Cancelado; histórico e reservas anteriores preservados."}
        after = self.neighbor.collect(context["InterfaceIndex"])
        new_gateway_macs = {row["mac"] for row in after.get("entries", {}).get(context.get("Gateway"), [])}
        if context["GatewayMAC"] and new_gateway_macs and new_gateway_macs != {context["GatewayMAC"]}:
            raise ValueError("Identidade do gateway mudou durante a coleta; resultados descartados. Revalide a rede/cliente.")
        for ip, items in observations.items():
            neighbors = before.get("entries", {}).get(ip, []) + after.get("entries", {}).get(ip, [])
            unique = {(n["mac"], n["neighbor_state"]) for n in neighbors}
            if unique:
                items.extend(evidence("ARP/Neighbor", strength=55, mac=m, neighbor_state=s) for m, s in sorted(unique))
            else:
                items.append(evidence("ARP/Neighbor", after["status"], error=after.get("error", "")))
        # PTR usa somente o DNS configurado na interface. Até quatro subprocessos.
        enrich = [ip for ip in ips if focused_ip or any(e.get("responded") or e.get("mac") for e in observations[ip])]
        server = next(iter(context["DNS_servers"]), "")
        def collect_identification(ip):
            try:
                dns = self.dns.collect(ip, server, cancel)
            except Exception as exc:
                dns = evidence("Reverse DNS", "unavailable", error=clean(exc))
            try:
                nb = self.netbios.collect(ip, context["IPv4"], cancel)
            except Exception as exc:
                self.logger.warning("NETWORK_IDENTIFICATION_UNAVAILABLE | %s", type(exc).__name__)
                nb = {"status":"unavailable", "names":[], "error":type(exc).__name__}
            return dns, nb

        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="configurador_ti_ptr") as pool:
            futures = {pool.submit(collect_identification, ip): ip for ip in enrich}
            for number, future in enumerate(as_completed(futures), 1):
                if cancel():
                    for pending in futures:
                        pending.cancel()
                    break
                ip = futures[future]
                try:
                    dns, nb = future.result()
                except Exception as exc:
                    dns, nb = evidence("Reverse DNS", "unavailable", error=clean(exc)), {"status":"unavailable","names":[]}
                observations[ip].append(dns)
                identifications[ip] = (dns, nb)
                if progress_callback:
                    progress_callback(70 + int(25 * number / max(1, len(enrich))), f"Nomes: {number}/{len(enrich)}")
        if cancel():
            return {"Sucesso": False, "message": "Cancelado; nenhuma gravação parcial."}
        # Nunca atribui evidências a um contexto que mudou durante a coleta.
        latest = self.context(interface)
        if any(latest.get(k) != context.get(k) for k in ("Rede", "IPv4", "Gateway", "InterfaceGuid", "Profile")):
            raise ValueError("A interface/rede mudou durante a coleta; resultados descartados por segurança.")
        if cancel():
            return {"Sucesso": False, "message": "Cancelado antes da gravação; histórico preservado."}
        for items in observations.values():
            if not any(e["provider"] == "Reverse DNS" for e in items):
                items.append(evidence("Reverse DNS", "not_queried", error="Sem indício atual; PTR será consultado na verificação focada"))
        for ip, items in observations.items():
            items.append(self.history.collect(prior.get(ip), history_ok))
        stamp = utc()
        records = {ip: observe(ip, context, prior.get(ip), ev, now=stamp) for ip, ev in observations.items()}
        def attach_identity(record, ip):
            dns, nb = identifications.get(ip, ({}, {"names":[]}))
            record["identifications"] = metadata(record.get("identifications", []), dns, nb, record.get("mac", ""), stamp)
            record["identification_checked"] = stamp
            record["identification_status"] = nb.get("status", "not_queried")
            return record
        for ip, record in records.items():
            attach_identity(record, ip)
        # Registro da infraestrutura nunca é candidato só por filtrar sondas.
        for record in records.values():
            if record.get("protected") and not record.get("last_seen"):
                record["first_seen"] = record["last_seen"] = stamp
        if history_ok:
            def merge(data):
                target = data["scopes"].setdefault(scope, {"site": clean(site, 100), "context": context, "records": {}})
                target["ambiguous_context"] = ambiguous_context
                previous_anchor = target.get("context", {}).get("GatewayMAC")
                if previous_anchor and context["GatewayMAC"] and previous_anchor != context["GatewayMAC"]:
                    raise RuntimeError("Outra instância registrou um gateway diferente; histórico não foi misturado.")
                # Não perde a âncora conhecida quando o cache do gateway esvazia.
                if context["GatewayMAC"]:
                    target["context"] = context
                for ip, ev in observations.items():
                    # Rebase sob lock: não sobrescreve reservas/notas de outra instância.
                    target["records"][ip] = attach_identity(observe(ip, context, target["records"].get(ip), ev, now=stamp), ip)
                    records[ip] = copy.deepcopy(target["records"][ip])
            try:
                self.store.transaction(merge)
            except (OSError, ValueError, RuntimeError) as exc:
                history_ok = False
                warnings.append("Coleta concluída, mas histórico NÃO salvo: " + clean(exc))
                self.logger.warning("NETWORK_HISTORY_FAILED | %s", clean(exc))
        result = {"Sucesso": True, "scope": scope, "context": context, "site": clean(site, 100),
                  "records": [consolidate(records[ip], history_ok=history_ok and anchor_ok) for ip in ips],
                  "providers": [{"name": p.name, "timeout": p.timeout, "kind": p.kind, "strength": p.strength} for p in (self.icmp, self.tcp, self.neighbor, self.dns, self.history)],
                  "unavailable": [p.collect() for p in self.future], "history_ok": history_ok and anchor_ok,
                  "warnings": warnings, "focused": bool(focused_ip),
                  "message": f"{len(ips)} IPs verificados em {time.monotonic()-start:.1f}s. " + " ".join(warnings)}
        statuses = Counter(f"{e['provider']}:{e['status']}" for items in observations.values() for e in items)
        result["provider_statuses"] = dict(statuses)
        self.logger.info("NETWORK_PROVIDERS | %s", dict(statuses))
        if not focused_ip and self.inventory_path:
            try:
                self.export_inventory(result)
            except (OSError, ValueError, TypeError) as exc:
                warning = "Coleta concluída, mas exportação do inventário NÃO salva: " + clean(exc)
                result["warnings"].append(warning)
                result["message"] += " " + warning
                self.logger.warning("NETWORK_INVENTORY_EXPORT_FAILED | %s", clean(exc))
        self.logger.info("NETWORK_SCAN_END | hosts=%s | duracao=%.2f | historico=%s", len(ips), time.monotonic()-start, history_ok)
        return result

    def export_inventory(self, result):
        """Preserva o contrato consumido por relatórios; sem estimativa legada livre."""
        data = {}
        path = self.inventory_path
        if path.exists():
            with path.open("rb") as source:
                raw = source.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Inventário anterior acima do limite; preservado.")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Inventário anterior inválido; preservado.")
        hosts = [{"IP": r["ip"], "Nome": r.get("hostname") or "Não identificado", "MAC": r.get("mac") or "Não identificado",
                  "Tipo": r["type"], "Estado": r["state"], "Servicos": "; ".join(map(str, r.get("ports", []))),
                  "Impressora": bool(set(r.get("ports", [])) & {9100, 631, 515})} for r in result["records"] if any(e.get("responded") for e in r.get("evidence", []))]
        data.update(Hosts=hosts, InterfaceVarredura=result["context"], DataAtualizacao=utc(),
                    ModoColeta="Configurador TI Network Intelligence /24", NetworkScopeId=result["scope"],
                    DisponibilidadeIPs={"Concluida": False, "Candidatos": [], "Motivo": "Consulte Network Intelligence: histórico, reservas e validade são necessários."})
        data["Impressoras"] = [{"Nome": h["Nome"], "IP": h["IP"], "MAC": h["MAC"], "Porta": h["Servicos"], "Origem": "Network Intelligence"} for h in hosts if h["Impressora"]]
        data["Resumo"] = dict(data.get("Resumo") or {}, TotalHosts=len(hosts), TotalImpressoras=len(data["Impressoras"]))
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".configurador_ti_inventory_", delete=False) as out:
                tmp = Path(out.name)
                out.write(json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8"))
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, path)
        finally:
            if tmp and tmp.exists():
                tmp.unlink()

    def edit(self, scope, ip, action, text="", hours=0):
        """Ações locais explícitas; não altera rede/DHCP/dispositivo."""
        text = clean(text, 500)
        stamp = utc()
        def change(data):
            record = data["scopes"][scope]["records"][ip]
            if action == "reserve":
                expiry = datetime.fromtimestamp(time.time() + hours * 3600, timezone.utc).isoformat(timespec="seconds") if hours else None
                record["reservation"] = {"description": text, "created": stamp, "expires": expiry, "origin": "Configurador TI local — não altera DHCP"}
            elif action == "remove":
                if record.get("reservation"):
                    record["reservation"]["removed"] = stamp
            elif action == "note":
                record["note"] = text
            elif action == "replacement":
                record["replacement_confirmed"] = {"at": stamp, "description": text, "macs": list(record.get("macs", []))}
                record["identity_alert"] = ""
            else:
                raise ValueError("Ação local inválida")
            record["events"] = (record.get("events", []) + [{"at": stamp, "kind": action, "description": text}])[-64:]
        data = self.store.transaction(change)
        self.logger.info("NETWORK_LOCAL_ACTION | action=%s | scope=%s | ip=%s", action, scope[:12], ip)
        return consolidate(data["scopes"][scope]["records"][ip])


def technical_summary(record, context, providers=()):
    labels = [("IP", "ip"), ("Estado", "state"), ("Confiança", "confidence"), ("Peso de evidência (não é probabilidade)", "score"), ("MAC atual/último", "mac"),
              ("Hostname atual/último", "hostname"), ("Fabricante", "manufacturer"), ("Tipo", "type"),
              ("Primeiro visto", "first_seen"), ("Último visto", "last_seen"), ("Último online", "last_online"),
              ("Verificado em", "checked"), ("Alerta", "identity_alert"), ("Observação", "note")]
    lines = [f"Rede: {clean(context.get('Rede'))} | Interface: {clean(context.get('Alias'))}"]
    lines.append("Escopo local: " + clean(context.get("network_scope_id"), 64))
    lines.append("Gateway: " + clean(context.get("Gateway")) + " | Perfil: " + clean(context.get("Profile")))
    lines += [f"{label}: {clean(record.get(key)) or 'Não disponível'}" for label, key in labels]
    lines += ["Reserva Configurador TI local: " + clean(json.dumps(record.get("active_reservation"), ensure_ascii=False), 700),
              "Portas TCP: " + ", ".join(map(str, record.get("ports", []))),
              "MACs históricos: " + ", ".join(record.get("macs", [])),
              "Hostnames históricos: " + ", ".join(record.get("hostnames", [])), "Evidências:"]
    lines += [clean(json.dumps(e, ensure_ascii=False), 600) for e in record.get("evidence", [])]
    lines += ["Providers indisponíveis: " + ", ".join(p["provider"] for p in providers), "Histórico (até 64 eventos recentes):"]
    lines += [clean(json.dumps(e, ensure_ascii=False), 600) for e in reversed(record.get("events", []))]
    lines += ["Limitações:"] + record.get("limitations", []) + ["Recomendação: " + record.get("recommendation", "")]
    if record.get("identification_status"):
        lines += ["Status NetBIOS (identificação): " + clean(record["identification_status"])]
    if record.get("identifications"):
        lines += ["Identificação adicional (não altera disponibilidade):"]
        lines += [clean(json.dumps(v, ensure_ascii=False),700) for v in record["identifications"]]
    return "\n".join(lines)
