"""Identificação adicional, não evidência de disponibilidade. RFC 1002 NBSTAT.
Sem SMB, autenticação, subprocesso, broadcast ou escrita remota.
"""
import ipaddress
import logging
import os
import re
import secrets
import socket
import struct
from datetime import datetime, timezone
LOG=logging.getLogger("ConfiguradorTI.Network.Identification")


def valid_name(value):
    value=str(value or "").strip().rstrip(".")
    return value if len(value)<=253 and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*",value) else ""


def parse_node_status(packet, transaction):
    if len(packet)<12 or len(packet)>4096:raise ValueError("Resposta NBSTAT fora do limite")
    ident,flags,qd,an,ns,ar=struct.unpack("!6H",packet[:12])
    if ident!=transaction or not flags&0x8000 or flags&0x020f or flags&0x7800 or qd>1 or an!=1 or ns or ar:
        raise ValueError("Cabeçalho NBSTAT inválido")
    def skip_name(pos):
        for _ in range(128):
            if pos>=len(packet):raise ValueError("Nome truncado")
            length=packet[pos]
            if length&0xc0==0xc0:
                if pos+1>=len(packet) or ((length&63)<<8|packet[pos+1])>=len(packet):raise ValueError("Ponteiro inválido")
                return pos+2
            if length>63:raise ValueError("Rótulo inválido")
            pos+=1
            if not length:return pos
            pos+=length
        raise ValueError("Nome acima do limite")
    pos=12
    for _ in range(qd):pos=skip_name(pos)+4
    pos=skip_name(pos)
    if pos+10>len(packet):raise ValueError("RR truncado")
    kind,cls,ttl,size=struct.unpack("!HHIH",packet[pos:pos+10]);pos+=10
    if kind!=33 or cls!=1 or not size or pos+size>len(packet):raise ValueError("RR inválido")
    count=packet[pos]
    if count>100 or 1+count*18>size:raise ValueError("Contagem inválida")
    names=[]
    for i in range(count):
        row=packet[pos+1+i*18:pos+1+(i+1)*18]
        flag=struct.unpack("!H",row[16:18])[0]
        # Somente nome único de estação; grupos/domínios não são hostname.
        if row[15]!=0 or flag&0x8000:continue
        name=valid_name(row[:15].decode("ascii",errors="strict").strip())
        if name and name not in names:names.append(name)
    return names


class NetBIOSProvider:
    timeout=.45
    def collect(self,ip,source,cancel):
        if cancel():return {"status":"cancelled","names":[]}
        if os.name!="nt":return {"status":"unavailable","names":[],"error":"Requer Windows"}
        try:
            target=ipaddress.IPv4Address(ip);origin=ipaddress.IPv4Address(source)
            network=ipaddress.ip_network(str(origin)+"/24",strict=False)
            if target not in network or target in (network.network_address,network.broadcast_address) or not target.is_private or target.is_loopback or target.is_link_local:
                raise ValueError("Destino fora do escopo local elegível")
            transaction=secrets.randbits(16)
            name=b"*"+b"\x00"*15
            encoded=bytes(65+n for b in name for n in (b>>4,b&15))
            query=struct.pack("!6H",transaction,0,1,0,0,0)+b"\x20"+encoded+b"\x00"+struct.pack("!HH",33,1)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout);sock.bind((str(origin),0))
                sock.connect((str(target),137))
                if cancel():return {"status":"cancelled","names":[]}
                sock.send(query);packet=sock.recv(4096)
            if cancel():return {"status":"cancelled","names":[]}
            return {"status":"ok","names":parse_node_status(packet,transaction)}
        except (OSError,ValueError,UnicodeError) as exc:
            LOG.debug("NBSTAT não disponível: %s",type(exc).__name__)
            return {"status":"unavailable","names":[],"error":type(exc).__name__}


def metadata(previous, dns, nb, bound_mac, observed_at=None):
    """Metadados aditivos; nunca modifica evidence/score/state/last_seen."""
    now=observed_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    values=list(previous) if isinstance(previous,list) else []
    for source,names,confidence in (("DNS PTR",[dns.get("hostname")],"Alta"),("NetBIOS",nb.get("names",[]),"Média")):
        for name in names:
            name=valid_name(name)
            if not name:continue
            values=[v for v in values if not (v.get("name","").casefold()==name.casefold() and v.get("source")==source and v.get("mac")==bound_mac)]
            values.append(dict(name=name,source=source,observed_at=now,confidence=confidence,mac=bound_mac))
    return values[-64:]


def identification(record):
    values=[v for v in record.get("identifications",[]) if isinstance(v,dict) and valid_name(v.get("name"))]
    # Sem âncora MAC, metadados anteriores não são reassociados automaticamente.
    current=[v for v in values if (record.get("mac") and v.get("mac")==record.get("mac")) or v.get("observed_at","")==record.get("identification_checked")]
    names=list(dict.fromkeys(v['name'] for v in current))
    old=valid_name(record.get("hostname"))
    if old and old not in names:names.insert(0,old)
    roots={name.split('.')[0].casefold() for name in names}
    domains={name.casefold() for name in names if '.' in name}
    divergent=len(roots)>1 or len(domains)>1
    return (" / ".join(names) if names else "Não identificado"), ("Identificação divergente — verificar" if divergent else ""),values
