
from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator, Optional
import queue, threading

from tfg.plugins.api import ExfilServerPlugin
from .icmp_common import RawSession

class _IcmpStore:
    def __init__(self):
        self.q: "queue.Queue[bytes]" = queue.Queue()
        self.done = threading.Event()

    def put(self, b: bytes) -> None:
        self.q.put(b)

    def close(self) -> None:
        self.done.set()
        self.q.put(b"")

    def iter(self) -> Iterator[bytes]:
        while True:
            x = self.q.get()
            if x == b"" and self.done.is_set():
                break
            if x:
                yield x

def _sniff_identifier(dst_host: Optional[str], sess: RawSession, iface: Optional[str] = None):
    from scapy.all import sniff, IP, ICMP
    def cb(pkt):
        if ICMP in pkt and pkt[ICMP].type == 8:
            if dst_host and pkt[IP].dst != dst_host:
                return
            v = pkt[ICMP].id & 0xFF
            out = sess.feed(v)
            if out is not None:
                store.put(out); store.close()
    sniff(filter="icmp", prn=cb, store=False, iface=iface)

def _sniff_sequence(dst_host: Optional[str], sess: RawSession, iface: Optional[str] = None):
    from scapy.all import sniff, IP, ICMP
    def cb(pkt):
        if ICMP in pkt and pkt[ICMP].type == 8:
            if dst_host and pkt[IP].dst != dst_host:
                return
            v = pkt[ICMP].seq & 0xFF
            out = sess.feed(v)
            if out is not None:
                store.put(out); store.close()
    sniff(filter="icmp", prn=cb, store=False, iface=iface)

def _sniff_ttl(dst_host: Optional[str], sess: RawSession, ttl_base: int, iface: Optional[str] = None):
    from scapy.all import sniff, IP, ICMP
    def cb(pkt):
        if ICMP in pkt and pkt[ICMP].type == 8:
            if dst_host and pkt[IP].dst != dst_host:
                return
            observed = int(pkt[IP].ttl)
            v = (observed - ttl_base) & 0xFF
            out = sess.feed(v)
            if out is not None:
                store.put(out); store.close()
    sniff(filter="icmp", prn=cb, store=False, iface=iface)

class IcmpServerIdentifier(ExfilServerPlugin):
    canal = "ICMP"
    metodo = 1  # Identifier
    name = "icmp_server_identifier"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        host = config.get("host")  # opcional: filtra destino
        global store
        store = _IcmpStore()
        sess = RawSession(exfil_id, auth_token)
        th = threading.Thread(target=_sniff_identifier, args=(host, sess, iface), daemon=True)
        th.start()
        return store.iter()

class IcmpServerSequence(ExfilServerPlugin):
    canal = "ICMP"
    metodo = 2  # Sequence Number
    name = "icmp_server_sequence"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        host = config.get("host")
        global store
        store = _IcmpStore()
        sess = RawSession(exfil_id, auth_token)
        th = threading.Thread(target=_sniff_sequence, args=(host, sess, iface), daemon=True)
        th.start()
        return store.iter()

class IcmpServerTTL(ExfilServerPlugin):
    canal = "ICMP"
    metodo = 3  # TTL
    name = "icmp_server_ttl"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        host = config.get("host")
        ttl_base = int(config.get("ttl_base") or 64)
        global store
        store = _IcmpStore()
        sess = RawSession(exfil_id, auth_token)
        th = threading.Thread(target=_sniff_ttl, args=(host, sess, ttl_base, iface), daemon=True)
        th.start()
        return store.iter()
