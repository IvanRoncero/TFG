
from __future__ import annotations
from typing import Dict, Any, Iterable, Optional

from tfg.plugins.api import ExfilServerPlugin
from .icmp_common import RawSession


class IcmpServerIdentifier(ExfilServerPlugin):
    canal = "ICMP"
    metodo = 1  # Identifier
    name = "icmp_server_identifier"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        from scapy.all import sniff, IP, ICMP
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        host = config.get("host")
        sess = RawSession(exfil_id, auth_token)
        result: list = []
        print(f"[DEBUG] ICMP/1 sniffing iface={iface} host={host}", flush=True)
        def cb(pkt):
            if ICMP in pkt and pkt[ICMP].type == 8:
                if host and host != "0.0.0.0" and pkt[IP].dst != host:
                    return
                v = pkt[ICMP].id & 0xFF
                print(f"[DEBUG] ICMP id byte={v}", flush=True)
                out = sess.feed(v)
                if out is not None:
                    result.append(out)
        sniff(filter="icmp", prn=cb, store=False, iface=iface, stop_filter=lambda _: sess.done)
        def gen():
            yield from result
        return gen()


class IcmpServerSequence(ExfilServerPlugin):
    canal = "ICMP"
    metodo = 2  # Sequence Number
    name = "icmp_server_sequence"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        from scapy.all import sniff, IP, ICMP
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        host = config.get("host")
        sess = RawSession(exfil_id, auth_token)
        result: list = []
        def cb(pkt):
            if ICMP in pkt and pkt[ICMP].type == 8:
                if host and host != "0.0.0.0" and pkt[IP].dst != host:
                    return
                v = pkt[ICMP].seq & 0xFF
                out = sess.feed(v)
                if out is not None:
                    result.append(out)
        sniff(filter="icmp", prn=cb, store=False, iface=iface, stop_filter=lambda _: sess.done)
        def gen():
            yield from result
        return gen()


class IcmpServerTTL(ExfilServerPlugin):
    canal = "ICMP"
    metodo = 3  # TTL
    name = "icmp_server_ttl"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        from scapy.all import sniff, IP, ICMP
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        host = config.get("host")
        ttl_base = int(config.get("ttl_base") or 64)
        sess = RawSession(exfil_id, auth_token)
        result: list = []
        def cb(pkt):
            if ICMP in pkt and pkt[ICMP].type == 8:
                if host and host != "0.0.0.0" and pkt[IP].dst != host:
                    return
                v = (int(pkt[IP].ttl) - ttl_base) & 0xFF
                out = sess.feed(v)
                if out is not None:
                    result.append(out)
        sniff(filter="icmp", prn=cb, store=False, iface=iface, stop_filter=lambda _: sess.done)
        def gen():
            yield from result
        return gen()
