from __future__ import annotations
from typing import Dict, Any, Iterable

from tfg.plugins.api import ExfilClientPlugin

class HttpClientDummy(ExfilClientPlugin):
    canal = "HTTP"
    metodo = 1
    name = "http_client_dummy"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        total = 0
        frags = 0
        for chunk in payload_iter:
            total += len(chunk)
            frags += 1
        return {"ok": True, "sent_bytes": total, "sent_fragments": frags, "plugin": self.name}
