
from __future__ import annotations
from typing import Optional, Iterable

MAGIC = b"TFG1"     # same marker as TCP raw
EOT = 0xFF          # end of transmission

def build_header_bytes(exfil_id: str, auth_token: Optional[str]) -> bytes:
    eid = exfil_id.encode("utf-8")
    tok = (auth_token or "").encode("utf-8")
    if len(eid) > 255: raise ValueError("exfil_id demasiado largo (max 255)")
    if len(tok) > 255: raise ValueError("auth_token demasiado largo (max 255)")
    return MAGIC + bytes([len(eid)]) + eid + bytes([len(tok)]) + tok

def iter_bytes_from_chunks(chunks: Iterable[bytes]):
    for ch in chunks:
        if not ch:
            continue
        for b in ch:
            yield b

class RawSession:
    """Parses MAGIC | len(eid) | eid | len(tok) | tok | BODY ... EOT"""
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
                    self.buf.clear()
                    return None
                self.stage = "eid_len"; self.expected = 1; self.buf.clear()
        elif self.stage == "eid_len":
            self.eid_len = b; self.stage = "eid"; self.expected = self.eid_len; self.buf.clear()
        elif self.stage == "eid":
            self.buf.append(b)
            if len(self.buf) == self.expected:
                if bytes(self.buf) != self.target_eid:
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
