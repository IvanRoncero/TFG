
from __future__ import annotations
from typing import Optional, Iterable

MAGIC = b"TFG1"       # 4 bytes magic for raw encodings
EOT = 0xFF            # end-of-transmission marker (single byte)
SEQ_BASE = 1_000_000_000  # base to build encoded SEQ numbers

def build_header_bytes(exfil_id: str, auth_token: Optional[str]) -> bytes:
    eid = exfil_id.encode("utf-8")
    tok = (auth_token or "").encode("utf-8")
    if len(eid) > 255: raise ValueError("exfil_id demasiado largo (max 255)")
    if len(tok) > 255: raise ValueError("auth_token demasiado largo (max 255)")
    # MAGIC | len(eid) | eid | len(tok) | tok
    return MAGIC + bytes([len(eid)]) + eid + bytes([len(tok)]) + tok

def iter_bytes_from_chunks(chunks: Iterable[bytes]):
    for ch in chunks:
        if not ch:
            continue
        for b in ch:
            yield b

def iter_chunks_from_bytes(biter: Iterable[int], chunk_size: int = 16384):
    buf = bytearray()
    for b in biter:
        buf.append(b & 0xFF)
        if len(buf) >= chunk_size:
            yield bytes(buf)
            buf.clear()
    if buf:
        yield bytes(buf)
