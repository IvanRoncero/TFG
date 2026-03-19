from __future__ import annotations
from typing import Iterable
from base64 import b32encode

MAX_LABEL = 50
def encode_chunk(b: bytes) -> str:
    return b32encode(b).decode("ascii").strip("=").lower()

def chunk_labels(chunks: Iterable[bytes]) -> Iterable[str]:
    buf = bytearray()
    for ch in chunks:
        buf += ch
        while len(buf) >= 30:
            raw = bytes(buf[:30]); del buf[:30]; yield encode_chunk(raw)
    if buf: yield encode_chunk(bytes(buf))
