
from __future__ import annotations
from typing import Optional, Tuple, Iterable, Iterator, Dict, Any
import json

MAGIC = b"ENC1"

def build_enc_header(scheme: str, algo: str, params: Optional[Dict[str, Any]] = None) -> bytes:
    s = scheme.encode("utf-8")
    a = algo.encode("utf-8")
    pj = json.dumps(params or {}, separators=(",", ":")).encode("utf-8")
    if len(s) > 255 or len(a) > 255 or len(pj) > 65535:
        raise ValueError("header demasiado grande")
    return MAGIC + bytes([len(s)]) + s + bytes([len(a)]) + a + len(pj).to_bytes(2, "big") + pj + b"\x00"

def try_parse_enc_header(data: bytes):
    if not data.startswith(MAGIC):
        return None
    i = len(MAGIC)
    if i >= len(data): return None
    ls = data[i]; i += 1
    if i + ls > len(data): return None
    scheme = data[i:i+ls].decode("utf-8"); i += ls
    if i >= len(data): return None
    la = data[i]; i += 1
    if i + la > len(data): return None
    algo = data[i:i+la].decode("utf-8"); i += la
    if i + 2 > len(data): return None
    lp = int.from_bytes(data[i:i+2], "big"); i += 2
    if i + lp + 1 > len(data): return None
    params = json.loads(data[i:i+lp].decode("utf-8") or "{}"); i += lp
    if data[i] != 0:
        return None
    i += 1
    return (scheme, algo, params, i)

def prefix_header_iter(header: bytes, chunks: Iterable[bytes]) -> Iterable[bytes]:
    yield header
    for ch in chunks:
        yield ch

def peek_and_autodecrypt(stream: Iterable[bytes],
                         decrypt_resolver,
                         explicit: Optional[Tuple[str,str,Dict[str,Any]]] = None
                         ) -> Iterable[bytes]:
    buf = bytearray()
    it = iter(stream)
    try:
        while len(buf) < 8192:
            ch = next(it)
            buf += ch
            if len(buf) >= 4 and buf[:4] == MAGIC:
                parsed = try_parse_enc_header(bytes(buf))
                if parsed:
                    scheme, algo, params, off = parsed
                    leftover = bytes(buf[off:])
                    init, decrypt_iter = decrypt_resolver(scheme, algo)
                    meta = init(params)
                    def gen():
                        if leftover:
                            yield leftover
                        for rest in it:
                            yield rest
                    return decrypt_iter(meta, gen())
                break
    except StopIteration:
        pass

    if explicit is not None:
        scheme, algo, params = explicit
        init, decrypt_iter = decrypt_resolver(scheme, algo)
        meta = init(params)
        def gen2():
            if buf:
                yield bytes(buf)
            for rest in it:
                yield rest
        return decrypt_iter(meta, gen2())

    def plain():
        if buf:
            yield bytes(buf)
        for rest in it:
            yield rest
    return plain()
