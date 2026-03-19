from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
import hashlib, base64, secrets

from tfg.plugins.api_crypto import CryptoEncryptPlugin, CryptoDecryptPlugin

def _derive_block(key: bytes, nonce: bytes, counter: int, length: int) -> bytes:
    out = bytearray()
    c = counter
    while len(out) < length:
        h = hashlib.sha256(key + nonce + c.to_bytes(8, "big")).digest()
        out.extend(h)
        c += 1
    return bytes(out[:length])

def _xor(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, mask))

class SymmetricXorEncrypt(CryptoEncryptPlugin):
    esquema = "SIMETRICO"
    algoritmo = "XOR256"
    name = "symmetric_xor_encrypt"

    def init(self, config: Dict[str, Any]) -> Dict[str, Any]:
        key = config.get("key_bytes") or b""
        if not key:
            raise ValueError("XOR256 requiere key_bytes en config")
        nonce = secrets.token_bytes(16)
        return {"alg": self.algoritmo, "nonce_b64": base64.b64encode(nonce).decode("ascii")}

    def encrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        nonce = base64.b64decode(meta["nonce_b64"])
        key = meta.get("_key_bytes")
        if not key:
            raise ValueError("Falta _key_bytes en meta para cifrar")
        def _gen() -> Iterator[bytes]:
            counter = 0
            for chunk in chunk_iter:
                mask = _derive_block(key, nonce, counter, len(chunk))
                yield _xor(chunk, mask)
                counter += 1
        return _gen()

class SymmetricXorDecrypt(CryptoDecryptPlugin):
    esquema = "SIMETRICO"
    algoritmo = "XOR256"
    name = "symmetric_xor_decrypt"

    def decrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        nonce = base64.b64decode(meta["nonce_b64"])
        key = meta.get("_key_bytes")
        if not key:
            raise ValueError("Falta _key_bytes en meta para descifrar")
        def _gen() -> Iterator[bytes]:
            counter = 0
            for chunk in chunk_iter:
                mask = _derive_block(key, nonce, counter, len(chunk))
                yield _xor(chunk, mask)
                counter += 1
        return _gen()
