from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
import hashlib, base64, secrets

from tfg.plugins.api_crypto import CryptoEncryptPlugin, CryptoDecryptPlugin

def _session_key(pub: bytes, prv: bytes, nonce: bytes) -> bytes:
    return hashlib.sha256(pub + b"|" + prv + b"|" + nonce).digest()

def _derive_block(key: bytes, nonce: bytes, counter: int, length: int) -> bytes:
    out = bytearray()
    c = counter
    while len(out) < length:
        out.extend(hashlib.sha256(key + nonce + c.to_bytes(8, "big")).digest())
        c += 1
    return bytes(out[:length])

def _xor(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, mask))

class AsymFakeEncrypt(CryptoEncryptPlugin):
    esquema = "ASIMETRICO"
    algoritmo = "FAKE_RSA"
    name = "asym_fake_encrypt"

    def init(self, config: Dict[str, Any]) -> Dict[str, Any]:
        pub = config.get("public_key_bytes") or b""
        prv = config.get("private_key_bytes") or b""
        if not pub or not prv:
            raise ValueError("FAKE_RSA requiere public_key_bytes y private_key_bytes")
        nonce = secrets.token_bytes(16)
        return {"alg": self.algoritmo, "nonce_b64": base64.b64encode(nonce).decode("ascii")}

    def encrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        pub = meta.get("_public_key_bytes"); prv = meta.get("_private_key_bytes")
        nonce = base64.b64decode(meta["nonce_b64"])
        if not pub or not prv:
            raise ValueError("Falta material de clave en meta para cifrar")
        key = _session_key(pub, prv, nonce)
        def _gen() -> Iterator[bytes]:
            counter = 0
            for chunk in chunk_iter:
                mask = _derive_block(key, nonce, counter, len(chunk))
                yield _xor(chunk, mask)
                counter += 1
        return _gen()

class AsymFakeDecrypt(CryptoDecryptPlugin):
    esquema = "ASIMETRICO"
    algoritmo = "FAKE_RSA"
    name = "asym_fake_decrypt"

    def decrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        pub = meta.get("_public_key_bytes"); prv = meta.get("_private_key_bytes")
        nonce = base64.b64decode(meta["nonce_b64"])
        if not pub or not prv:
            raise ValueError("Falta material de clave en meta para descifrar")
        key = _session_key(pub, prv, nonce)
        def _gen() -> Iterator[bytes]:
            counter = 0
            for chunk in chunk_iter:
                mask = _derive_block(key, nonce, counter, len(chunk))
                yield _xor(chunk, mask)
                counter += 1
        return _gen()
