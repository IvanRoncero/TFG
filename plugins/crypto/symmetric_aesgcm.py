from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
import base64, hashlib, secrets

from tfg.plugins.api_crypto import CryptoEncryptPlugin, CryptoDecryptPlugin

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    raise ImportError("Requiere 'cryptography' (pip install cryptography)") from e

NONCE_PREFIX_LEN = 8


def _kdf_sha256(key_bytes: bytes) -> bytes:
    return hashlib.sha256(key_bytes).digest()


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + counter.to_bytes(4, "big")


def _read_exact(it, n: int):
    """Lee exactamente n bytes de un iterador de chunks. Devuelve (data, leftover)."""
    buf = bytearray()
    for chunk in it:
        buf += chunk
        if len(buf) >= n:
            break
    if len(buf) < n:
        raise ValueError(f"Stream truncado: esperaba {n} bytes, recibidos {len(buf)}")
    return bytes(buf[:n]), bytes(buf[n:])


def _prepend(data: bytes, it):
    if data:
        yield data
    yield from it


class AESGCMEncrypt(CryptoEncryptPlugin):
    esquema = "SIMETRICO"
    algoritmo = "AESGCM"
    name = "aesgcm_encrypt"

    def init(self, config: Dict[str, Any]) -> Dict[str, Any]:
        key_bytes = config.get("key_bytes")
        if not key_bytes:
            raise ValueError("AESGCM requiere 'key_bytes'")
        return {"_key_bytes": key_bytes}

    def encrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        k = meta.get("_key_bytes")
        if not k:
            raise ValueError("Falta _key_bytes")
        key = _kdf_sha256(k)
        prefix = secrets.token_bytes(NONCE_PREFIX_LEN)
        aead = AESGCM(key)

        def _gen() -> Iterator[bytes]:
            yield prefix  # cabecera: 8 bytes de nonce prefix
            ctr = 0
            for chunk in chunk_iter:
                nonce = _nonce(prefix, ctr)
                yield aead.encrypt(nonce, chunk, None)
                ctr += 1
        return _gen()


class AESGCMDecrypt(CryptoDecryptPlugin):
    esquema = "SIMETRICO"
    algoritmo = "AESGCM"
    name = "aesgcm_decrypt"

    def decrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        k = meta.get("_key_bytes")
        if not k:
            raise ValueError("Falta _key_bytes")
        key = _kdf_sha256(k)
        aead = AESGCM(key)

        def _gen() -> Iterator[bytes]:
            it = iter(chunk_iter)
            prefix, leftover = _read_exact(it, NONCE_PREFIX_LEN)
            ctr = 0
            for chunk in _prepend(leftover, it):
                nonce = _nonce(prefix, ctr)
                yield aead.decrypt(nonce, chunk, None)
                ctr += 1
        return _gen()
