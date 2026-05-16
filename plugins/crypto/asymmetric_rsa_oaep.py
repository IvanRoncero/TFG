from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
import secrets

from tfg.plugins.api_crypto import CryptoEncryptPlugin, CryptoDecryptPlugin

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception as e:
    raise ImportError("Requiere 'cryptography' (pip install cryptography)") from e

NONCE_PREFIX_LEN = 8

# Formato de cabecera incrustada en el stream:
#   2 bytes: longitud de enc_key (big-endian uint16)
#   N bytes: clave de sesión cifrada con RSA-OAEP
#   8 bytes: nonce prefix AES-GCM


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + counter.to_bytes(4, "big")


def _read_exact(it, n: int):
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


def _oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


class RSAOAEPEncrypt(CryptoEncryptPlugin):
    esquema = "ASIMETRICO"
    algoritmo = "RSA_OAEP"
    name = "rsa_oaep_encrypt"

    def init(self, config: Dict[str, Any]) -> Dict[str, Any]:
        pub_bytes = config.get("public_key_bytes")
        if not pub_bytes:
            raise ValueError("RSA_OAEP requiere 'public_key_bytes' (PEM)")
        return {"_public_key_bytes": pub_bytes}

    def encrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        pub_bytes = meta.get("_public_key_bytes")
        if not pub_bytes:
            raise ValueError("Falta _public_key_bytes")
        sess_key = secrets.token_bytes(32)
        prefix = secrets.token_bytes(NONCE_PREFIX_LEN)
        pub = serialization.load_pem_public_key(pub_bytes)
        enc_key = pub.encrypt(sess_key, _oaep_padding())
        aead = AESGCM(sess_key)

        def _gen() -> Iterator[bytes]:
            # cabecera: 2 bytes longitud + enc_key + nonce prefix
            yield len(enc_key).to_bytes(2, "big") + enc_key + prefix
            ctr = 0
            for chunk in chunk_iter:
                nonce = _nonce(prefix, ctr)
                yield aead.encrypt(nonce, chunk, None)
                ctr += 1
        return _gen()


class RSAOAEPDecrypt(CryptoDecryptPlugin):
    esquema = "ASIMETRICO"
    algoritmo = "RSA_OAEP"
    name = "rsa_oaep_decrypt"

    def decrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        priv_bytes = meta.get("_private_key_bytes")
        if not priv_bytes:
            raise ValueError("RSA_OAEP requiere '_private_key_bytes' (PEM)")
        priv = serialization.load_pem_private_key(priv_bytes, password=None)

        def _gen() -> Iterator[bytes]:
            it = iter(chunk_iter)

            len_bytes, lo1 = _read_exact(it, 2)
            enc_key_len = int.from_bytes(len_bytes, "big")

            enc_key, lo2 = _read_exact(_prepend(lo1, it), enc_key_len)
            prefix, lo3 = _read_exact(_prepend(lo2, it), NONCE_PREFIX_LEN)

            sess_key = priv.decrypt(enc_key, _oaep_padding())
            aead = AESGCM(sess_key)

            ctr = 0
            for chunk in _prepend(lo3, it):
                nonce = _nonce(prefix, ctr)
                yield aead.decrypt(nonce, chunk, None)
                ctr += 1
        return _gen()
