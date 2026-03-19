from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
import base64, secrets

from tfg.plugins.api_crypto import CryptoEncryptPlugin, CryptoDecryptPlugin

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception as e:
    raise ImportError("Requiere 'cryptography' (pip install cryptography)") from e

NONCE_PREFIX_LEN = 8

def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + counter.to_bytes(4, "big")

class RSAOAEPEncrypt(CryptoEncryptPlugin):
    esquema = "ASIMETRICO"
    algoritmo = "RSA_OAEP"
    name = "rsa_oaep_encrypt"

    def init(self, config: Dict[str, Any]) -> Dict[str, Any]:
        pub_bytes = config.get("public_key_bytes")
        if not pub_bytes:
            raise ValueError("RSA_OAEP requiere 'public_key_bytes' (PEM)")
        sess_key = secrets.token_bytes(32)
        prefix = secrets.token_bytes(NONCE_PREFIX_LEN)
        pub = serialization.load_pem_public_key(pub_bytes)
        enc_key = pub.encrypt(
            sess_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return {
            "alg": "RSA_OAEP+AESGCM",
            "enc_key_b64": base64.b64encode(enc_key).decode("ascii"),
            "nonce_prefix_b64": base64.b64encode(prefix).decode("ascii"),
            "_session_key_b64": base64.b64encode(sess_key).decode("ascii"),
        }

    def encrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        from typing import Iterator
        sess_key = base64.b64decode(meta.get("_session_key_b64", ""))
        if not sess_key:
            raise ValueError("Falta clave de sesión")
        prefix = base64.b64decode(meta["nonce_prefix_b64"])
        aead = AESGCM(sess_key)
        def _gen() -> Iterator[bytes]:
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
        enc_key = base64.b64decode(meta["enc_key_b64"])
        prefix = base64.b64decode(meta["nonce_prefix_b64"])
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        priv = serialization.load_pem_private_key(priv_bytes, password=None)
        sess_key = priv.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        aead = AESGCM(sess_key)
        def _gen() -> Iterator[bytes]:
            ctr = 0
            for chunk in chunk_iter:
                nonce = _nonce(prefix, ctr)
                yield aead.decrypt(nonce, chunk, None)
                ctr += 1
        return _gen()
