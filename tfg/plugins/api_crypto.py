from __future__ import annotations
from typing import Dict, Any, Iterable

class CryptoEncryptPlugin:
    esquema: str = ""
    algoritmo: str = ""
    name: str = ""

    def init(self, config: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def encrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]):
        raise NotImplementedError

class CryptoDecryptPlugin:
    esquema: str = ""
    algoritmo: str = ""
    name: str = ""

    def decrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]):
        raise NotImplementedError
