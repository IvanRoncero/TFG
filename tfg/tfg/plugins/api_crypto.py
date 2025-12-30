from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, Iterable

class CryptoEncryptPlugin(ABC):
    esquema: str      # "SIMETRICO" | "ASIMETRICO"
    algoritmo: str    # nombre del algoritmo
    name: str

    @abstractmethod
    def init(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Inicializa y devuelve metadatos (p.ej., nonce, versión)."""

    @abstractmethod
    def encrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        """Devuelve un iterable que cifra on-the-fly los chunks de entrada."""

class CryptoDecryptPlugin(ABC):
    esquema: str
    algoritmo: str
    name: str

    @abstractmethod
    def decrypt_iter(self, meta: Dict[str, Any], chunk_iter: Iterable[bytes]) -> Iterable[bytes]:
        """Devuelve un iterable que descifra on-the-fly los chunks de entrada."""
