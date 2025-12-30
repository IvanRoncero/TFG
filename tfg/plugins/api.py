from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterable, Dict, Any

class ExfilClientPlugin(ABC):
    """Interfaz de plugin de EXFILTRACIÓN (rol CLIENTE/EMISOR)."""
    canal: str  # "HTTP", "TCP", ...
    metodo: int # selector entero
    name: str   # identificador legible

    @abstractmethod
    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        """Ejecuta el envío. Debe consumir payload_iter. Retorna dict con métricas."""

class ExfilServerPlugin(ABC):
    """Interfaz de plugin de EXFILTRACIÓN (rol SERVIDOR/RECEPTOR)."""
    canal: str
    metodo: int
    name: str

    @abstractmethod
    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        """Ejecuta la recepción. Devuelve un iterable de chunks (bytes)."""
