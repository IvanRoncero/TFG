from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterable, Dict, Any

class ExfilClientPlugin(ABC):
    canal: str
    metodo: int
    name: str
    @abstractmethod
    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        ...

class ExfilServerPlugin(ABC):
    canal: str
    metodo: int
    name: str
    @abstractmethod
    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        ...
