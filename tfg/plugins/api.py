from __future__ import annotations
from typing import Dict, Any, Iterable

class ExfilClientPlugin:
    canal: str = ""
    metodo: int = 0
    name: str = ""

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        raise NotImplementedError

class ExfilServerPlugin:
    canal: str = ""
    metodo: int = 0
    name: str = ""

    def run(self, config: Dict[str, Any]):
        raise NotImplementedError
