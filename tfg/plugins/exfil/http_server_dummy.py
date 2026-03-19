from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator

from tfg.plugins.api import ExfilServerPlugin

class HttpServerDummy(ExfilServerPlugin):
    canal = "HTTP"
    metodo = 1
    name = "http_server_dummy"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        def _gen() -> Iterator[bytes]:
            yield b""  # simulación
        return _gen()
