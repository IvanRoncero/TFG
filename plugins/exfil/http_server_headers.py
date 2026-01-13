from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
import threading
from http.server import ThreadingHTTPServer

from tfg.plugins.api import ExfilServerPlugin
from .http_server_common import _Store, _make_handler_headers

class HttpServerHeaders(ExfilServerPlugin):
    canal = "HTTP"
    metodo = 1
    name = "http_server_headers"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        bind_host = config.get("bind_host") or "0.0.0.0"
        bind_port = int(config.get("bind_port") or 8080)
        path = config.get("path") or "/upload"
        exfil_id = config.get("exfil_id") or "default"
        auth_token = config.get("auth_token")

        store = _Store()
        Handler = _make_handler_headers(store, path, auth_token)
        httpd = ThreadingHTTPServer((bind_host, bind_port), Handler)
        th = threading.Thread(target=httpd.serve_forever, daemon=True); th.start()

        def _gen() -> Iterator[bytes]:
            try:
                for chunk in store.pop_iter(exfil_id):
                    yield chunk
            finally:
                httpd.shutdown()
        return _gen()
