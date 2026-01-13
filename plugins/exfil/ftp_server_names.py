
from __future__ import annotations
from typing import Dict, Any, Iterable
from ftplib import FTP
import re, base64

from tfg.plugins.api import ExfilServerPlugin

def b32dec(s: str) -> bytes:
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode((s + pad).upper())

class FtpServerNames(ExfilServerPlugin):
    canal = "FTP"
    metodo = 2
    name = "ftp_server_names"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        host = config["host"]; port = int(config.get("port", 21))
        user = config.get("user") or "anonymous"
        password = config.get("password") or "anonymous@"
        root = config.get("root") or "/"
        exfil_id = config.get("exfil_id") or "tfg"
        # pattern: exfilid.seq.token
        pat = re.compile(rf"^{re.escape(exfil_id)}\.(\d{{6}})\.([a-z0-9]+)$")

        ftp = FTP(); ftp.connect(host, port, timeout=30); ftp.login(user=user, passwd=password)
        if root and root != "/": ftp.cwd(root)
        names = []; ftp.retrlines("NLST", names.append)
        parts = sorted((m.group(1), m.group(2)) for n in names for m in [pat.match(n)] if m)

        data = bytearray()
        for seq, token in parts:
            data += b32dec(token)

        def gen():
            if data:
                yield bytes(data)
            ftp.quit()
        return gen()
