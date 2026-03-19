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

    def _login_hint(msg: str) -> RuntimeError:
        return RuntimeError(
            "FTP login failed. Verify FileZilla user is enabled, password is set/saved, "
            "and authentication mode is not 'Use system credentials'. "
            f"Server response: {msg!r}"
        )

    ftp = FTP()
    ftp.connect(host, port, timeout=30)
    try:
        ftp.login(user=user, passwd=password)
        return ftp
    except error_perm as e:
        msg = str(e).lower()
        ftp.close()
        if "login" in msg or "530" in msg or "disabled" in msg:
            raise _login_hint(str(e)) from e
        if "auth" not in msg:
            raise

    ftps = FTP_TLS()
    ftps.connect(host, port, timeout=30)
    ftps.auth()
    try:
        ftps.login(user=user, passwd=password)
    except error_perm as e:
        ftps.close()
        raise _login_hint(str(e)) from e
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