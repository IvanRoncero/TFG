from __future__ import annotations
from typing import Dict, Any, Iterable
import re, base64, paramiko, time

from tfg.plugins.api import ExfilServerPlugin


def b32dec(s: str) -> bytes:
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode((s + pad).upper())


class SshServerNames(ExfilServerPlugin):
    canal = "SSH"
    metodo = 2
    name = "ssh_server_names"

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

        pat = re.compile(rf"^{re.escape(exfil_id)}\.(\d{{6}})\.([a-z0-9]+)$")
        eot_name = f"{exfil_id}.EOT"

        key = paramiko.RSAKey.from_private_key_file(pkey_path) if pkey_path else None
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, port=port, username=user, password=password, pkey=key, look_for_keys=False)
        sftp = ssh.open_sftp()
        try:
            sftp.chdir(remote_dir)
            deadline = None if timeout_s is None else (time.time() + timeout_s)
            seen = set()
            while True:
                names = sftp.listdir(".")
                seen.update(names)
                if eot_name in names:
                    break
                if deadline is not None and time.time() >= deadline:
                    break
                time.sleep(poll_interval)

            parts = sorted((m.group(1), m.group(2)) for n in seen for m in [pat.match(n)] if m)
            data = bytearray()
            for _seq, token in parts:
                data += b32dec(token)

            def gen():
                if data:
                    yield bytes(data)
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

