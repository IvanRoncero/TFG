from __future__ import annotations
from typing import Dict, Any, Iterable
import imaplib, email, base64
from tfg.plugins.api import ExfilServerPlugin

class SmtpServerHeaders(ExfilServerPlugin):
    canal = "SMTP"
    metodo = 1
    name = "smtp_server_headers"

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        host = config["imap_host"]; port = int(config.get("imap_port", 993))
        user = config["imap_user"]; password = config["imap_pass"]
        mailbox = config.get("mailbox", "INBOX")
        exfil_id = config.get("exfil_id") or "tfg"

        imap = imaplib.IMAP4_SSL(host, port); imap.login(user, password); imap.select(mailbox)
        typ, data = imap.search(None, '(SUBJECT "TFG EXFIL ' + exfil_id + '")'); ids = data[0].split()
        if not ids:
            imap.logout()
            def empty():
                if False: yield b""
            return empty()
        mid = ids[-1]; typ, msg_data = imap.fetch(mid, "(RFC822)"); raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)
        vals = msg.get_all("X-TFG-Data", []); b64 = "".join(vals); decoded = base64.b64decode(b64.encode("ascii")) if b64 else b""
        imap.logout()
        def gen():
            if decoded: yield decoded
        return gen()
