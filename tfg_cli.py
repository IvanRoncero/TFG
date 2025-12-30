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
    if modo == "send":
        return {"url": url}
    else:
        bind_host = host or "0.0.0.0"
        bind_port = port or (443 if url.startswith("https://") else 8080)
        path = ruta if (isinstance(ruta,str) and ruta.startswith("/")) else f"/{ruta}" if ruta else "/upload"
        return {"bind_host": bind_host, "bind_port": bind_port, "path": path}

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
    }

    sp = sub.add_parser("send", help="Enviar recurso")
    for arg, kw in common.items():
        sp.add_argument(f"--{arg}", **kw)
    sp.add_argument("--recurso-tipo", required=True, choices=[e.name for e in TipoRecurso])
    sp.add_argument("--recurso-ubicacion", required=True)
    sp.add_argument("--fragment-size", type=int, default=1024)
    sp.add_argument("--crypto-meta-out", required=False, help="Ruta donde guardar meta CRYPTO (JSON)")
    sp.set_defaults(func=cmd_send)

    sp = sub.add_parser("receive", help="Recibir recurso")
    for arg, kw in common.items():
        sp.add_argument(f"--{arg}", **kw)
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

    cfg = {"exfil_id": args.transfer_id, **_maybe_http_cfg(canal, args, "send")}

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

    client = resolve_exfil_plugin(canal.tipo, canal.metodo, "client", args.plugins_dir)
    res = client.run(cfg, payload_iter)
    t.finalizarComoCompletada()
    print(json.dumps({"ok": True, "transferencia": t.id, "resumen": res}, indent=2))
    return 0

def cmd_receive(args: argparse.Namespace) -> int:
    t = Transferencia(id=args.transfer_id, modo=Modo.RECEPTOR)
    t.iniciar()

    canal = Canal(tipo=_canal_from_str(args.canal), metodo=int(args.metodo))
    canal.validarConfiguracion()

    cfg = {"exfil_id": args.transfer_id, **_maybe_http_cfg(canal, args, "receive")}

    server = resolve_exfil_plugin(canal.tipo, canal.metodo, "server", args.plugins_dir)
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

def cmd_scan(args: argparse.Namespace) -> int:  # type: ignore[no-redef]
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

def cmd_check_file(args: argparse.Namespace) -> int:  # type: ignore[no-redef]
    p = Path(args.recurso_ubicacion)
    if not p.exists():
        print("NO_EXISTE")
        return 2
    print(f"OK size={p.stat().st_size} path={p}")
    return 0

def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
