# tfg_cli.py — CLI con plugins de EXFIL y CRYPTO (M3)
from __future__ import annotations

import argparse
import base64
import json
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Iterable

from tfg.core.models import (
    Transferencia, Fragmento, Canal, Endpoint, Credencial,
    PoliticaCifrado, PerfilRitmo, RecursoDatos
)
from tfg.core.enums import (
    Modo, TipoCanal, EsquemaCifrado, TipoRecurso
)
from tfg.plugins.loader import resolve_exfil_plugin, resolve_crypto_plugin
from tfg.plugins.errors import PluginNotFound

def _to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        d = {}
        for k, v in asdict(obj).items():
            d[k] = _to_jsonable(v)
        return d
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if hasattr(obj, "value") and isinstance(getattr(obj, "value"), str):
        return obj.value
    if isinstance(obj, (bytes, bytearray)):
        return {"__bytes_b64__": base64.b64encode(bytes(obj)).decode("ascii")}
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj

def print_json(data: Any) -> None:
    print(json.dumps(_to_jsonable(data), ensure_ascii=False, indent=2))

def build_canal(args) -> Canal:
    parametros = {}
    if args.host: parametros["host"] = args.host
    if args.puerto is not None: parametros["puerto"] = args.puerto
    if args.ruta: parametros["ruta"] = args.ruta
    return Canal(
        id=args.canal_id,
        tipo=TipoCanal[args.canal.upper()],
        nombre=args.canal_nombre,
        metodo=int(args.metodo),
        parametros=parametros,
    )

def build_endpoints(args):
    e_o = e_d = None
    if args.origen_host or args.origen_puerto is not None or args.origen_ruta:
        e_o = Endpoint(id="EP-ORIG", host=args.origen_host or "", puerto=args.origen_puerto, ruta=args.origen_ruta or "")
        e_o.normalizar()
    if args.dest_host or args.dest_puerto is not None or args.dest_ruta:
        e_d = Endpoint(id="EP-DEST", host=args.dest_host or "", puerto=args.dest_puerto, ruta=args.dest_ruta or "")
        e_d.normalizar()
    return e_o, e_d

def build_credencial(args):
    if any([args.cred_usuario, args.cred_secreto, args.cred_token, args.cred_scope]):
        return Credencial(id="CRED-1", usuario=args.cred_usuario, secreto=args.cred_secreto, token=args.cred_token, scope=args.cred_scope)
    return None

def _read_bytes(path: str | None):
    if not path:
        return None
    if not os.path.exists(path):
        raise FileNotFoundError(f"No existe el fichero: {path}")
    with open(path, "rb") as f:
        return f.read()

def build_politica(args, esquema: EsquemaCifrado) -> PoliticaCifrado:
    algoritmo = args.algoritmo
    if not algoritmo:
        algoritmo = "XOR256" if esquema == EsquemaCifrado.SIMETRICO else ("FAKE_RSA" if esquema == EsquemaCifrado.ASIMETRICO else "NONE")
    return PoliticaCifrado(
        id="POL-1",
        esquema=esquema,
        algoritmo=algoritmo,
        clavePublica=_read_bytes(args.clave_publica),
        clavePrivada=_read_bytes(args.clave_privada),
    )

def build_perfil_ritmo(args):
    if args.ritmo_base_ms is None:
        return None
    return PerfilRitmo(id="RIT-1", tiempoBaseMs=int(args.ritmo_base_ms), dispersionMs=int(args.ritmo_disp_ms or 0))

def build_recurso(tipo: str | None, ubicacion: str | None):
    if not tipo and not ubicacion:
        return None
    assert tipo, "Debes indicar --recurso-tipo"
    assert ubicacion, "Debes indicar --recurso-ubicacion"
    return RecursoDatos(id="RES-1", tipo=TipoRecurso[tipo.upper()], ubicacion=ubicacion)

def iter_payload_and_register(t: Transferencia, recurso: RecursoDatos | None, frag_size: int) -> Iterable[bytes]:
    if recurso and recurso.tipo.name == "ARCHIVO" and os.path.exists(recurso.ubicacion):
        idx = 0
        with open(recurso.ubicacion, "rb") as f:
            while True:
                chunk = f.read(frag_size)
                if not chunk:
                    break
                frag = Fragmento(id=f"F-{idx}", indice=idx, tam=len(chunk), payloadCifrado=chunk)
                frag.obtenerHuella()
                t.registrarFragmento(frag)
                idx += 1
                yield chunk
        return
    payload = recurso.ubicacion.encode("utf-8") if recurso else b""
    frag = Fragmento(id="F-0", indice=0, tam=len(payload), payloadCifrado=payload)
    frag.obtenerHuella()
    t.registrarFragmento(frag)
    yield payload

def maybe_wrap_with_crypto_encrypt(args, pol: PoliticaCifrado, chunk_iter: Iterable[bytes]):
    if not pol or pol.esquema.name == "NINGUNO":
        return chunk_iter, None
    try:
        plug = resolve_crypto_plugin(args.plugins_dir, pol.esquema.name, pol.algoritmo, "encrypt")
    except PluginNotFound as ex:
        print_json({"error":"PluginNotFound","detalle":str(ex)})
        raise SystemExit(2)
    cfg = {
        "key_bytes": pol.clavePrivada,
        "public_key_bytes": pol.clavePublica,
        "private_key_bytes": pol.clavePrivada,
    }
    meta = plug.init(cfg)
    if pol.esquema.name == "SIMETRICO":
        meta["_key_bytes"] = pol.clavePrivada or b""
    else:
        meta["_public_key_bytes"] = pol.clavePublica or b""
        meta["_private_key_bytes"] = pol.clavePrivada or b""
    enc_iter = plug.encrypt_iter(meta, chunk_iter)
    return enc_iter, meta

def maybe_wrap_with_crypto_decrypt(args, pol: PoliticaCifrado, chunk_iter: Iterable[bytes], meta: dict) -> Iterable[bytes]:
    if not pol or pol.esquema.name == "NINGUNO":
        return chunk_iter
    try:
        plug = resolve_crypto_plugin(args.plugins_dir, pol.esquema.name, pol.algoritmo, "decrypt")
    except PluginNotFound as ex:
        print_json({"error":"PluginNotFound","detalle":str(ex)})
        raise SystemExit(2)
    if pol.esquema.name == "SIMETRICO":
        meta["_key_bytes"] = pol.clavePrivada or b""
    else:
        meta["_public_key_bytes"] = pol.clavePublica or b""
        meta["_private_key_bytes"] = pol.clavePrivada or b""
    return plug.decrypt_iter(meta, chunk_iter)

def cmd_send(args) -> int:
    t = Transferencia(id=args.transfer_id, modo=Modo.EMISOR)
    canal = build_canal(args)
    e_o, e_d = build_endpoints(args)
    cred = build_credencial(args)
    pol = build_politica(args, EsquemaCifrado[args.cifrado.upper()])
    ritmo = build_perfil_ritmo(args)
    recurso = build_recurso(args.recurso_tipo, args.recurso_ubicacion)

    t.canal = canal; t.endpointOrigen = e_o; t.endpointDestino = e_d
    t.politicaCifrado = pol; t.perfilRitmo = ritmo; t.recursoOrigen = recurso

    canal.validarConfiguracion()
    if recurso and recurso.tipo.name == "ARCHIVO":
        if not os.path.isfile(recurso.ubicacion):
            raise FileNotFoundError(f"Recurso no accesible: {recurso.ubicacion}")
        recurso.calcularHash()

    try:
        exfil_plugin = resolve_exfil_plugin(args.plugins_dir, args.canal, int(args.metodo), rol="client")
    except PluginNotFound as ex:
        print_json({"error":"PluginNotFound","detalle":str(ex)})
        return 2

    plain_iter = iter_payload_and_register(t, recurso, args.fragment_size)
    crypto_meta = None
    if pol.esquema.name != "NINGUNO":
        enc_iter, crypto_meta = maybe_wrap_with_crypto_encrypt(args, pol, plain_iter)
    else:
        enc_iter = plain_iter

    t.iniciar()
    cfg = {
        "canal": canal.descripcion(),
        "endpoint_origen": e_o.describe() if e_o else None,
        "endpoint_destino": e_d.describe() if e_d else None,
        "credencial": bool(cred),
        "cifrado": pol.algoritmo if pol.esquema.name != "NINGUNO" else "NONE",
        "ritmo_ms": getattr(ritmo, "tiempoBaseMs", None),
    }
    result = exfil_plugin.run(cfg, enc_iter)
    t.finalizarComoCompletada()

    if crypto_meta and args.crypto_meta_out:
        with open(args.crypto_meta_out, "w", encoding="utf-8") as f:
            json.dump({k:v for k,v in crypto_meta.items() if not k.startswith("_")}, f, indent=2)

    print_json({"accion":"send", "exfil_plugin": getattr(exfil_plugin, "name", type(exfil_plugin).__name__),
                "transferencia": t, "exfil_result": result,
                "crypto_meta": {k:v for k,v in (crypto_meta or {}).items() if not k.startswith('_')}})
    return 0

def cmd_receive(args) -> int:
    t = Transferencia(id=args.transfer_id, modo=Modo.RECEPTOR)
    canal = build_canal(args)
    e_o, e_d = build_endpoints(args)
    cred = build_credencial(args)
    pol = build_politica(args, EsquemaCifrado[args.cifrado.upper()])
    ritmo = build_perfil_ritmo(args)
    recurso_dest = build_recurso(args.recurso_tipo, args.recurso_ubicacion)

    t.canal = canal; t.endpointOrigen = e_o; t.endpointDestino = e_d
    t.politicaCifrado = pol; t.perfilRitmo = ritmo; t.recursoDestino = recurso_dest

    canal.validarConfiguracion()

    try:
        exfil_plugin = resolve_exfil_plugin(args.plugins_dir, args.canal, int(args.metodo), rol="server")
    except PluginNotFound as ex:
        print_json({"error":"PluginNotFound","detalle":str(ex)})
        return 2

    t.iniciar()
    cfg = {
        "canal": canal.descripcion(),
        "endpoint_origen": e_o.describe() if e_o else None,
        "endpoint_destino": e_d.describe() if e_d else None,
        "credencial": bool(cred),
        "cifrado": pol.algoritmo if pol.esquema.name != "NINGUNO" else "NONE",
        "ritmo_ms": getattr(ritmo, "tiempoBaseMs", None),
    }
    enc_iter = exfil_plugin.run(cfg)

    crypto_meta = None
    if pol.esquema.name != "NINGUNO":
        if not args.crypto_meta_in:
            print_json({"error":"CryptoMetaMissing","detalle":"Debe proporcionar --crypto-meta-in para descifrar"})
            return 2
        with open(args.crypto_meta_in, "r", encoding="utf-8") as f:
            crypto_meta = json.load(f)
        plain_iter = maybe_wrap_with_crypto_decrypt(args, pol, enc_iter, crypto_meta)
    else:
        plain_iter = enc_iter

    total = 0
    idx = 0
    out_path = args.out_file
    out_fh = open(out_path, "wb") if out_path else None
    try:
        for chunk in plain_iter:
            frag = Fragmento(id=f"F-{idx}", indice=idx, tam=len(chunk), payloadCifrado=chunk)
            frag.obtenerHuella()
            t.registrarFragmento(frag)
            total += len(chunk)
            if out_fh and chunk:
                out_fh.write(chunk)
            idx += 1
    finally:
        if out_fh:
            out_fh.close()

    t.finalizarComoCompletada()
    print_json({"accion":"receive", "exfil_plugin": getattr(exfil_plugin, "name", type(exfil_plugin).__name__),
                "transferencia": t, "salida_archivo": out_path or None})
    return 0

def cmd_scan_plugins(args) -> int:
    from tfg.plugins.loader import build_registry
    reg = build_registry(args.plugins_dir)
    clients = [{"canal":k[0],"metodo":k[1],"rol":k[2],"name":getattr(v,"name",type(v).__name__)} for k,v in reg.clients.items()]
    servers = [{"canal":k[0],"metodo":k[1],"rol":k[2],"name":getattr(v,"name",type(v).__name__)} for k,v in reg.servers.items()]
    cenc = [{"esquema":k[0],"algoritmo":k[1],"rol":k[2],"name":getattr(v,"name",type(v).__name__)} for k,v in reg.crypto_enc.items()]
    cdec = [{"esquema":k[0],"algoritmo":k[1],"rol":k[2],"name":getattr(v,"name",type(v).__name__)} for k,v in reg.crypto_dec.items()]
    print_json({"accion":"scan-plugins","directorio":args.plugins_dir,
                "exfil_clients":clients,"exfil_servers":servers,"crypto_encrypt":cenc,"crypto_decrypt":cdec})
    return 0

def cmd_check_file(args) -> int:
    from tfg.core.enums import TipoRecurso
    from tfg.core.models import RecursoDatos
    r = RecursoDatos(id="RES-CHK", tipo=TipoRecurso[args.recurso_tipo], ubicacion=args.recurso_ubicacion)
    ok = r.esAccesible()
    if ok:
        r.calcularHash()
    print_json({"accion":"check-file", "accesible": ok, "recurso": r})
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tfg_cli.py", description="TFG — CLI con plugins (M3: EXFIL + CRYPTO)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(parser: argparse.ArgumentParser, modo: str):
        parser.add_argument("--transfer-id", required=True, help="Identificador de la transferencia")
        parser.add_argument("--canal", required=True, choices=[e.name for e in TipoCanal], help="Tipo de canal")
        parser.add_argument("--canal-id", default="CAN-1", help="ID lógico del canal")
        parser.add_argument("--canal-nombre", default="canal", help="Nombre legible del canal")
        parser.add_argument("--metodo", required=True, type=int, help="Método/técnica concreta dentro del canal (entero)")
        parser.add_argument("--host", help="Host remoto (se refleja en parametros del canal)")
        parser.add_argument("--puerto", type=int, help="Puerto remoto (se refleja en parametros del canal)")
        parser.add_argument("--ruta", help="Ruta/endpoint remoto (se refleja en parametros del canal)")

        parser.add_argument("--origen-host", help="Endpoint origen: host")
        parser.add_argument("--origen-puerto", type=int, help="Endpoint origen: puerto")
        parser.add_argument("--origen-ruta", help="Endpoint origen: ruta")
        parser.add_argument("--dest-host", help="Endpoint destino: host")
        parser.add_argument("--dest-puerto", type=int, help="Endpoint destino: puerto")
        parser.add_argument("--dest-ruta", help="Endpoint destino: ruta")

        parser.add_argument("--cred-usuario")
        parser.add_argument("--cred-secreto")
        parser.add_argument("--cred-token")
        parser.add_argument("--cred-scope")

        parser.add_argument("--cifrado", default="NINGUNO", choices=[e.name for e in EsquemaCifrado])
        parser.add_argument("--algoritmo", help="Algoritmo de cifrado (SIMETRICO: XOR256 | ASIMETRICO: FAKE_RSA)")
        parser.add_argument("--clave-publica", help="Ruta a fichero de clave pública (bytes arbitrarios en M3 demo)")
        parser.add_argument("--clave-privada", help="Ruta a fichero de clave privada (bytes; SIMETRICO usa esta como clave)")
        parser.add_argument("--crypto-meta-out", help="Ruta para guardar metadatos de cifrado (send)")
        parser.add_argument("--crypto-meta-in", help="Ruta para leer metadatos de cifrado (receive)")

        parser.add_argument("--ritmo-base-ms", type=int, help="Tiempo base entre envíos (ms)")
        parser.add_argument("--ritmo-disp-ms", type=int, default=0, help="Dispersión aleatoria ± (ms)")

        parser.add_argument("--recurso-tipo", choices=[e.name for e in TipoRecurso], help="Tipo de recurso: ARCHIVO|MEMORIA|URL")
        parser.add_argument("--recurso-ubicacion", help="Ruta de archivo, mem://id o URL")
        parser.add_argument("--fragment-size", type=int, default=512, help="Tamaño de fragmento para envío (bytes)")
        parser.add_argument("--plugins-dir", default="plugins", help="Directorio raíz de plugins")

    sp_send = sub.add_parser("send", help="CU-003 — Proceso de envío (vía plugin EXFIL y CRYPTO encrypt opcional)")
    add_common(sp_send, "EMISOR")
    sp_send.set_defaults(_fn=cmd_send)

    sp_recv = sub.add_parser("receive", help="CU-005 — Recepción (vía plugin EXFIL y CRYPTO decrypt opcional)")
    add_common(sp_recv, "RECEPTOR")
    sp_recv.add_argument("--out-file", help="Ruta para guardar el resultado descifrado (opcional)")
    sp_recv.set_defaults(_fn=cmd_receive)

    sp_scan = sub.add_parser("scan-plugins", help="Descubrimiento de plugins EXFIL/CRYPTO")
    sp_scan.add_argument("--plugins-dir", default="plugins", help="Directorio raíz de plugins")
    sp_scan.set_defaults(_fn=cmd_scan_plugins)

    sp_chk = sub.add_parser("check-file", help="CU-002 — Verificación de recurso")
    sp_chk.add_argument("--recurso-tipo", choices=["ARCHIVO","MEMORIA","URL"], default="ARCHIVO")
    sp_chk.add_argument("--recurso-ubicacion", required=True)
    sp_chk.set_defaults(_fn=cmd_check_file)

    return p

def main(argv=None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        return args._fn(args)
    except SystemExit as se:
        raise
    except Exception as ex:
        print_json({"error": type(ex).__name__, "detalle": str(ex)})
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
