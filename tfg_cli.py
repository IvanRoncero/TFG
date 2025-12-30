# tfg_cli.py — CLI con resolución de plugins (M2)
from __future__ import annotations

import argparse
import base64
import json
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Iterable, Iterator

from tfg.core.models import (
    Transferencia, Fragmento, Canal, Endpoint, Credencial,
    PoliticaCifrado, PerfilRitmo, RecursoDatos
)
from tfg.core.enums import (
    Modo, TipoCanal, EsquemaCifrado, TipoRecurso
)
from tfg.plugins.loader import resolve_exfil_plugin
from tfg.plugins.errors import PluginNotFound

# ---------------- utilidades de serialización ---------------- #
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

# ---------------- construcción de objetos desde CLI ---------------- #
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

def _read_key_file(path: str | None):
    if not path:
        return None
    if not os.path.exists(path):
        raise FileNotFoundError(f"No existe la clave: {path}")
    with open(path, "rb") as f:
        return f.read()

def build_politica(args, esquema: EsquemaCifrado) -> PoliticaCifrado:
    return PoliticaCifrado(
        id="POL-1",
        esquema=esquema,
        algoritmo=args.algoritmo or ("NONE" if esquema == EsquemaCifrado.NINGUNO else "UNSET"),
        clavePublica=_read_key_file(args.clave_publica),
        clavePrivada=_read_key_file(args.clave_privada),
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

# ---------------- utilidades de fragmentación ---------------- #
def iter_payload_and_register(t: Transferencia, recurso: RecursoDatos | None, frag_size: int) -> Iterable[bytes]:
    """Genera chunks y registra Fragmento en la Transferencia."""
    # ARCHIVO
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
    # OTROS (mem/url → demostración)
    payload = recurso.ubicacion.encode("utf-8") if recurso else b""
    frag = Fragmento(id="F-0", indice=0, tam=len(payload), payloadCifrado=payload)
    frag.obtenerHuella()
    t.registrarFragmento(frag)
    yield payload

# ---------------- comandos ---------------- #
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

    # Resolver plugin requerido
    try:
        plugin = resolve_exfil_plugin(args.plugins_dir, args.canal, int(args.metodo), rol="client")
    except PluginNotFound as ex:
        print_json({"error":"PluginNotFound", "detalle":str(ex)})
        return 2

    # Ejecutar
    t.iniciar()
    payload_iter = iter_payload_and_register(t, recurso, args.fragment_size)
    cfg = {
        "canal": canal.descripcion(),
        "endpoint_origen": e_o.describe() if e_o else None,
        "endpoint_destino": e_d.describe() if e_d else None,
        "credencial": bool(cred),
        "cifrado": pol.algoritmo,
        "ritmo_ms": getattr(ritmo, "tiempoBaseMs", None),
    }
    result = plugin.run(cfg, payload_iter)
    t.finalizarComoCompletada()

    print_json({"accion":"send", "plugin": getattr(plugin, "name", type(plugin).__name__),
                "transferencia": t, "plugin_result": result})
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

    # Resolver plugin requerido
    try:
        plugin = resolve_exfil_plugin(args.plugins_dir, args.canal, int(args.metodo), rol="server")
    except PluginNotFound as ex:
        print_json({"error":"PluginNotFound", "detalle":str(ex)})
        return 2

    # Ejecutar
    t.iniciar()
    cfg = {
        "canal": canal.descripcion(),
        "endpoint_origen": e_o.describe() if e_o else None,
        "endpoint_destino": e_d.describe() if e_d else None,
        "credencial": bool(cred),
        "cifrado": pol.algoritmo,
        "ritmo_ms": getattr(ritmo, "tiempoBaseMs", None),
    }
    received = plugin.run(cfg)  # iterable de bytes
    idx = 0
    for chunk in received:
        frag = Fragmento(id=f"F-{idx}", indice=idx, tam=len(chunk), payloadCifrado=chunk)
        frag.obtenerHuella()
        t.registrarFragmento(frag)
        idx += 1
    t.finalizarComoCompletada()

    print_json({"accion":"receive", "plugin": getattr(plugin, "name", type(plugin).__name__),
                "transferencia": t, "resumen":{"frags": t.numFragmentos, "bytes": t.bytesTotales}})
    return 0

def cmd_scan_plugins(args) -> int:
    # Simplemente usa el loader para construir el registro y mostrar claves
    from tfg.plugins.loader import build_registry
    reg = build_registry(args.plugins_dir)
    clients = [{"canal":k[0],"metodo":k[1],"rol":k[2],"name":getattr(v,"name",type(v).__name__)} for k,v in reg.clients.items()]
    servers = [{"canal":k[0],"metodo":k[1],"rol":k[2],"name":getattr(v,"name",type(v).__name__)} for k,v in reg.servers.items()]
    print_json({"accion":"scan-plugins","directorio":args.plugins_dir,"clients":clients,"servers":servers})
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

# ---------------- argparse ---------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tfg_cli.py", description="TFG — CLI con plugins (M2)")
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
        parser.add_argument("--algoritmo", help="Algoritmo de cifrado (p.ej., AES-256-GCM, RSA-OAEP)")
        parser.add_argument("--clave-publica", help="Ruta a fichero de clave pública (si aplica)")
        parser.add_argument("--clave-privada", help="Ruta a fichero de clave privada (si aplica)")

        parser.add_argument("--ritmo-base-ms", type=int, help="Tiempo base entre envíos (ms)")
        parser.add_argument("--ritmo-disp-ms", type=int, default=0, help="Dispersión aleatoria ± (ms)")

        parser.add_argument("--recurso-tipo", choices=[e.name for e in TipoRecurso], help="Tipo de recurso: ARCHIVO|MEMORIA|URL")
        parser.add_argument("--recurso-ubicacion", help="Ruta de archivo, mem://id o URL")
        parser.add_argument("--fragment-size", type=int, default=512, help="Tamaño de fragmento para envío (bytes)")
        parser.add_argument("--plugins-dir", default="plugins", help="Directorio raíz de plugins")

    # send
    sp_send = sub.add_parser("send", help="CU-003 — Proceso de envío (vía plugin de exfil CLIENT)")
    add_common(sp_send, "EMISOR")
    sp_send.set_defaults(_fn=cmd_send)

    # receive
    sp_recv = sub.add_parser("receive", help="CU-005 — Recepción (vía plugin de exfil SERVER)")
    add_common(sp_recv, "RECEPTOR")
    sp_recv.set_defaults(_fn=cmd_receive)

    # scan-plugins
    sp_scan = sub.add_parser("scan-plugins", help="CU-001 — Descubrimiento real de plugins")
    sp_scan.add_argument("--plugins-dir", default="plugins", help="Directorio raíz de plugins")
    sp_scan.set_defaults(_fn=cmd_scan_plugins)

    # check-file
    sp_chk = sub.add_parser("check-file", help="CU-002 — Verificación de recurso")
    sp_chk.add_argument("--recurso-tipo", choices=[e.name for e in TipoRecurso], default="ARCHIVO")
    sp_chk.add_argument("--recurso-ubicacion", required=True)
    sp_chk.set_defaults(_fn=cmd_check_file)

    return p

def main(argv=None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        return args._fn(args)
    except Exception as ex:
        print_json({"error": type(ex).__name__, "detalle": str(ex)})
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
