from __future__ import annotations
import importlib.util
import inspect
import os
from dataclasses import dataclass
from typing import Dict, Tuple

from .api import ExfilClientPlugin, ExfilServerPlugin
from .api_crypto import CryptoEncryptPlugin, CryptoDecryptPlugin
from .errors import PluginNotFound, PluginLoadError

KeyExfil = Tuple[str, int, str]    # (canal, metodo, rol: "client"|"server")
KeyCrypto = Tuple[str, str, str]   # (esquema, algoritmo, rol: "encrypt"|"decrypt")

@dataclass
class Registry:
    clients: Dict[KeyExfil, ExfilClientPlugin]
    servers: Dict[KeyExfil, ExfilServerPlugin]
    crypto_enc: Dict[KeyCrypto, CryptoEncryptPlugin]
    crypto_dec: Dict[KeyCrypto, CryptoDecryptPlugin]

def _safe_import(py_path: str):
    mod_name = "plugin_" + os.path.splitext(os.path.basename(py_path))[0]
    spec = importlib.util.spec_from_file_location(mod_name, py_path)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"No se pudo crear spec para {py_path}")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    except Exception as ex:
        raise PluginLoadError(f"Error importando {py_path}: {ex}")
    return mod

def _find_plugin_classes(mod):
    client_classes = []
    server_classes = []
    crypto_enc_classes = []
    crypto_dec_classes = []
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if issubclass(obj, ExfilClientPlugin) and obj is not ExfilClientPlugin:
            client_classes.append(obj)
        if issubclass(obj, ExfilServerPlugin) and obj is not ExfilServerPlugin:
            server_classes.append(obj)
        if issubclass(obj, CryptoEncryptPlugin) and obj is not CryptoEncryptPlugin:
            crypto_enc_classes.append(obj)
        if issubclass(obj, CryptoDecryptPlugin) and obj is not CryptoDecryptPlugin:
            crypto_dec_classes.append(obj)
    return client_classes, server_classes, crypto_enc_classes, crypto_dec_classes

def build_registry(base_dir: str) -> Registry:
    base_dir = base_dir or "plugins"
    clients: Dict[KeyExfil, ExfilClientPlugin] = {}
    servers: Dict[KeyExfil, ExfilServerPlugin] = {}
    crypto_enc: Dict[KeyCrypto, CryptoEncryptPlugin] = {}
    crypto_dec: Dict[KeyCrypto, CryptoDecryptPlugin] = {}
    if not os.path.isdir(base_dir):
        return Registry(clients=clients, servers=servers, crypto_enc=crypto_enc, crypto_dec=crypto_dec)

    for root, _, files in os.walk(base_dir):
        for f in files:
            if not f.endswith(".py"):
                continue
            py_path = os.path.join(root, f)
            mod = _safe_import(py_path)
            cl_c, cl_s, cl_ce, cl_cd = _find_plugin_classes(mod)

            for cls in cl_c:
                inst = cls()  # type: ignore
                key = (inst.canal.upper(), int(inst.metodo), "client")
                clients[key] = inst

            for cls in cl_s:
                inst = cls()  # type: ignore
                key = (inst.canal.upper(), int(inst.metodo), "server")
                servers[key] = inst

            for cls in cl_ce:
                inst = cls()  # type: ignore
                key = (inst.esquema.upper(), inst.algoritmo.upper(), "encrypt")
                crypto_enc[key] = inst

            for cls in cl_cd:
                inst = cls()  # type: ignore
                key = (inst.esquema.upper(), inst.algoritmo.upper(), "decrypt")
                crypto_dec[key] = inst

    return Registry(clients=clients, servers=servers, crypto_enc=crypto_enc, crypto_dec=crypto_dec)

def resolve_exfil_plugin(base_dir: str, canal: str, metodo: int, rol: str):
    reg = build_registry(base_dir)
    key = (canal.upper(), int(metodo), rol.lower())
    if rol.lower() == "client":
        if key in reg.clients:
            return reg.clients[key]
    else:
        if key in reg.servers:
            return reg.servers[key]
    raise PluginNotFound(f"No hay plugin EXFIL para canal={canal} metodo={metodo} rol={rol} en {base_dir}")

def resolve_crypto_plugin(base_dir: str, esquema: str, algoritmo: str, rol: str):
    reg = build_registry(base_dir)
    key = (esquema.upper(), algoritmo.upper(), rol.lower())
    if rol.lower() == "encrypt":
        if key in reg.crypto_enc:
            return reg.crypto_enc[key]
    else:
        if key in reg.crypto_dec:
            return reg.crypto_dec[key]
    raise PluginNotFound(f"No hay plugin CRYPTO para esquema={esquema} algoritmo={algoritmo} rol={rol} en {base_dir}")
