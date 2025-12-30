from __future__ import annotations
import importlib.util
import inspect
import os
from dataclasses import dataclass
from typing import Dict, Tuple, Type, Any

from .api import ExfilClientPlugin, ExfilServerPlugin
from .errors import PluginNotFound, PluginLoadError

Key = Tuple[str, int, str]  # (canal, metodo, rol)

@dataclass
class Registry:
    clients: Dict[Key, ExfilClientPlugin]
    servers: Dict[Key, ExfilServerPlugin]

def _safe_import(py_path: str):
    """Importa un .py arbitrario sin añadirlo al sys.path global."""
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
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if issubclass(obj, ExfilClientPlugin) and obj is not ExfilClientPlugin:
            client_classes.append(obj)
        if issubclass(obj, ExfilServerPlugin) and obj is not ExfilServerPlugin:
            server_classes.append(obj)
    return client_classes, server_classes

def build_registry(base_dir: str) -> Registry:
    base_dir = base_dir or "plugins"
    clients: Dict[Key, ExfilClientPlugin] = {}
    servers: Dict[Key, ExfilServerPlugin] = {}
    if not os.path.isdir(base_dir):
        return Registry(clients=clients, servers=servers)

    for root, _, files in os.walk(base_dir):
        for f in files:
            if not f.endswith(".py"):
                continue
            py_path = os.path.join(root, f)
            mod = _safe_import(py_path)
            clzs_c, clzs_s = _find_plugin_classes(mod)

            for cls in clzs_c:
                inst: ExfilClientPlugin = cls()  # type: ignore[call-arg]
                key: Key = (inst.canal.upper(), int(inst.metodo), "client")
                clients[key] = inst
            for cls in clzs_s:
                inst: ExfilServerPlugin = cls()  # type: ignore[call-arg]
                key: Key = (inst.canal.upper(), int(inst.metodo), "server")
                servers[key] = inst
    return Registry(clients=clients, servers=servers)

def resolve_exfil_plugin(base_dir: str, canal: str, metodo: int, rol: str):
    reg = build_registry(base_dir)
    key: Key = (canal.upper(), int(metodo), rol.lower())
    if rol.lower() == "client":
        if key in reg.clients:
            return reg.clients[key]
    else:
        if key in reg.servers:
            return reg.servers[key]
    raise PluginNotFound(f"No hay plugin para canal={canal} metodo={metodo} rol={rol} en {base_dir}")
