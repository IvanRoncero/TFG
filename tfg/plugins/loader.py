from __future__ import annotations
import importlib.util, sys, os, inspect, pathlib
from typing import Dict, Tuple

from .api import ExfilClientPlugin, ExfilServerPlugin
from .api_crypto import CryptoEncryptPlugin, CryptoDecryptPlugin

class _Registry:
    def __init__(self) -> None:
        self.exfil_client: Dict[Tuple[str,int], type] = {}
        self.exfil_server: Dict[Tuple[str,int], type] = {}
        self.crypto_enc: Dict[Tuple[str,str], type] = {}
        self.crypto_dec: Dict[Tuple[str,str], type] = {}

    def register_module(self, module) -> None:
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, ExfilClientPlugin) and cls is not ExfilClientPlugin and getattr(cls, "name", ""):
                self.exfil_client[(str(getattr(cls, "canal","")).upper(), int(getattr(cls,"metodo",0)))] = cls
            elif issubclass(cls, ExfilServerPlugin) and cls is not ExfilServerPlugin and getattr(cls, "name", ""):
                self.exfil_server[(str(getattr(cls, "canal","")).upper(), int(getattr(cls,"metodo",0)))] = cls
            elif issubclass(cls, CryptoEncryptPlugin) and cls is not CryptoEncryptPlugin and getattr(cls, "name", ""):
                self.crypto_enc[(str(getattr(cls, "esquema","")).upper(), str(getattr(cls,"algoritmo","")).upper())] = cls
            elif issubclass(cls, CryptoDecryptPlugin) and cls is not CryptoDecryptPlugin and getattr(cls, "name", ""):
                self.crypto_dec[(str(getattr(cls, "esquema","")).upper(), str(getattr(cls,"algoritmo","")).upper())] = cls

    def load_path(self, path: str) -> None:
        p = pathlib.Path(path)
        if p.is_dir():
            for f in p.rglob("*.py"):
                self._load_file(str(f))
        elif p.is_file() and path.endswith(".py"):
            self._load_file(path)

    def _load_file(self, fp: str) -> None:
        mod_name = "tfg_plugins_" + os.path.basename(fp).replace(".py","")
        spec = importlib.util.spec_from_file_location(mod_name, fp)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)  # type: ignore
            self.register_module(mod)

    def resolve_exfil(self, canal: str, metodo: int, rol: str):
        key = (canal.upper(), int(metodo))
        return (self.exfil_client if rol=='client' else self.exfil_server).get(key)

    def resolve_crypto(self, esquema: str, algoritmo: str, rol: str):
        key = (esquema.upper(), algoritmo.upper())
        return (self.crypto_enc if rol=='encrypt' else self.crypto_dec).get(key)

def scan_plugins(plugins_dir: str) -> _Registry:
    reg = _Registry()
    if plugins_dir and os.path.exists(plugins_dir):
        reg.load_path(plugins_dir)
    return reg

def resolve_exfil_plugin(canal, metodo: int, rol: str, plugins_dir: str):
    reg = scan_plugins(plugins_dir)
    cls = reg.resolve_exfil(str(canal), metodo, rol)
    if not cls:
        raise RuntimeError(f"No se encontró plugin EXFIL para canal={canal}, metodo={metodo}, rol={rol}")
    return cls()

def resolve_crypto_plugin(esquema, algoritmo: str, rol: str, plugins_dir: str):
    reg = scan_plugins(plugins_dir)
    cls = reg.resolve_crypto(str(esquema), algoritmo, rol)
    if not cls:
        raise RuntimeError(f"No se encontró plugin CRYPTO para esquema={esquema}, algoritmo={algoritmo}, rol={rol}")
    return cls()
