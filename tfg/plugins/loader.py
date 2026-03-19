from __future__ import annotations

import os
import sys
import inspect
import pathlib
import importlib
from typing import Dict, Tuple, List

from .api import ExfilClientPlugin, ExfilServerPlugin
from .api_crypto import CryptoEncryptPlugin, CryptoDecryptPlugin


class _Registry:
    def __init__(self) -> None:
        self.exfil_client: Dict[Tuple[str, int], type] = {}
        self.exfil_server: Dict[Tuple[str, int], type] = {}
        self.crypto_enc: Dict[Tuple[str, str], type] = {}
        self.crypto_dec: Dict[Tuple[str, str], type] = {}
        self.load_errors: List[str] = []

    def register_module(self, module) -> None:
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, ExfilClientPlugin) and cls is not ExfilClientPlugin and getattr(cls, "name", ""):
                self.exfil_client[(str(getattr(cls, "canal", "")).upper(), int(getattr(cls, "metodo", 0)))] = cls
            elif issubclass(cls, ExfilServerPlugin) and cls is not ExfilServerPlugin and getattr(cls, "name", ""):
                self.exfil_server[(str(getattr(cls, "canal", "")).upper(), int(getattr(cls, "metodo", 0)))] = cls
            elif issubclass(cls, CryptoEncryptPlugin) and cls is not CryptoEncryptPlugin and getattr(cls, "name", ""):
                self.crypto_enc[(str(getattr(cls, "esquema", "")).upper(), str(getattr(cls, "algoritmo", "")).upper())] = cls
            elif issubclass(cls, CryptoDecryptPlugin) and cls is not CryptoDecryptPlugin and getattr(cls, "name", ""):
                self.crypto_dec[(str(getattr(cls, "esquema", "")).upper(), str(getattr(cls, "algoritmo", "")).upper())] = cls

    def load_path(self, path: str) -> None:
        plugins_dir = pathlib.Path(path).resolve()

        if not plugins_dir.exists():
            return

        # Queremos poder importar módulos como: plugins.exfil.dns_client
        # Para ello necesitamos que el directorio padre de "plugins" esté en sys.path
        # Ej: E:\TFG-REPO\plugins\...  => sys.path incluye E:\TFG-REPO
        repo_root = plugins_dir.parent
        if str(repo_root) not in sys.path:
            # Lo añadimos al final para minimizar conflictos/shadowing
            sys.path.append(str(repo_root))

        if plugins_dir.is_dir():
            for f in plugins_dir.rglob("*.py"):
                if f.name == "__init__.py":
                    continue
                self._load_file(f, repo_root)
        elif plugins_dir.is_file() and plugins_dir.suffix == ".py":
            self._load_file(plugins_dir, repo_root)

    def _load_file(self, file_path: pathlib.Path, repo_root: pathlib.Path) -> None:
        file_path = file_path.resolve()

        # Construimos el nombre dotted relativo al repo_root
        # Ej: repo_root=E:\TFG-REPO, file=E:\TFG-REPO\plugins\exfil\dns_client.py
        # => plugins.exfil.dns_client
        rel = file_path.relative_to(repo_root).with_suffix("")
        mod_name = ".".join(rel.parts)

        # Evita recarga duplicada
        if mod_name in sys.modules:
            return

        try:
            mod = importlib.import_module(mod_name)
            self.register_module(mod)
        except Exception as e:
            self.load_errors.append(f"{mod_name}: {type(e).__name__}: {e}")

    def resolve_exfil(self, canal: str, metodo: int, rol: str):
        key = (canal.upper(), int(metodo))
        return (self.exfil_client if rol == "client" else self.exfil_server).get(key)

    def resolve_crypto(self, esquema: str, algoritmo: str, rol: str):
        key = (esquema.upper(), algoritmo.upper())
        return (self.crypto_enc if rol == "encrypt" else self.crypto_dec).get(key)


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
