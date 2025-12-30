# tfg/core/value_objects.py
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class Mensaje:
    """Contenedor de payloads codificados (fragmento ya transformado por un método)."""
    raw: bytes


@dataclass(frozen=True)
class Resultado:
    ok: bool
    detalle: str = ""
