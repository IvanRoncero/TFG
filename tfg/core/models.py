from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .enums import EsquemaCifrado, Estado, Modo, TipoCanal, TipoRecurso
from .errors import AccesoRecursoError, EstadoInvalido, ValidacionError

def _now() -> datetime:
    return datetime.now(timezone.utc)

@dataclass
class Transferencia:
    id: str
    modo: Modo
    estado: Estado = Estado.PENDIENTE
    inicio: Optional[datetime] = None
    fin: Optional[datetime] = None
    actualizadoEn: Optional[datetime] = None
    bytesTotales: int = 0
    numFragmentos: int = 0
    reintentos: int = 0
    error: str = ""

    canal: Optional["Canal"] = None
    endpointOrigen: Optional["Endpoint"] = None
    endpointDestino: Optional["Endpoint"] = None
    politicaCifrado: Optional["PoliticaCifrado"] = None
    perfilRitmo: Optional["PerfilRitmo"] = None
    recursoOrigen: Optional["RecursoDatos"] = None
    recursoDestino: Optional["RecursoDatos"] = None

    def _assert_estado(self, permitido: set[Estado]) -> None:
        if self.estado not in permitido:
            raise EstadoInvalido(f"Estado {self.estado} no permite esta operación")

    def iniciar(self) -> None:
        self._assert_estado({Estado.PENDIENTE})
        self.estado = Estado.EN_PROGRESO
        self.inicio = _now()
        self.actualizadoEn = self.inicio

    def registrarFragmento(self, fragmento: "Fragmento") -> None:
        self._assert_estado({Estado.EN_PROGRESO})
        self.numFragmentos += 1
        if fragmento.tam is not None:
            self.bytesTotales += int(fragmento.tam)
        self.actualizadoEn = _now()

    def calcularProgreso(self, total_esperado_bytes: Optional[int] = None,
                         total_esperado_fragmentos: Optional[int] = None) -> float:
        if total_esperado_bytes and total_esperado_bytes > 0:
            return min(100.0, 100.0 * (self.bytesTotales / total_esperado_bytes))
        if total_esperado_fragmentos and total_esperado_fragmentos > 0:
            return min(100.0, 100.0 * (self.numFragmentos / total_esperado_fragmentos))
        return 0.0

    def finalizarComoCompletada(self) -> None:
        self._assert_estado({Estado.EN_PROGRESO})
        self.estado = Estado.COMPLETADA
        self.fin = _now()
        self.actualizadoEn = self.fin

    def finalizarComoFallida(self, mensaje: str) -> None:
        self._assert_estado({Estado.EN_PROGRESO, Estado.PENDIENTE})
        self.estado = Estado.FALLIDA
        self.error = mensaje
        self.fin = _now()
        self.actualizadoEn = self.fin

    def cancelar(self) -> None:
        self._assert_estado({Estado.PENDIENTE, Estado.EN_PROGRESO})
        self.estado = Estado.CANCELADA
        self.fin = _now()
        self.actualizadoEn = self.fin

@dataclass
class Fragmento:
    id: str
    indice: int
    tam: int
    hashParcial: str = ""
    recibidoEnviadoEn: Optional[datetime] = None
    rutaAlmacen: str = ""
    payloadCifrado: bytes = b""

    def obtenerHuella(self) -> str:
        if self.hashParcial:
            return self.hashParcial
        h = hashlib.sha256()
        if self.payloadCifrado:
            h.update(self.payloadCifrado)
        elif self.rutaAlmacen and os.path.exists(self.rutaAlmacen):
            with open(self.rutaAlmacen, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        else:
            h.update(f"{self.id}:{self.indice}:{self.tam}".encode("utf-8"))
        self.hashParcial = h.hexdigest()
        return self.hashParcial

    def marcarRecibido(self) -> None:
        self.recibidoEnviadoEn = _now()

@dataclass
class Canal:
    id: str
    tipo: TipoCanal
    nombre: str
    metodo: int
    parametros: dict[str, Any] = field(default_factory=dict)

    def validarConfiguracion(self) -> None:
        if not isinstance(self.parametros, dict):
            raise ValidacionError("parametros debe ser un dict")
        if self.tipo in {TipoCanal.HTTP, TipoCanal.SSH, TipoCanal.FTP, TipoCanal.SMTP}:
            for k in ("host", "puerto"):
                if k not in self.parametros:
                    raise ValidacionError(f"Falta clave requerida en parametros: {k}")

    def descripcion(self) -> str:
        return f"{self.tipo.name}::{self.nombre} metodo={self.metodo} cfg={json.dumps(self.parametros, ensure_ascii=False)}"

@dataclass
class Endpoint:
    id: str
    host: str
    puerto: int | None = None
    ruta: str = ""

    def normalizar(self) -> None:
        self.host = (self.host or "").strip()
        self.ruta = (self.ruta or "").strip()
        if not self.host:
            raise ValidacionError("Endpoint.host es obligatorio")

    def esSeguro(self) -> bool:
        return (self.puerto in {443, 22, 465, 993}) or self.ruta.startswith("https://")

    def describe(self) -> str:
        p = f":{self.puerto}" if self.puerto else ""
        r = self.ruta if self.ruta else ""
        return f"{self.host}{p}{('/' + r) if r and not r.startswith('/') else r}"

@dataclass
class Credencial:
    id: str
    usuario: str | None = None
    secreto: str | None = None
    token: str | None = None
    scope: str | None = None
    ultimaVezUsado: Optional[datetime] = None

    def marcarUso(self) -> None:
        self.ultimaVezUsado = _now()

    def rotarSecreto(self, nuevo: str) -> None:
        self.secreto = nuevo
        self.marcarUso()

    def esValidaPara(self, endpoint: Endpoint) -> bool:
        return bool(endpoint and endpoint.host)

@dataclass
class PoliticaCifrado:
    id: str
    esquema: EsquemaCifrado
    algoritmo: str
    clavePublica: Optional[bytes] = None
    clavePrivada: Optional[bytes] = None

    def estaActiva(self) -> bool:
        return self.esquema != EsquemaCifrado.NINGUNO

    def esCompatibleCon(self, canal: Canal) -> bool:
        return True

    def aplicarA(self, transferencia: Transferencia) -> None:
        transferencia.politicaCifrado = self

@dataclass
class PerfilRitmo:
    id: str
    tiempoBaseMs: int
    dispersionMs: int = 0

    def proximaEspera(self) -> float:
        base = float(self.tiempoBaseMs) / 1000.0
        disp = float(self.dispersionMs) / 1000.0
        if disp <= 0:
            return base
        return max(0.0, base + random.uniform(-disp, disp))

@dataclass
class RecursoDatos:
    id: str
    tipo: TipoRecurso
    ubicacion: str
    tam: int | None = None
    hash: str | None = None

    def calcularHash(self) -> str:
        if self.tipo == TipoRecurso.ARCHIVO and os.path.exists(self.ubicacion):
            h = hashlib.sha256()
            with open(self.ubicacion, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            self.hash = h.hexdigest()
            self.tam = os.path.getsize(self.ubicacion)
            return self.hash
        self.hash = hashlib.sha256(self.ubicacion.encode("utf-8")).hexdigest()
        return self.hash

    def esAccesible(self) -> bool:
        if self.tipo == TipoRecurso.ARCHIVO:
            return os.path.isfile(self.ubicacion)
        if self.tipo == TipoRecurso.MEMORIA:
            return self.ubicacion.startswith("mem://")
        if self.tipo == TipoRecurso.URL:
            return self.ubicacion.startswith(("http://", "https://"))
        return False
