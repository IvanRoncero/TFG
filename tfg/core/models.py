from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional, Dict, Any
import time, json, hashlib, random, os

from .enums import Modo, Estado, TipoCanal, EsquemaCifrado, TipoRecurso
from .errors import *

@dataclass
class Fragmento:
    id: str
    indice: int
    tam: int
    hashParcial: str | None = None
    recibidoEnviadoEn: float | None = None
    rutaAlmacen: str | None = None
    payloadCifrado: bytes | None = None

    def obtenerHuella(self) -> str:
        if self.payloadCifrado is not None:
            h = hashlib.sha256(self.payloadCifrado).hexdigest()
        elif self.rutaAlmacen and Path(self.rutaAlmacen).exists():
            h = hashlib.sha256(Path(self.rutaAlmacen).read_bytes()).hexdigest()
        else:
            h = self.hashParcial or ""
        self.hashParcial = h
        return h

    def marcarRecibido(self) -> None:
        self.recibidoEnviadoEn = time.time()

@dataclass
class Transferencia:
    id: str
    modo: Modo
    estado: Estado = Estado.PENDIENTE
    inicio: float | None = None
    fin: float | None = None
    actualizadoEn: float | None = None
    bytesTotales: int = 0
    numFragmentos: int = 0
    reintentos: int = 0
    error: str | None = None

    def iniciar(self) -> None:
        if self.estado not in (Estado.PENDIENTE, Estado.FALLIDA, Estado.CANCELADA):
            raise EstadoInvalido("No se puede iniciar desde el estado actual")
        self.inicio = time.time()
        self.estado = Estado.EN_PROGRESO
        self.actualizadoEn = self.inicio

    def registrarFragmento(self, frag: Fragmento) -> None:
        self.numFragmentos += 1
        self.bytesTotales += frag.tam
        self.actualizadoEn = time.time()

    def calcularProgreso(self, total_estimado: int | None = None) -> float:
        if (total_estimado or 0) > 0:
            return min(100.0, 100.0 * self.bytesTotales / float(total_estimado))
        return 0.0

    def finalizarComoCompletada(self) -> None:
        self.estado = Estado.COMPLETADA
        self.fin = time.time()
        self.actualizadoEn = self.fin

    def finalizarComoFallida(self, mensaje: str) -> None:
        self.estado = Estado.FALLIDA
        self.error = mensaje
        self.fin = time.time()
        self.actualizadoEn = self.fin

    def cancelar(self) -> None:
        self.estado = Estado.CANCELADA
        self.fin = time.time()
        self.actualizadoEn = self.fin

@dataclass
class Canal:
    id: str = ""
    tipo: TipoCanal = TipoCanal.HTTP
    nombre: str = ""
    metodo: int = 1
    parametros: Dict[str, Any] = field(default_factory=dict)

    def validarConfiguracion(self) -> None:
        if self.tipo == TipoCanal.HTTP and self.metodo not in (1,2):
            raise ValidacionError("HTTP.metodo debe ser 1 (headers) o 2 (verbs)")

    def descripcion(self) -> str:
        return f"{self.tipo.name} metodo={self.metodo} parametros={self.parametros}"

@dataclass
class Endpoint:
    id: str = ""
    host: str | None = None
    puerto: int | None = None
    ruta: str | None = None

    def normalizar(self) -> None:
        if self.puerto is not None and not (0 < int(self.puerto) < 65536):
            raise ValidacionError("Puerto inválido")

    def esSeguro(self) -> bool:
        return False

    def describe(self) -> str:
        return f"{self.host}:{self.puerto}{self.ruta or ''}"

@dataclass
class Credencial:
    id: str = ""
    usuario: str | None = None
    secreto: str | None = None
    token: str | None = None
    scope: str | None = None
    ultimaVezUsado: float | None = None

    def marcarUso(self) -> None:
        self.ultimaVezUsado = time.time()

    def rotarSecreto(self, nuevo: str) -> None:
        self.secreto = nuevo
        self.marcarUso()

    def esValidaPara(self, endpoint: Endpoint) -> bool:
        return True

@dataclass
class PoliticaCifrado:
    id: str = ""
    esquema: EsquemaCifrado = EsquemaCifrado.NINGUNO
    algoritmo: str = ""
    clavePublica: bytes | None = None
    clavePrivada: bytes | None = None
    parametros: Dict[str, Any] = field(default_factory=dict)

    def estaActiva(self) -> bool:
        return self.esquema != EsquemaCifrado.NINGUNO

    def esCompatibleCon(self, canal: Canal) -> bool:
        return True

    def aplicarA(self, transferencia: Transferencia) -> None:
        pass

@dataclass
class PerfilRitmo:
    id: str = ""
    tiempoBaseMs: int = 0
    dispersionMs: int = 0

    def proximaEspera(self) -> float:
        if self.tiempoBaseMs <= 0 and self.dispersionMs <= 0:
            return 0.0
        delta = random.uniform(-self.dispersionMs, self.dispersionMs)
        return max(0.0, (self.tiempoBaseMs + delta) / 1000.0)

@dataclass
class RecursoDatos:
    id: str = ""
    tipo: TipoRecurso = TipoRecurso.ARCHIVO
    ubicacion: str = ""
    tam: int | None = None
    hash: str | None = None

    def esAccesible(self) -> bool:
        if self.tipo == TipoRecurso.ARCHIVO:
            return Path(self.ubicacion).exists()
        return True

    def calcularHash(self) -> str:
        if self.tipo == TipoRecurso.ARCHIVO and Path(self.ubicacion).exists():
            h = hashlib.sha256()
            with open(self.ubicacion, "rb") as f:
                for b in iter(lambda: f.read(65536), b""):
                    h.update(b)
            self.hash = h.hexdigest()
        return self.hash or ""

    def iter_chunks(self, fragment_size: int) -> Iterator[bytes]:
        if self.tipo != TipoRecurso.ARCHIVO:
            raise RecursoNoAccesible("Solo ARCHIVO soportado en esta versión")
        with open(self.ubicacion, "rb") as f:
            while True:
                chunk = f.read(fragment_size)
                if not chunk:
                    break
                yield chunk
