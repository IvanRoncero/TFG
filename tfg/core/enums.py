# tfg/core/enums.py
from __future__ import annotations
from enum import Enum


class Modo(str, Enum):
    EMISOR = "emisor"
    RECEPTOR = "receptor"


class Estado(str, Enum):
    PENDIENTE = "pendiente"
    EN_PROGRESO = "en_progreso"
    COMPLETADA = "completada"
    FALLIDA = "fallida"
    CANCELADA = "cancelada"


class TipoCanal(str, Enum):
    TCP = "TCP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    SSH = "SSH"
    FTP = "FTP"
    DNS = "DNS"
    SMTP = "SMTP"


class EsquemaCifrado(str, Enum):
    SIMETRICO = "SIMETRICO"
    ASIMETRICO = "ASIMETRICO"
    NINGUNO = "NINGUNO"


class TipoRecurso(str, Enum):
    ARCHIVO = "archivo"
    MEMORIA = "memoria"
    URL = "url"
