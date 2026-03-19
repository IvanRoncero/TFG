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
    HTTP = "HTTP"
    TCP = "TCP"
    ICMP = "ICMP"
    SSH = "SSH"
    FTP = "FTP"
    DNS = "DNS"
    SMTP = "SMTP"

class EsquemaCifrado(str, Enum):
    NINGUNO = "NINGUNO"
    SIMETRICO = "SIMETRICO"
    ASIMETRICO = "ASIMETRICO"

class TipoRecurso(str, Enum):
    ARCHIVO = "ARCHIVO"
    MEMORIA = "MEMORIA"
    URL = "URL"
