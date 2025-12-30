# tfg/core/errors.py
class DomainError(Exception):
    """Error genérico de dominio."""


class EstadoInvalido(DomainError):
    """Transición de estado no permitida."""


class ValidacionError(DomainError):
    """Datos o configuración inválidos."""


class AccesoRecursoError(DomainError):
    """El RecursoDatos no es accesible o falla su lectura."""
