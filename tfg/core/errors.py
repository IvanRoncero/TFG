class DomainError(Exception):
    pass

class EstadoInvalido(DomainError):
    pass

class ValidacionError(DomainError):
    pass

class AccesoRecursoError(DomainError):
    pass
