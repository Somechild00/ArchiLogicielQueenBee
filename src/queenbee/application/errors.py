"""Erreurs de la couche application."""


class AccessDeniedError(Exception):
    """Le principal n'a pas le rôle requis. Message volontairement générique."""
