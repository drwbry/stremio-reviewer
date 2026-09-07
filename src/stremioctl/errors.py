"""Typed, stable errors used by the command-line and library layers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class StremioctlError(Exception):
    """Base error with a stable process exit code and safe public message."""

    message: str
    exit_code: int = 2

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)

    @property
    def public_message(self) -> str:
        """Return the message intended for a user-facing error boundary."""

        return self.message


class ConfigurationError(StremioctlError):
    """The local configuration cannot be used safely."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 2)


class SecurityError(StremioctlError):
    """A permission or secret-handling safety check failed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 2)


class ValidationError(StremioctlError):
    """Input is malformed or does not satisfy a data contract."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 2)


class NetworkError(StremioctlError):
    """A future remote operation failed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 3)


class AuthenticationError(StremioctlError):
    """A future authenticated operation was rejected."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 4)


class DriftError(StremioctlError):
    """A future guarded operation found changed remote state."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 5)


class ApplyError(StremioctlError):
    """A future apply or verification operation failed."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 6)


__all__ = [
    "ApplyError",
    "AuthenticationError",
    "ConfigurationError",
    "DriftError",
    "NetworkError",
    "SecurityError",
    "StremioctlError",
    "ValidationError",
]

