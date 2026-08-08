"""Exception hierarchy."""

from __future__ import annotations


class BlastRadiusError(Exception):
    """Base class for expected, user-facing failures."""


class PlanError(BlastRadiusError):
    """The plan JSON is missing, malformed, or in an unexpected format."""


class PolicyError(BlastRadiusError):
    """The policy file is malformed or internally inconsistent."""

    def __init__(self, message: str, *, source: str | None = None) -> None:
        self.source = source
        super().__init__(f"{source}: {message}" if source else message)
