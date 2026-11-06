"""OWASP ZAP adapter. Planned: this module refuses to execute."""

MODE = "Planned"


def run(*_args: object, **_kwargs: object) -> None:
    """Refuse. The Docker daemon API is not wired."""
    raise RuntimeError("zap is planned and has no executor")
