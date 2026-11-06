"""Nikto adapter. Planned: this module refuses to execute."""

MODE = "Planned"


def run(*_args: object, **_kwargs: object) -> None:
    """Refuse. There is no Nikto executor in this build."""
    raise RuntimeError("nikto is planned and has no executor")
