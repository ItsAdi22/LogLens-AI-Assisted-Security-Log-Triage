"""Command Line Interface for LogLens."""

from typing import Annotated

import typer
from rich.console import Console

from loglens import __version__

app = typer.Typer(
    name="loglens",
    help="LogLens — AI-Assisted Security Log Triage (Open Source).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print the version and exit."""
    if value:
        console.print(f"LogLens [bold cyan]v{__version__}[/bold cyan]")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """LogLens CLI entrypoint."""


def main() -> None:
    """Main CLI execution function."""
    app()


if __name__ == "__main__":
    main()
