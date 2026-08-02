"""Anteumbra v1.0 entry point — delegates to CLI."""

from anteumbra.cli.main import cli


def main():
    """Entry point for pyproject.toml [project.scripts]."""
    cli()


if __name__ == "__main__":
    main()
