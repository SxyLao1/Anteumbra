"""Click commands that export the bundled Anteumbra agent skill."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import click

SKILL_NAME = "anteumbra"
SKILL_FILENAME = "SKILL.md"
SKILL_ROOT_HINT = (
    "Agents discover skills as <skills-root>/<name>/SKILL.md; point this command at "
    "your agent's skills root."
)


def skill_dir(source_root: Path) -> Path:
    """Return the packaged skill directory inside the wheel."""
    return source_root / SKILL_NAME


def discover_skill_file(source_root: Path) -> Path:
    """Return the packaged SKILL.md path."""
    return skill_dir(source_root) / SKILL_FILENAME


def export_skill(
    source_root: Path,
    destination: Path,
    *,
    flat: bool = False,
    force: bool = False,
) -> list[Path]:
    """Copy the packaged skill into ``destination`` and return the files written."""
    source = skill_dir(source_root)
    if not discover_skill_file(source_root).is_file():
        raise click.ClickException(
            f"The bundled skill is missing from this installation ({source}). "
            "Reinstall the anteumbra package."
        )

    target_dir = destination if flat else destination / SKILL_NAME
    skill_file = target_dir / SKILL_FILENAME
    if skill_file.exists() and not force:
        raise click.ClickException(
            f"{skill_file} already exists. Re-run with --force to replace it, "
            "or choose another directory."
        )

    written: list[Path] = []
    try:
        for path in sorted(source.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            target = target_dir / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
            written.append(target)
    except OSError as exc:
        raise click.ClickException(f"Cannot write the skill to {target_dir}: {exc}") from exc
    return written


def register_skill_commands(
    root: click.Group,
    *,
    skill_source_dir: Callable[[], Path],
) -> click.Group:
    """Register the ``skill`` command group and return it."""

    @root.group(
        "skill",
        invoke_without_command=True,
        epilog=(
            "\b\nExamples:\n"
            "  anteumbra skill export .\\skills\n"
            "  anteumbra skill export ~/.agents/skills\n"
            "  anteumbra skill show"
        ),
    )
    @click.pass_context
    def skill(ctx):
        """Export the bundled Anteumbra operator skill for an AI agent.

        The skill is the operator manual an agent follows: it names the MCP
        tools to call at each step, the questions to ask the user, the safety
        rules, and the verification checklist.
        """
        if ctx.invoked_subcommand is None:
            click.echo(ctx.get_help())

    @skill.command("export")
    @click.argument("directory", type=click.Path(file_okay=False, path_type=Path))
    @click.option(
        "--flat",
        is_flag=True,
        help="Write SKILL.md directly into DIRECTORY instead of DIRECTORY/anteumbra.",
    )
    @click.option("--force", is_flag=True, help="Replace an existing SKILL.md.")
    def skill_export(directory, flat, force):
        """Copy the bundled skill into DIRECTORY for an agent to install."""
        destination = Path(directory).expanduser().resolve()
        written = export_skill(
            skill_source_dir(), destination, flat=bool(flat), force=bool(force)
        )
        click.echo(f"Skill exported to {destination if flat else destination / SKILL_NAME}")
        for path in written:
            click.echo(f"  {path}")
        click.echo(SKILL_ROOT_HINT)

    @skill.command("show")
    def skill_show():
        """Print the bundled skill without copying it."""
        skill_file = discover_skill_file(skill_source_dir())
        if not skill_file.is_file():
            raise click.ClickException(
                f"The bundled skill is missing from this installation ({skill_file}). "
                "Reinstall the anteumbra package."
            )
        click.echo(f"# {skill_file}")
        click.echo(skill_file.read_text(encoding="utf-8"), nl=False)

    return skill
