"""Memory-shell detection infrastructure (probe template, deployment, parsing)."""

from anteumbra.domain.memory_shell import ProbeError
from anteumbra.infrastructure.memory_shell.probe_deployer import (
    MemoryShellProbeDeployer,
    default_template_path,
    load_probe_template,
    render_probe,
)

__all__ = [
    "MemoryShellProbeDeployer",
    "ProbeError",
    "default_template_path",
    "load_probe_template",
    "render_probe",
]
