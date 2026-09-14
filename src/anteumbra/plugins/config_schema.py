# -*- coding: utf-8 -*-
"""Declarative configuration schemas for the built-in plugins.

Why this module exists
----------------------
A plugin reads its own settings in ``activate()`` through
``config.get("...", <default>)``.  That default is the only place the runtime
knows what "unset" means, but it was invisible to the settings page: the panel
could show *that* a plugin exists, never *what* it would accept, so SMTP hosts,
webhook URLs, poll intervals, thresholds and cooldowns could only be changed by
hand-editing ``config.toml``.

``ConfigField`` puts that knowledge next to the behaviour instead of duplicating
it in a template: each entry states the key, its type, the default the plugin
itself falls back to, the bounds a form may enforce, and whether the value is a
credential that must live in ``.env``.

Where the schemas live
----------------------
* A plugin class that can be built without runtime services exposes
  ``config_schema()`` itself (``stdout_logger``, the WAF adapters,
  ``memory_shell_probe``, ``quarantine_handler``).  ``PluginManager`` prefers
  that, so a plugin shipping in a wheel describes its own settings.
* Plugins whose constructor needs injected services (``notifier_handler``,
  ``threat_graph_handler``, ``siem_handler``) cannot be instantiated just to ask
  a question, so their schema is registered here in ``BRIDGE_PLUGIN_SCHEMAS``
  and resolved from the module path in ``[plugins] builtin``.

Resolution order used by the settings page (see
``PluginManager.plugin_config_schema``):
``live class -> module registry -> shipped config.toml/``live section keys.
The last step is the fallback, so a third-party plugin with no schema at all
still renders typed controls for the keys an operator can actually see.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

#: Field kinds the settings page knows how to render.  ``secret`` is not a
#: widget: it renders a write-only input whose value is stored in ``.env`` and
#: never read back into a response.
FIELD_TYPES: tuple[str, ...] = (
    "toggle",
    "number",
    "text",
    "select",
    "list",
    "secret",
)

_MISSING = object()


@dataclass(frozen=True)
class ConfigField:
    """One plugin setting, described declaratively.

    ``default`` is the value the plugin's own ``activate()`` falls back to when
    the key is absent, so the settings page can show an *effective* value even
    for a key no operator has ever written.
    """

    name: str
    type: str = "text"
    default: Any = None
    label: str = ""
    description: str = ""
    min: float | None = None
    max: float | None = None
    choices: tuple[str, ...] = ()
    pattern: str = ""
    pattern_hint: str = ""
    item_pattern: str = ""
    item_pattern_hint: str = ""
    required: bool = False
    allow_empty: bool = True
    env_key: str = ""
    restart_required: bool = False

    def __post_init__(self) -> None:
        if self.type not in FIELD_TYPES:
            raise ValueError(f"{self.name}: unknown field type {self.type!r}")
        if self.type == "select" and not self.choices:
            raise ValueError(f"{self.name}: a select field needs choices")
        # A secret field without ``env_key`` is still valid: the settings page
        # falls back to the ``${VAR}`` placeholder found in config.toml, and only
        # refuses to write when neither name can be resolved.
        if self.pattern:
            re.compile(self.pattern)  # fail loudly at import, not at save time
        if self.item_pattern:
            re.compile(self.item_pattern)

    # -- rendering / comparison helpers ------------------------------------

    def to_mapping(self) -> dict[str, Any]:
        """Plain-dict form, so ``config_schema()`` can cross an import boundary."""
        return {
            "name": self.name,
            "type": self.type,
            "default": self.default,
            "label": self.label,
            "description": self.description,
            "min": self.min,
            "max": self.max,
            "choices": list(self.choices),
            "pattern": self.pattern,
            "pattern_hint": self.pattern_hint,
            "item_pattern": self.item_pattern,
            "item_pattern_hint": self.item_pattern_hint,
            "required": self.required,
            "allow_empty": self.allow_empty,
            "env_key": self.env_key,
            "restart_required": self.restart_required,
        }

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ConfigField":
        """Build a field from either a mapping or an existing ``ConfigField``."""
        if isinstance(raw, ConfigField):
            return raw
        name = str(raw.get("name") or raw.get("key") or "").strip()
        if not name:
            raise ValueError("a config field needs a name")
        choices = raw.get("choices") or ()
        if isinstance(choices, str):
            choices = (choices,)
        return cls(
            name=name,
            type=str(raw.get("type") or "text"),
            default=raw.get("default"),
            label=str(raw.get("label") or ""),
            description=str(raw.get("description") or ""),
            min=raw.get("min"),
            max=raw.get("max"),
            choices=tuple(str(choice) for choice in choices),
            pattern=str(raw.get("pattern") or ""),
            pattern_hint=str(raw.get("pattern_hint") or ""),
            item_pattern=str(raw.get("item_pattern") or ""),
            item_pattern_hint=str(raw.get("item_pattern_hint") or ""),
            required=bool(raw.get("required", False)),
            allow_empty=bool(raw.get("allow_empty", True)),
            env_key=str(raw.get("env_key") or ""),
            restart_required=bool(raw.get("restart_required", False)),
        )


def normalize_fields(raw: Any) -> list[ConfigField]:
    """Coerce anything a plugin calls a schema into a list of ``ConfigField``."""
    if not raw:
        return []
    if isinstance(raw, Mapping):  # {key: field} also accepted
        raw = [dict(value, name=key) if isinstance(value, Mapping) else value
               for key, value in raw.items()]
    if not isinstance(raw, Sequence):
        return []
    fields: list[ConfigField] = []
    seen: set[str] = set()
    for entry in raw:
        if isinstance(entry, str):
            entry = {"name": entry}
        try:
            field = ConfigField.from_mapping(entry)
        except (ValueError, TypeError, AttributeError):
            continue
        if field.name in seen:
            continue
        seen.add(field.name)
        fields.append(field)
    return fields


def field_values_equal(left: Any, right: Any) -> bool:
    """Whether two config values mean the same thing.

    TOML gives back ``5`` for an interval and ``5.0`` for a threshold, and a
    number typed into a form arrives as a string; comparing them literally
    would report every numeric field as "changed", which is exactly the signal
    the readability filters rely on.
    """
    if isinstance(left, bool) or isinstance(right, bool):
        return _as_bool(left) == _as_bool(right)
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, (int, float)) or isinstance(right, (int, float)):
        left_number, right_number = _as_number(left), _as_number(right)
        if left_number is not None and right_number is not None:
            if math.isnan(left_number) or math.isnan(right_number):
                return False
            return math.isclose(left_number, right_number, rel_tol=1e-9, abs_tol=1e-9)
    if isinstance(left, (list, tuple)) or isinstance(right, (list, tuple)):
        left_items = list(left) if isinstance(left, (list, tuple)) else [left]
        right_items = list(right) if isinstance(right, (list, tuple)) else [right]
        return len(left_items) == len(right_items) and all(
            field_values_equal(a, b) for a, b in zip(left_items, right_items)
        )
    return str(left).strip() == str(right).strip()


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return None


def _as_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# -- schema registry for plugins that cannot be built without services --------

#: Bridge plugins are constructed by the runtime with injected services
#: (``application/runtime_plugins.py``), so they cannot be instantiated to ask
#: ``config_schema()``.  Their schema is registered here under the exact name a
#: ``[plugins] builtin`` entry would use.  A plugin that can be built without
#: services still declares its own ``config_schema()`` and wins over anything
#: listed here; these entries only cover the classes that cannot.
#: An empty tuple is a real answer, not a missing one: it says the plugin has no
#: settings of its own, which is why the settings page renders "no settings"
#: instead of inventing controls for it.
BRIDGE_PLUGIN_SCHEMAS: dict[str, tuple[ConfigField, ...]] = {
    "notifier_handler": (),
    "threat_graph_handler": (),
    "siem_handler": (),
}

#: WAF adapter modules, keyed by the short plugin name their config section uses.
_ADAPTER_MODULES: dict[str, str] = {
    "modsecurity": "anteumbra.plugins.waf_adapters.modsecurity_adapter",
    "cloudflare": "anteumbra.plugins.waf_adapters.cloudflare_adapter",
    "aws_waf": "anteumbra.plugins.waf_adapters.aws_adapter",
    "syslog_waf": "anteumbra.plugins.waf_adapters.syslog_receiver",
}

#: Every built-in schema this build knows, whether or not the plugin can be
#: instantiated here: an adapter whose optional dependency is missing still has a
#: config section an operator is entitled to edit.
_BUILTIN_SCHEMAS: dict[str, tuple[ConfigField, ...]] = dict(BRIDGE_PLUGIN_SCHEMAS)


def register_builtin_schema(module_path: str, fields: Any) -> None:
    """Register one built-in plugin's declared schema (idempotent)."""
    name = str(module_path or "").strip()
    if not name:
        return
    _BUILTIN_SCHEMAS[name] = tuple(normalize_fields(fields))


def load_adapter_schemas() -> None:
    """Adopt each WAF adapter's own ``config_schema()``.

    Called once at the bottom of this module.  The adapters keep their schema next
    to the ``activate()`` that reads it; this only saves the settings page from
    importing an adapter (and its optional dependencies) to learn what its form
    looks like.
    """
    import importlib

    for short_name, module_path in _ADAPTER_MODULES.items():
        try:
            module = importlib.import_module(module_path)
        except Exception:  # noqa: BLE001 - an unimportable adapter keeps its section
            continue
        plugin_class = next(
            (
                getattr(module, attribute)
                for attribute in dir(module)
                if isinstance(getattr(module, attribute), type)
                and getattr(getattr(module, attribute), "__module__", "") == module_path
                and hasattr(getattr(module, attribute), "config_schema")
            ),
            None,
        )
        method = getattr(plugin_class, "config_schema", None)
        if not callable(method):
            continue
        try:
            register_builtin_schema(short_name, method())
        except Exception:  # noqa: BLE001 - a broken schema must not break imports
            continue


def schema_for_module(module_name: str) -> tuple[ConfigField, ...]:
    """Registered schema for one plugin module/name, or an empty tuple.

    Both spellings resolve: a ``[plugins] builtin`` entry may be the module path
    (``waf_adapters.modsecurity``) while the plugin registers itself under the
    short name (``modsecurity``), and its config section is the short name.
    """
    name = str(module_name or "").strip()
    return _BUILTIN_SCHEMAS.get(name) or _BUILTIN_SCHEMAS.get(name.rsplit(".", 1)[-1], ())


def has_builtin_schema(module_name: str) -> bool:
    """Whether this build ships a declared schema for the plugin (set or empty)."""
    name = str(module_name or "").strip()
    return name in _BUILTIN_SCHEMAS or name.rsplit(".", 1)[-1] in _BUILTIN_SCHEMAS


load_adapter_schemas()


__all__ = [
    "BRIDGE_PLUGIN_SCHEMAS",
    "ConfigField",
    "FIELD_TYPES",
    "field_values_equal",
    "has_builtin_schema",
    "load_adapter_schemas",
    "normalize_fields",
    "register_builtin_schema",
    "schema_for_module",
]
