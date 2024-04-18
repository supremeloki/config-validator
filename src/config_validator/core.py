from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    pass


class ConfigLoadError(ConfigError): ...
class SchemaDefinitionError(ConfigError): ...
class SecretLeakError(ConfigError): ...


SENSITIVE_HINTS = ("password", "secret", "token", "api_key", "private_key", "credential")


@dataclass(frozen=True)
class Violation:
    path: str
    rule: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: [{self.rule}] {self.message}"


@dataclass(frozen=True)
class ValidationReport:
    valid: bool
    violations: tuple[Violation, ...] = field(default_factory=tuple)

    def summary(self) -> str:
        status = "PASS" if self.valid else "FAIL"
        return f"{status}: {len(self.violations)} violation(s)"

    def raise_if_invalid(self) -> "ValidationReport":
        if not self.valid:
            lines = "\n".join(str(v) for v in self.violations[:10])
            raise ConfigError(f"config invalid:\n{lines}")
        return self


TYPE_CHECKS: dict[str, type] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
}


def _type_matches(value: Any, declared: str) -> bool:
    python_type = TYPE_CHECKS.get(declared)
    if python_type is None:
        raise SchemaDefinitionError(f"unknown type keyword: {declared!r}")
    if declared in {"integer", "number"} and isinstance(value, bool):
        return False
    return isinstance(value, python_type)


class FieldRule:
    def __init__(
        self,
        expected_type: str | None = None,
        required: bool = False,
        min_value: int | float | None = None,
        max_value: int | float | None = None,
        choices: tuple[Any, ...] = (),
        pattern: str | None = None,
    ) -> None:
        import re as _re

        self.expected_type = expected_type
        self.required = required
        self.min_value = min_value
        self.max_value = max_value
        self.choices = choices
        self._pattern = _re.compile(pattern) if pattern else None

    def validate(self, value: Any, path: str) -> list[Violation]:
        violations: list[Violation] = []
        if value is None:
            if self.required:
                violations.append(Violation(path, "required", "value missing"))
            return violations
        if self.expected_type and not _type_matches(value, self.expected_type):
            violations.append(
                Violation(path, "type", f"expected {self.expected_type}, got {type(value).__name__}")
            )
            return violations
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if self.min_value is not None and value < self.min_value:
                violations.append(Violation(path, "min", f"{value} < {self.min_value}"))
            if self.max_value is not None and value > self.max_value:
                violations.append(Violation(path, "max", f"{value} > {self.max_value}"))
        if isinstance(value, str):
            if self._pattern and not self._pattern.fullmatch(value):
                violations.append(Violation(path, "pattern", f"{value!r} fails pattern"))
        if self.choices and value not in self.choices:
            violations.append(
                Violation(path, "choices", f"{value!r} not in {self.choices}")
            )
        return violations


class ConfigSchema:
    def __init__(self, rules: dict[str, FieldRule], strict_extra: bool = False) -> None:
        self._rules = rules
        self._strict_extra = strict_extra

    def validate(self, config: dict[str, Any]) -> ValidationReport:
        violations: list[Violation] = []
        for key, rule in self._rules.items():
            violations.extend(rule.validate(config.get(key), f"${key}"))
        if self._strict_extra:
            extras = set(config) - set(self._rules)
            for extra in sorted(extras):
                violations.append(Violation(f"${extra}", "extra", "undeclared key"))
        return ValidationReport(valid=not violations, violations=tuple(violations))


def load_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigLoadError(f"config file not found: {path}")
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigLoadError(f"invalid JSON in {path.name}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigLoadError(f"config root must be an object: {path.name}")
    return document


def scan_for_secrets(config: dict[str, Any], prefix: str = "$") -> list[Violation]:
    findings: list[Violation] = []
    for key, value in config.items():
        lowered = key.lower()
        path = f"{prefix}{key}"
        if any(hint in lowered for hint in SENSITIVE_HINTS) and isinstance(value, str) and len(value) >= 6:
            findings.append(Violation(path, "secret", f"suspicious literal secret in {key!r}"))
        elif isinstance(value, dict):
            findings.extend(scan_for_secrets(value, prefix=f"{path}."))
    return findings


def merge_configs(*layers: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for layer in layers:
        for key, value in layer.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = merge_configs(merged[key], value)
            else:
                merged[key] = value
    return merged
