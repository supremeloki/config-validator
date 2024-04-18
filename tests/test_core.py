import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from config_validator import (
    ConfigLoadError,
    ConfigSchema,
    ConfigError,
    FieldRule,
    load_config_file,
    merge_configs,
    scan_for_secrets,
)


def sample_schema() -> ConfigSchema:
    return ConfigSchema({
        "host": FieldRule(expected_type="string", required=True),
        "port": FieldRule(expected_type="integer", min_value=1, max_value=65535),
        "mode": FieldRule(choices=("internet", "intranet", "standalone")),
        "retries": FieldRule(expected_type="integer", min_value=0),
    })


def test_valid_config_passes():
    report = sample_schema().validate({"host": "db.local", "port": 1433, "mode": "intranet"})
    assert report.valid
    assert report.summary().startswith("PASS")


def test_missing_required_reports_violation():
    report = sample_schema().validate({"port": 80})
    assert not report.valid
    assert any(v.rule == "required" and v.path == "$host" for v in report.violations)


def test_bool_not_integer():
    report = sample_schema().validate({"host": "x", "port": True})
    assert not report.valid
    assert any(v.rule == "type" for v in report.violations)


def test_range_bounds_enforced():
    schema = sample_schema()
    assert not schema.validate({"host": "h", "port": 0}).valid
    assert not schema.validate({"host": "h", "port": 99999}).valid
    assert schema.validate({"host": "h", "port": 5432}).valid


def test_choices_reject_unknown_mode():
    report = sample_schema().validate({"host": "h", "mode": "cloud"})
    assert any(v.rule == "choices" for v in report.violations)


def test_strict_extra_flags_undeclared():
    schema = ConfigSchema({"a": FieldRule(expected_type="integer")}, strict_extra=True)
    report = schema.validate({"a": 1, "ghost": True})
    assert any(v.rule == "extra" for v in report.violations)


def test_load_file_roundtrip(tmp_path: Path):
    target = tmp_path / "app.json"
    target.write_text(json.dumps({"host": "h"}), encoding="utf-8")
    assert load_config_file(target) == {"host": "h"}


def test_load_missing_file_raises(tmp_path: Path):
    with pytest.raises(ConfigLoadError):
        load_config_file(tmp_path / "nope.json")


def test_load_invalid_json_raises(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigLoadError):
        load_config_file(bad)


def test_secret_scan_finds_literals():
    findings = scan_for_secrets({"db_password": "hunter2secret"})
    assert findings
    assert findings[0].rule == "secret"


def test_secret_scan_ignores_short_and_nested_clean():
    assert scan_for_secrets({"password": ""}) == []
    nested = {"db": {"api_key": "superlongkeyvalue"}}
    assert len(scan_for_secrets(nested)) == 1


def test_merge_deep_dicts_later_wins():
    base = {"db": {"host": "a", "port": 1}, "flag": False}
    override = {"db": {"host": "b"}}
    merged = merge_configs(base, override)
    assert merged == {"db": {"host": "b", "port": 1}, "flag": False}


def test_raise_if_invalid_raises_with_lines():
    with pytest.raises(ConfigError):
        sample_schema().validate({"port": 0}).raise_if_invalid()


def test_unknown_type_keyword_raises_at_rule_build():
    rule = FieldRule(expected_type="float32")
    with pytest.raises(Exception):
        rule.validate(1.5, "$x")
