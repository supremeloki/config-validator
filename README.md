# config-validator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Validate JSON configuration files against declarative rules, deep-merge layered configs, and scan for accidentally-committed secrets — before they reach production.

## 🚀 Overview

Config bugs are the cheapest bugs to catch and the most expensive to ship. `config-validator` describes expected config shape as `FieldRule` objects (types, ranges, choices, patterns), collects *all* violations per file, flags undeclared keys in strict mode, warns when keys like `password`/`api_key` hold literal values, and merges environment layers (base ← env ← local) with predictable precedence.

## ✨ Features

- **Declarative rules:** `FieldRule(expected_type="integer", min_value=1, max_value=65535, choices=(...))`
- **Collect-all reporting:** every violation returned as frozen dataclass with path (`$db.port`) — not fail-fast
- **Strict mode:** undeclared keys become violations instead of silent acceptance
- **Bool-guard:** `true` is never accepted where an integer is declared
- **Secret scanner:** flags literal strings in keys named password/token/api_key/… recursively
- **Layered merge:** deep dict merge; later layers override earlier ones key-by-key
- **Safe file loading:** missing files, invalid JSON, non-object roots → typed `ConfigLoadError`
- **Zero dependencies**

## 🚧 Structure

```
config-validator/
├── src/config_validator/
│   ├── __init__.py
│   └── core.py
├── tests/
│   └── test_core.py
├── README.md
└── pyproject.toml
```

## 📦 Installation

```bash
git clone https://github.com/supremeloki/config-validator.git
cd config-validator
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## 📋 Requirements

- Python 3.11+
- No runtime dependencies

## 🏃 Quick Start

```python
from pathlib import Path
from config_validator import ConfigSchema, FieldRule, load_config_file, scan_for_secrets

schema = ConfigSchema({
    "host": FieldRule(expected_type="string", required=True),
    "port": FieldRule(expected_type="integer", min_value=1, max_value=65535),
    "mode": FieldRule(choices=("internet", "intranet", "standalone")),
})

report = schema.validate(load_config_file(Path("app.json")))
print(report.summary())

for violation in report.violations:
    print(violation)

report.raise_if_invalid()
```

### Secret scan

```python
findings = scan_for_secrets(config)
for finding in findings:
    print(f"{finding.path}: {finding.message}")
```

## 🔧 Error Handling

```text
ConfigError
├── ConfigLoadError         # missing file / bad JSON / non-object root
├── SchemaDefinitionError   # unknown type keyword in a rule
└── SecretLeakError         # reserved for hard-fail secret policy
```

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📝 Code Quality

- Full type hints (`X | None` style), frozen reports and violations
- Zero comments — names carry the meaning
- `ruff` clean

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Kooroush Masoumi**

---

⭐ Star this repo if you find it useful!
