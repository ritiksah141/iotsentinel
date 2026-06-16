# Contributing to IoTSentinel

Thanks for your interest in improving IoTSentinel. This guide covers local setup,
the test/lint workflow, and conventions for pull requests.

## Project layout

| Area | Path |
|---|---|
| Backend orchestrator (Zeek parsing, ML, agent, alerts) | `orchestrator.py`, `agents/`, `ml/`, `capture/`, `alerts/` |
| Web dashboard (Dash + Flask) | `dashboard/` (layouts in `dashboard/layouts/`, callbacks in `dashboard/callbacks/`) |
| First-run setup wizard | `dashboard/layouts/setup_wizard.py`, `dashboard/callbacks/callbacks_setup.py` |
| Configuration | `config/default_config.json`, `config/config_manager.py` |
| Raspberry Pi image build | `scripts/build_pi_image.sh`, `scripts/setup_pi.sh`, `services/*.service` |
| Tests | `tests/` |

## Local setup

```bash
git clone https://github.com/ritiksah141/iotsentinel.git
cd iotsentinel
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python config/init_database.py </dev/null
```

Run the dashboard:

```bash
IOTSENTINEL_HOST=127.0.0.1 python dashboard/app.py
# open http://localhost:8050
```

## Before you open a PR

```bash
pytest tests/ -q            # full test suite must pass
ruff check .               # correctness lint must pass
```

Optional but encouraged:

```bash
pre-commit install         # runs the hooks in .pre-commit-config.yaml on commit
ruff format .              # auto-format files you touched
bandit -r . -c pyproject.toml --severity-level high --confidence-level high -q
```

## Conventions

- **Branch** off `main`; keep PRs focused and small.
- **Tests** accompany behaviour changes. Match the existing class-based style in
  `tests/` (module docstring explaining *why* the test exists, `sys.path.insert`
  at the top where needed).
- **No secrets** in commits. `.env`, API keys, and credentials never get checked in
  (`detect-secrets` runs as a pre-commit hook).
- **Privacy first.** Network data, alerts, and device info stay on-device; only the
  optional integrations the user explicitly configures (Groq, AbuseIPDB, ntfy, etc.)
  make outbound calls.
- **Docs.** Update `README.md`, `tests/README.md`, and `.github/CHANGELOG.md`
  (under `[Unreleased]`) when your change is user-visible.

## Reporting security issues

Please report vulnerabilities privately - see [SECURITY.md](.github/SECURITY.md).
Do not open a public issue for security problems.
