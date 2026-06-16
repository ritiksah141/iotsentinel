# scripts/

Operational, maintenance, and developer helper scripts for IoTSentinel.

Every file in this directory is documented below. Scripts are grouped into two categories:

- **Wired** - called automatically by the installer, CI/CD, systemd/cron, or production code.
- **Manual** - run by a human operator or developer when needed; never called automatically.

---

## Wired scripts

| Script | Called by | Purpose |
|---|---|---|
| `build_pi_image.sh` | `.github/workflows/build-pi-image.yml` | Builds the Raspberry Pi `.img` artefact for each release. |
| `setup_pi.sh` | `README.md` install flow; `docs/SETUP_GUIDE.md` | Full Pi provisioning: system deps, Python venv, systemd service, firewall, Tailscale. Called once during first-time setup. |
| `setup_db_automation.sh` | `install.sh`; `docs/SETUP_GUIDE.md` | Installs the cron job that runs `db_maintenance.py` nightly. |
| `db_maintenance.py` | Cron (installed by `setup_db_automation.sh`) | Nightly database housekeeping: vacuums SQLite, purges old records, re-indexes. |
| `firewall_manager.py` | `utils/firewall_enforcer.py` (`from scripts import firewall_manager`) | OpenWrt SSH bridge: translates IoTSentinel block/allow commands into router firewall rules. Used by `FirewallEnforcer` at runtime. |
| `run_tests.sh` | `README.md` (developer workflow) | Convenience wrapper around `pytest` with standard flags and coverage reporting. |

---

## Manual scripts

Run these directly when needed. None are called by the app or CI automatically.

### `reset_admin.py` - Admin password recovery
```
python scripts/reset_admin.py
```
Resets the admin account password interactively. Use this if the admin password is lost and
the forced-change flow cannot be completed (e.g. forgotten before first login). Requires direct
access to the machine running IoTSentinel.

### `update_threat_feeds.py` - Refresh threat intelligence feeds
```
python scripts/update_threat_feeds.py
```
Downloads the latest IP blocklists and domain threat-intel feeds into the database. The app
loads threat data at startup, so run this then restart IoTSentinel to pick up fresh data.
Recommended: run monthly, or after a known incident.

### `verify_rbac_security.py` - RBAC/permissions audit
```
python scripts/verify_rbac_security.py
```
Checks that every protected route and callback enforces the expected role (viewer/admin/super-admin).
Run before a release or after adding new dashboard features.

### `validate_pi.sh` - Post-deploy Pi health check
```
./scripts/validate_pi.sh
```
Confirms that all systemd services are running, Zeek is capturing, the DB is reachable, and idle
CPU is below 20%. Run on the Pi after first boot or after upgrading IoTSentinel.

### `generate_test_data.py` - Seed a development database
```
python scripts/generate_test_data.py
```
Populates the database with realistic sample devices, traffic flows, alerts, and anomalies.
Useful for local development and UI testing when no real network traffic is available.

### `init_db_features.py` - One-off feature-table initialiser
```
python scripts/init_db_features.py
```
Creates optional feature tables (e.g. advanced reporting, custom alert rules) that are not part
of the default schema migration. Run once if you want to enable these features on an existing
installation. Safe to run multiple times (`CREATE TABLE IF NOT EXISTS`).
