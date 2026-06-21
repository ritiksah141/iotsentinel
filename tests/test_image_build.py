#!/usr/bin/env python3
"""
Image-build safety tests — catch broken Pi-image builds in SECONDS, locally, before
paying for a ~40-minute CI ARM build (and before shipping a dead image).

These tests do NOT build a real image. They:
  1. Dry-run `scripts/build_pi_image.sh` with a stubbed qemu + a stub pi-gen whose
     build.sh just emits a fake image, so the script generates its full custom-stage
     tree without chrooting. We then assert the generated tree is correct.
  2. Run static checks over the repo: every service/script the build references
     exists, every systemd unit's ExecStart target exists, and `git archive HEAD`
     (what the image actually bundles) includes the critical files — catching the
     recurring "new file not committed -> missing from image" class of bug.

Why this exists: real images shipped broken because setup_pi.sh aborted in the
chroot (su+sudo under qemu), a `__WIFI_COUNTRY__` placeholder went unsubstituted,
and untracked files were absent from `git archive`. Each of those now fails here.

Run: pytest tests/test_image_build.py -v
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BUILD = REPO / "scripts" / "build_pi_image.sh"
WORKFLOW = REPO / ".github" / "workflows" / "build-pi-image.yml"
SERVICES = REPO / "services"

# Service unit files the image build copies + enables.
REQUIRED_SERVICES = [
    "iotsentinel-provision.service",
    "iotsentinel-backend.service",
    "iotsentinel-dashboard.service",
    "iotsentinel-localai.service",
    "iotsentinel-connectivity.service",
    "iotsentinel-connectivity.timer",
    "iotsentinel-firstboot-report.service",
]

# Front-end SOURCE assets the dashboard needs. These must be tracked (the gitignored
# *.min.css and PWA icons are generated at boot from these, so the SOURCES must ship).
REQUIRED_ASSETS = [
    "dashboard/assets/logo.png",                      # also the PWA-icon source
    "dashboard/assets/custom.css",                    # main theme (minified at boot)
    "dashboard/assets/mobile-responsive.css",
    "dashboard/assets/skeleton.css",
    "dashboard/assets/bootstrap.min.css",
    "dashboard/assets/fontawesome.min.css",
    "dashboard/assets/webfonts/fa-solid-900.woff2",   # icon glyphs render
    "dashboard/assets/manifest.webmanifest",          # PWA install
    "dashboard/assets/sw.js",                         # service worker
    "dashboard/assets/offline.html",
    "dashboard/assets/topojson/world_110m.json",      # offline threat map
]

# Repo paths that MUST be in `git archive HEAD` or the flashed image won't have them.
CRITICAL_TRACKED = [
    "scripts/setup_pi.sh",
    "scripts/setup_hotspot.sh",
    "scripts/firstboot_diag.sh",
    "scripts/setup_local_ai.sh",
    "scripts/build_setup_guide_html.py",
    "utils/wifi_manager.py",
    "config/default_config.json",
    "requirements-pi.txt",
    "config/init_database.py",
    "dashboard/app.py",
] + [f"services/{s}" for s in REQUIRED_SERVICES] + REQUIRED_ASSETS


def _run_dry_build(tmp_path: Path, country: str | None = None) -> Path:
    """Run build_pi_image.sh with stubbed qemu + pi-gen; return the stub pi-gen dir."""
    binp = tmp_path / "bin"
    pigen = tmp_path / "pi-gen"
    (binp).mkdir()
    (pigen / "stage2").mkdir(parents=True)
    # stub qemu so the prereq check passes
    (binp / "qemu-aarch64-static").write_text("#!/bin/sh\nexit 0\n")
    (binp / "qemu-aarch64-static").chmod(0o755)
    # stub pi-gen build.sh: just emit a fake compressed image so the script finishes
    (pigen / "build.sh").write_text(
        "#!/bin/bash\nmkdir -p deploy\necho fake | xz > deploy/0001-IoTSentinel.img.xz\n"
    )
    (pigen / "build.sh").chmod(0o755)

    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    if country:
        env["IOTSENTINEL_WIFI_COUNTRY"] = country
    proc = subprocess.run(
        ["bash", str(BUILD), "--tag=test", f"--pigen-dir={pigen}"],
        cwd=str(REPO), env=env, capture_output=True, text=True, timeout=120,
    )
    # The stub build can't produce a real rootfs, so the post-build verify step just
    # warns and skips; the script should still complete (rc 0) through "Collecting".
    assert "Creating custom pi-gen stage" in proc.stdout, (
        f"stage generation did not run.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    # Clean the fake image the script copies into the repo's deploy/.
    shutil.rmtree(REPO / "deploy", ignore_errors=True)
    return pigen


@pytest.fixture(scope="module")
def staged(tmp_path_factory):
    return _run_dry_build(tmp_path_factory.mktemp("dry"))


def _stage(pigen: Path) -> Path:
    return pigen / "stage-iotsentinel"


# ---------------------------------------------------------------------------
# pi-gen config + stage scaffolding
# ---------------------------------------------------------------------------
def test_stage_list_runs_custom_stage_last(staged):
    cfg = (staged / "config").read_text()
    assert 'STAGE_LIST="stage0 stage1 stage2 stage-iotsentinel"' in cfg, \
        "custom stage must run AFTER stage0-2 (it sorts before stage0 without STAGE_LIST)"
    assert "WPA_COUNTRY=" in cfg


def test_prerun_and_export_image_present(staged):
    s = _stage(staged)
    assert (s / "prerun.sh").exists(), "missing prerun.sh -> empty rootfs, chroot fails"
    assert "copy_previous" in (s / "prerun.sh").read_text()
    assert (s / "EXPORT_IMAGE").exists(), "without EXPORT_IMAGE no .img is produced"


def test_deps_run_in_chroot_not_host(staged):
    s = _stage(staged)
    # MUST be *-run-chroot.sh so apt runs in the ARM chroot (python3.11 exists there),
    # not on the amd64 build host (which only has python3.12).
    deps = s / "00-install-deps" / "00-run-chroot.sh"
    assert deps.exists(), "deps must be a -run-chroot.sh (ran on host -> python3.11 not found)"
    assert not (s / "00-install-deps" / "00-run.sh").exists(), \
        "a host-side 00-run.sh would run deps on the wrong arch"
    body = deps.read_text()
    assert "python3.11" in body and "network-manager" in body
    assert "iw" in body and "rfkill" in body, "iw/rfkill needed to start the AP"


# ---------------------------------------------------------------------------
# THE big regressions: setup must run as root (not su), placeholders substituted
# ---------------------------------------------------------------------------
def test_setup_runs_as_root_not_su(staged):
    inst = _stage(staged) / "01-install-iotsentinel" / "01-run-chroot.sh"
    body = inst.read_text()
    # Ignore comments — only real commands matter (a comment warns against `su`).
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    assert "IOTSENTINEL_TARGET_USER=sentinel" in code, \
        "setup_pi.sh must run as root targeting sentinel"
    assert "su - sentinel" not in code, \
        "su+sudo fails under qemu -> setup aborts -> serviceless image (the shipped-broken bug)"
    assert "setup_pi.sh --non-interactive --skip-ollama" in code


def test_no_unsubstituted_placeholders(staged):
    s = _stage(staged)
    for script in s.rglob("*.sh"):
        assert "__WIFI_COUNTRY__" not in script.read_text(), \
            f"unsubstituted placeholder in {script.name} (sed step failed)"


def test_country_override_is_baked_in(tmp_path):
    pigen = _run_dry_build(tmp_path, country="US")
    s = _stage(pigen)
    assert 'WPA_COUNTRY="US"' in (pigen / "config").read_text()
    deps = (s / "00-install-deps" / "00-run-chroot.sh").read_text()
    assert "do_wifi_country US" in deps


def test_repo_tarball_staged_into_chroot(staged):
    s = _stage(staged)
    host = s / "01-install-iotsentinel" / "00-run.sh"
    assert host.exists(), "host step must copy the tarball into the rootfs"
    assert "ROOTFS_DIR" in host.read_text()
    assert (s / "01-install-iotsentinel" / "files" / "iotsentinel.tar.gz").exists()


# ---------------------------------------------------------------------------
# systemd services: all copied + enabled
# ---------------------------------------------------------------------------
def test_all_services_copied_and_enabled(staged):
    svc = (_stage(staged) / "02-systemd-services" / "00-run-chroot.sh").read_text()
    for unit in REQUIRED_SERVICES:
        assert unit in svc, f"{unit} not copied into the image"
    # The TIMER (not the connectivity .service) is what gets enabled.
    assert "enable iotsentinel-connectivity.timer" in svc
    for enabled in ("iotsentinel-provision.service", "iotsentinel-dashboard.service",
                    "iotsentinel-firstboot-report.service"):
        assert f"enable {enabled}" in svc, f"{enabled} not enabled"


def test_tarball_contains_critical_files(staged):
    tar = _stage(staged) / "01-install-iotsentinel" / "files" / "iotsentinel.tar.gz"
    out = subprocess.run(["tar", "tzf", str(tar)], capture_output=True, text=True).stdout
    for rel in ("utils/wifi_manager.py", "scripts/setup_hotspot.sh",
                "scripts/firstboot_diag.sh", "services/iotsentinel-firstboot-report.service"):
        assert f"iotsentinel/{rel}" in out, f"{rel} missing from the image tarball"


# ---------------------------------------------------------------------------
# Static repo integrity (no dry-run needed)
# ---------------------------------------------------------------------------
def test_referenced_service_files_exist():
    for unit in REQUIRED_SERVICES:
        assert (SERVICES / unit).exists(), f"build references missing services/{unit}"


def test_service_execstart_targets_exist():
    """Every ExecStart script our custom units call must exist in the repo."""
    checks = {
        "iotsentinel-firstboot-report.service": "scripts/firstboot_diag.sh",
        "iotsentinel-connectivity.service": "scripts/setup_hotspot.sh",
    }
    for unit, target in checks.items():
        text = (SERVICES / unit).read_text()
        assert "ExecStart=" in text, f"{unit} has no ExecStart"
        assert Path(target).name in text, f"{unit} should call {target}"
        assert (REPO / target).exists(), f"{unit} ExecStart target {target} is missing"


def test_systemd_units_have_required_sections():
    for unit in REQUIRED_SERVICES:
        text = (SERVICES / unit).read_text()
        assert "[Unit]" in text
        if unit.endswith(".timer"):
            assert "[Timer]" in text and "[Install]" in text
        else:
            assert "[Service]" in text and "ExecStart=" in text


def test_critical_files_are_committed():
    """`git archive HEAD` is what the image bundles — untracked files won't ship."""
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True
    ).stdout.splitlines()
    tracked = set(out)
    missing = [p for p in CRITICAL_TRACKED if p not in tracked]
    assert not missing, (
        "These files are NOT committed and would be ABSENT from the built image "
        f"(git archive HEAD): {missing}"
    )


def test_required_assets_committed_and_present():
    """Design/assets (CSS, logo, fonts, PWA, offline map) must be tracked + on disk —
    untracked assets are silently absent from the image (git archive)."""
    tracked = set(subprocess.run(
        ["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True
    ).stdout.splitlines())
    for a in REQUIRED_ASSETS:
        assert a in tracked, f"asset not committed -> missing from image: {a}"
        assert (REPO / a).exists(), f"asset file missing on disk: {a}"


def test_assets_ship_in_image_tarball(staged):
    tar = _stage(staged) / "01-install-iotsentinel" / "files" / "iotsentinel.tar.gz"
    out = subprocess.run(["tar", "tzf", str(tar)], capture_output=True, text=True).stdout
    for a in ("dashboard/assets/logo.png", "dashboard/assets/custom.css",
              "dashboard/assets/sw.js", "dashboard/assets/topojson/world_110m.json"):
        assert f"iotsentinel/{a}" in out, f"{a} missing from the image tarball"


def test_asset_generators_run_at_boot():
    """The minified CSS + PWA icons are gitignored because they're generated at
    dashboard startup — so the generators MUST be invoked, or styling/PWA break."""
    app = (REPO / "dashboard" / "app.py").read_text()
    assert "ensure_minified_css(" in app, "minified CSS not generated at boot"
    assert "ensure_pwa_icons(" in app, "PWA icons not generated at boot"
    # Pillow (icon resize) must be a real dependency.
    assert "Pillow" in (REPO / "requirements-pi.txt").read_text()


def test_workflow_builds_64bit_arm64_image():
    """64-bit is required for on-device AI (Ollama/gemma2:2b don't run on 32-bit
    armhf). pi-gen builds 64-bit only from its `arm64` branch."""
    wf = WORKFLOW.read_text()
    assert "--branch arm64" in wf, \
        "build must clone pi-gen's arm64 branch or the image is 32-bit (no on-device AI)"


def test_setup_pi_has_root_target_mode():
    """The fix that lets setup_pi.sh run in the build chroot must stay in place."""
    text = (REPO / "scripts" / "setup_pi.sh").read_text()
    assert "IOTSENTINEL_TARGET_USER" in text, "root/target-user mode removed -> chroot build breaks"
    assert "TARGET_HOME" in text
    assert "--skip-apt" in text, "setup_pi.sh must support --skip-apt for the image build"


def test_setup_pi_systemctl_calls_are_chroot_safe():
    """Any `systemctl` in setup_pi.sh must be guarded — daemon-reload/start fail in
    the build chroot (no running systemd) and would abort setup under `set -e`,
    leaving the image with no services. This caught the daemon-reload regression."""
    import re as _re
    for ln in (REPO / "scripts" / "setup_pi.sh").read_text().splitlines():
        s = ln.strip()
        if s.startswith("#") or "systemctl" not in s:
            continue
        if "is-enabled" in s or "is-active" in s:   # read-only checks are fine
            continue
        guarded = ("|| true" in s) or ("|| sudo" in s) or s.endswith("\\") or \
                  bool(_re.match(r"(els?e?if|if)\b", s))
        assert guarded, f"unguarded systemctl (aborts in chroot): {s}"


def test_setup_pi_ensures_service_symlinks():
    """Explicit autostart-symlink fallback so enablement survives a chroot where
    `systemctl enable` can't reach systemd."""
    text = (REPO / "scripts" / "setup_pi.sh").read_text()
    assert "multi-user.target.wants" in text and "ln -sf" in text


def test_deps_stage_fixes_apt_tmp():
    """The arm64 deps stage must make apt usable or it fails verification (NO_PUBKEY /
    'not signed') and installs nothing — the empty-image bug. Needs the /tmp fix AND
    allowing the unsigned base repos so apt-get update/install proceed in the chroot."""
    text = BUILD.read_text()
    assert "chmod 1777 /tmp" in text
    assert "APT::Sandbox::User" in text
    assert "AllowInsecureRepositories" in text
    assert "AllowUnauthenticated" in text
    # The build-only override must be removed before the image ships.
    assert "rm -f /etc/apt/apt.conf.d/00iotsentinel-build" in text


def test_build_has_postbuild_rootfs_assertion():
    """The build must fail loudly if the rootfs lacks any P4-critical feature, so a
    green build means 'ready for the hardware gate' without a wasted rebuild."""
    text = BUILD.read_text()
    assert "Verifying IoTSentinel was actually installed" in text
    # Each P4 gate area must be asserted against the built rootfs:
    for token in (
        "etc/sudoers.d/iotsentinel",          # hardening
        "venv/bin/python3",                    # python env
        "opt/zeek/bin/zeek",                   # capture
        "iotsentinel-backend.service",         # services enabled
        "iotsentinel-localai.service",         # on-device AI enabled
        "iotsentinel-connectivity.timer",      # recovery timer enabled
        "configure_ap.sh",                     # gateway scripts
        "data",                                # database check
        "is_configured",                       # wizard pre-seed
        "/usr/sbin/nft",                       # gateway sudoers grant
        "zeek_monitor.sh",                     # longevity cron
    ):
        assert token in text, f"post-build verification no longer checks: {token}"
    # Python deps must be verified (catches a partial pip install)
    for pkg in ("dash", "river", "pandas", "numpy", "sklearn"):
        assert pkg in text, f"post-build verification no longer checks python pkg: {pkg}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
