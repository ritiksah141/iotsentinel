#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ensure_ssh.sh — guarantee sshd is enabled AND listening on every boot.
#
# The image build enables SSH in the pi-gen chroot (build_pi_image.sh), but a
# chroot `systemctl enable ssh` has silently no-op'd in some builds, and a later
# OS update / hardening pass / userconf regeneration can leave the unit masked or
# stopped — so a headless, monitor-less appliance ends up with port 22 refused and
# no remote way to fix anything WITHOUT cutting a whole new image.
#
# This runs as a oneshot on EVERY boot (idempotent and cheap) so SSH self-heals:
# unmask -> enable -> start, covering both the classic ssh.service daemon and the
# socket-activated ssh.socket that Raspberry Pi OS Bookworm can use. Always
# best-effort; never fatal (a non-zero exit must not block the boot).
# ─────────────────────────────────────────────────────────────────────────────

# Belt-and-suspenders: anything that ever masked SSH is undone here first.
systemctl unmask ssh.service ssh.socket >/dev/null 2>&1 || true

# Prefer socket activation when the distro ships ssh.socket (Bookworm default);
# fall back to the persistent ssh.service daemon. Enabling --now both enables the
# unit for future boots and starts it right now.
if systemctl list-unit-files ssh.socket >/dev/null 2>&1 \
   && systemctl cat ssh.socket >/dev/null 2>&1; then
  systemctl enable --now ssh.socket >/dev/null 2>&1 || true
fi
systemctl enable --now ssh.service >/dev/null 2>&1 \
  || systemctl enable --now ssh.socket >/dev/null 2>&1 \
  || true

# Final guarantee: if neither is active yet, force a start of whichever exists.
if ! systemctl is-active --quiet ssh.service \
   && ! systemctl is-active --quiet ssh.socket; then
  systemctl start ssh.service >/dev/null 2>&1 \
    || systemctl start ssh.socket >/dev/null 2>&1 \
    || true
fi

# Log the resolved state to the journal so `journalctl -u iotsentinel-ssh` shows
# exactly which path won — invaluable when debugging a locked-out device.
svc="$(systemctl is-active ssh.service 2>/dev/null || echo unknown)"
sock="$(systemctl is-active ssh.socket 2>/dev/null || echo unknown)"
echo "[ensure_ssh] ssh.service=${svc} ssh.socket=${sock}"

# Never fail the unit; SSH being best-effort must not brick the boot.
exit 0
