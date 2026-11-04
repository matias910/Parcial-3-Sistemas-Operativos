#!/usr/bin/env bash
# Prepara Fedora para compilar y probar mmapguard.
set -euo pipefail
echo "[1/3] Instalando dependencias..."
sudo dnf install -y gcc make kernel-devel-"$(uname -r)" kernel-headers \
     elfutils-libelf-devel python3 perf bpftrace

echo "[2/3] Secure Boot:"
if command -v mokutil >/dev/null; then
  mokutil --sb-state || true
else
  sudo dnf install -y mokutil && mokutil --sb-state || true
fi
echo "      Si dice 'SecureBoot enabled' el kernel RECHAZARA el .ko sin firmar."
echo "      Opciones: desactivar Secure Boot en la BIOS, o ejecutar scripts/sign_module.sh"

echo "[3/3] Kernel lockdown / kprobes:"
cat /sys/kernel/security/lockdown 2>/dev/null || echo "      (lockdown no disponible)"
zgrep -E "CONFIG_KPROBES=|CONFIG_KRETPROBES=" /proc/config.gz 2>/dev/null \
  || grep -E "CONFIG_KPROBES=|CONFIG_KRETPROBES=" /boot/config-"$(uname -r)" || true
echo "Listo."
