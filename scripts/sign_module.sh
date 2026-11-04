#!/usr/bin/env bash
# Firma mmapguard.ko con una llave MOK (necesario si Secure Boot esta activo).
set -euo pipefail
cd "$(dirname "$0")/.."
sudo dnf install -y akmods mokutil openssl
if [[ ! -f /etc/pki/akmods/certs/public_key.der ]]; then
  sudo kmodgenca -a
  echo ">> Se te pedira una clave. Reinicia, elige 'Enroll MOK' y escribela."
  sudo mokutil --import /etc/pki/akmods/certs/public_key.der
  echo ">> Reinicia, completa el enrolamiento y vuelve a ejecutar este script."
  exit 0
fi
/usr/src/kernels/"$(uname -r)"/scripts/sign-file sha256 \
  /etc/pki/akmods/private/private_key.priv \
  /etc/pki/akmods/certs/public_key.der src/mmapguard.ko
echo "Modulo firmado: src/mmapguard.ko"
