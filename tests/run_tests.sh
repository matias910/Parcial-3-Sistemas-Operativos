#!/usr/bin/env bash
# Carga mmapguard, ejecuta la bateria de pruebas y lo descarga.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo "Ejecutar con sudo"; exit 1; }

KO=src/mmapguard.ko
[[ -f $KO ]] || { echo "Falta $KO: ejecuta 'make' primero"; exit 1; }

DIR=/tmp/mg_test
mkdir -p "$DIR"
head -c 8192 /dev/urandom > "$DIR/secret.txt"
head -c 8192 /dev/urandom > "$DIR/public.txt"

rmmod mmapguard 2>/dev/null || true
dmesg -C 2>/dev/null || true
insmod "$KO" protected="$DIR/secret.txt" mode=1
trap 'rmmod mmapguard 2>/dev/null || true' EXIT

echo "--- /proc/mmapguard (inicial) ---"; cat /proc/mmapguard; echo
rc=0
python3 tests/test_mmapguard.py "$DIR/secret.txt" "$DIR/public.txt" || rc=$?

echo; echo "--- ultimas lineas de auditoria (dmesg) ---"
dmesg | grep mmapguard | tail -n 15 || true
echo; echo "--- /proc/mmapguard (final) ---"; cat /proc/mmapguard
exit $rc
