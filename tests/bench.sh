#!/usr/bin/env bash
# Mide el overhead de mmapguard en mmap() + page faults.
# Escenarios: (A) sin modulo  (B) modulo, archivo NO protegido
#             (C) modulo, archivo protegido (lookup + limitador de tasa)
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo "Ejecutar con sudo"; exit 1; }

ITER=${ITER:-500000}
REPS=${REPS:-5}
DIR=/tmp/mg_bench
mkdir -p "$DIR" results
head -c 8192 /dev/urandom > "$DIR/secret.txt"
head -c 8192 /dev/urandom > "$DIR/public.txt"
gcc -O2 -o tests/bench_mmap tests/bench_mmap.c

run() {  # $1=etiqueta  $2=archivo
  for i in $(seq "$REPS"); do
    echo -n "$1;rep=$i;"; ./tests/bench_mmap "$2" "$ITER"
  done
}

OUT=results/bench_$(date +%Y%m%d_%H%M%S).txt
{
  echo "# kernel: $(uname -r)  iter=$ITER reps=$REPS"
  rmmod mmapguard 2>/dev/null || true
  run "A_sin_modulo" "$DIR/public.txt"

  insmod src/mmapguard.ko protected="$DIR/secret.txt" mode=1 rate_max=2000000000
  run "B_modulo_no_protegido" "$DIR/public.txt"
  run "C_modulo_protegido"    "$DIR/secret.txt"
  cat /proc/mmapguard
  rmmod mmapguard

  if command -v perf >/dev/null; then
    echo; echo "# perf stat (escenario C)"
    insmod src/mmapguard.ko protected="$DIR/secret.txt" mode=1 rate_max=2000000000
    perf stat -e page-faults,context-switches,cpu-migrations \
      ./tests/bench_mmap "$DIR/secret.txt" "$ITER" 2>&1
    rmmod mmapguard
  fi
} | tee "$OUT"
echo "Resultados guardados en $OUT"
