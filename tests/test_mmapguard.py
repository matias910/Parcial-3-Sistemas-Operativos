#!/usr/bin/env python3
"""
Pruebas funcionales de mmapguard (requiere root y el modulo cargado).

Uso: sudo python3 tests/test_mmapguard.py /ruta/protegida /ruta/no_protegida

Se usa ctypes + libc directamente (no el modulo mmap de Python) para ejercer
exactamente las llamadas al sistema mmap/mprotect/madvise y ver el errno real.
"""
import ctypes, ctypes.util, errno, hashlib, os, sys, threading, time

PARAMS = "/sys/module/mmapguard/parameters"
PROC = "/proc/mmapguard"
PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
MAP_SHARED, MAP_PRIVATE = 1, 2
MADV_DONTNEED = 4
FAILED = 2**64 - 1

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

def setp(name, value):
    with open(f"{PARAMS}/{name}", "w") as f:
        f.write(str(value))

def stats():
    out = {}
    for line in open(PROC):
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out

def stat(name):
    return int(stats()[name])

def do_mmap(path, oflag, prot, flags, length=4096):
    """Devuelve (addr, 0) si exito o (None, errno) si fallo."""
    fd = os.open(path, oflag)
    try:
        addr = libc.mmap(None, length, prot, flags, fd, 0)
    finally:
        os.close(fd)
    if addr is None or addr == FAILED:
        return None, ctypes.get_errno()
    return addr, 0

def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))

def reset(mode=1, allow_uid=4242, rate_max=1000000000):
    # root NO esta autorizado (allow_uid=4242) para poder probar desde root
    setp("mode", mode); setp("allow_uid", allow_uid)
    setp("rate_max", rate_max); setp("rate_window_ms", 1000)

def main(prot_file, free_file):
    if os.geteuid() != 0:
        sys.exit("ejecutar como root")
    if not os.path.exists(PROC):
        sys.exit("mmapguard no esta cargado")

    print("\n== T01  Archivo NO protegido: sin falsos positivos")
    reset()
    a, e = do_mmap(free_file, os.O_RDWR, PROT_READ | PROT_WRITE, MAP_SHARED)
    check("mmap RW SHARED sobre archivo libre permitido", a is not None, f"errno={e}")
    if a: libc.munmap(a, 4096)

    print("\n== T02  Lectura legitima de archivo protegido")
    a, e = do_mmap(prot_file, os.O_RDONLY, PROT_READ, MAP_SHARED)
    check("mmap R SHARED permitido", a is not None, f"errno={e}")
    if a: libc.munmap(a, 4096)

    print("\n== T03  Escritura SHARED por uid no autorizado")
    a, e = do_mmap(prot_file, os.O_RDWR, PROT_READ | PROT_WRITE, MAP_SHARED)
    check("mmap RW SHARED bloqueado con EACCES", a is None and e == errno.EACCES, f"errno={e}")

    print("\n== T04  O_RDONLY + PROT_WRITE + MAP_PRIVATE (Pregunta 8)")
    reset(mode=0)
    a, e = do_mmap(prot_file, os.O_RDONLY, PROT_READ | PROT_WRITE, MAP_PRIVATE)
    check("modo audit: el kernel lo permite (COW)", a is not None, f"errno={e}")
    if a: libc.munmap(a, 4096)
    check("modo audit: se registra el intento", stat("audit_only") >= 1)
    reset(mode=1)
    a, e = do_mmap(prot_file, os.O_RDONLY, PROT_READ | PROT_WRITE, MAP_PRIVATE)
    check("modo enforce: bloqueado con EACCES", a is None and e == errno.EACCES, f"errno={e}")

    print("\n== T05  Escalada por mprotect(): mapear R y luego pedir RW")
    a, e = do_mmap(prot_file, os.O_RDONLY, PROT_READ, MAP_PRIVATE)
    ok = libc.mprotect(a, 4096, PROT_READ | PROT_WRITE) if a else 0
    e = ctypes.get_errno()
    check("mprotect(RW) bloqueado con EACCES", a is not None and ok == -1 and e == errno.EACCES, f"errno={e}")
    if a: libc.munmap(a, 4096)

    print("\n== T06  W^X con uid autorizado")
    reset(allow_uid=os.geteuid())
    a, e = do_mmap(prot_file, os.O_RDWR, PROT_READ | PROT_WRITE, MAP_SHARED)
    check("uid autorizado: escritura permitida", a is not None, f"errno={e}")
    if a: libc.munmap(a, 4096)
    a, e = do_mmap(prot_file, os.O_RDONLY, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE)
    check("W|X bloqueado incluso para uid autorizado", a is None and e == errno.EACCES, f"errno={e}")
    reset()

    print("\n== T07  Anomalia de tasa (rafaga de mmap)")
    setp("rate_max", 50); setp("rate_window_ms", 1000)
    denied = 0
    for _ in range(200):
        a, e = do_mmap(prot_file, os.O_RDONLY, PROT_READ, MAP_PRIVATE)
        if a: libc.munmap(a, 4096)
        else: denied += (e == errno.EACCES)
    check("rafaga de 200 mmap: se deniegan los que superan 50/s", denied >= 100, f"denegados={denied}")
    time.sleep(1.2)
    a, e = do_mmap(prot_file, os.O_RDONLY, PROT_READ, MAP_PRIVATE)
    check("la ventana se reinicia y vuelve a permitir", a is not None, f"errno={e}")
    if a: libc.munmap(a, 4096)
    reset()

    print("\n== T08  Integridad bajo carrera tipo Dirty COW (3 s, 4 hilos)")
    before = sha(prot_file)
    stop = time.time() + 3
    def hammer():
        fd_mem = os.open("/proc/self/mem", os.O_RDWR)
        while time.time() < stop:
            a, _ = do_mmap(prot_file, os.O_RDONLY, PROT_READ, MAP_PRIVATE)
            if not a:
                continue
            libc.mprotect(a, 4096, PROT_READ | PROT_WRITE)   # debe fallar
            libc.madvise(a, 4096, MADV_DONTNEED)
            try:
                os.pwrite(fd_mem, b"PWNED!!!", a)               # vector clasico FOLL_FORCE
            except OSError:
                pass
            libc.madvise(a, 4096, MADV_DONTNEED)
            libc.munmap(a, 4096)
        os.close(fd_mem)
    ts = [threading.Thread(target=hammer) for _ in range(4)]
    [t.start() for t in ts]; [t.join() for t in ts]
    check("el archivo en disco no cambio (SHA-256 identico)", sha(prot_file) == before)
    check("mprotect(RW) fue denegado durante la carrera", stat("mprotect_denied") > 0)

    print("\n== T09  Estadisticas expuestas en /proc/mmapguard")
    s = stats()
    check("contadores coherentes", int(s["denied_write"]) > 0 and int(s["denied_wx"]) > 0
          and int(s["mmap_seen"]) > 0, f"denied_write={s['denied_write']} denied_wx={s['denied_wx']}")

    passed = sum(RESULTS)
    print(f"\nResultado: {passed}/{len(RESULTS)} verificaciones OK")
    sys.exit(0 if passed == len(RESULTS) else 1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
