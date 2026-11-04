/* bench_mmap.c - mide el costo de mmap()+primer acceso+munmap() y los page faults.
 * Compilar: gcc -O2 -o tests/bench_mmap tests/bench_mmap.c
 * Uso:      ./tests/bench_mmap <archivo> <iteraciones>
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e9 + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	if (argc != 3) { fprintf(stderr, "uso: %s <archivo> <iter>\n", argv[0]); return 1; }
	long iters = atol(argv[2]);
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) { perror("open"); return 1; }

	struct rusage r0, r1;
	volatile char sink = 0;
	long fails = 0;

	getrusage(RUSAGE_SELF, &r0);
	double t0 = now_ns();
	for (long i = 0; i < iters; i++) {
		char *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
		if (p == MAP_FAILED) { fails++; continue; }
		sink += p[0];                 /* fuerza el page fault */
		munmap(p, 4096);
	}
	double t1 = now_ns();
	getrusage(RUSAGE_SELF, &r1);

	printf("iter=%ld  ns/iter=%.1f  minor_faults=%ld  mmap_fallidos=%ld\n",
	       iters, (t1 - t0) / iters, r1.ru_minflt - r0.ru_minflt, fails);
	return 0;
}
