/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mmapguard - defensa en capa kernel para archivos proyectados con mmap().
 * Interfaz interna compartida entre los modulos del driver.
 */
#ifndef MMAPGUARD_H
#define MMAPGUARD_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/fs.h>

#define MG_MAX_PROTECTED 16
#define MG_MODE_AUDIT    0   /* solo registra, nunca bloquea       */
#define MG_MODE_ENFORCE  1   /* registra y bloquea con -EACCES     */

/* Resultado de evaluar una operacion contra la politica. */
enum mg_verdict {
	MG_ALLOW = 0,
	MG_DENY_WRITE,   /* mapeo/mprotect escribible por uid no autorizado */
	MG_DENY_WX,      /* PROT_WRITE | PROT_EXEC (viola W^X)              */
	MG_DENY_RATE,    /* demasiados mmap() por ventana de tiempo         */
};

/* Archivo protegido: se identifica por (dispositivo, inodo), no por ruta. */
struct mg_target {
	dev_t dev;
	unsigned long ino;
	char *path;      /* solo informativo (logs / procfs) */
};

struct mg_stats {
	atomic64_t protected_hits;
	atomic64_t denied_write;
	atomic64_t denied_wx;
	atomic64_t denied_rate;
	atomic64_t audit_only;
	atomic64_t mprotect_seen;
	atomic64_t mprotect_denied;
};

/* Parametros del modulo (definidos en mg_main.c). */
extern int mg_mode;
extern int mg_allow_uid;
extern unsigned int mg_rate_max;
extern unsigned int mg_rate_window_ms;
extern bool mg_verbose;

extern struct mg_stats mg_stats;

/* mg_policy.c */
int  mg_policy_init(char **paths, int n);
void mg_policy_exit(void);
int  mg_policy_count(void);
const struct mg_target *mg_policy_get(int i);
const struct mg_target *mg_policy_lookup(const struct file *file);
enum mg_verdict mg_policy_eval_mmap(const struct mg_target *t,
				    unsigned long prot);
enum mg_verdict mg_policy_eval_mprotect(const struct mg_target *t,
					unsigned long prot);
const char *mg_verdict_str(enum mg_verdict v);

/* mg_hooks.c */
int  mg_hooks_init(void);
void mg_hooks_exit(void);
u64  mg_seen_total(void);

/* mg_proc.c */
int  mg_proc_init(void);
void mg_proc_exit(void);

#endif /* MMAPGUARD_H */
