// SPDX-License-Identifier: GPL-2.0
/*
 * mg_hooks.c - intercepcion en la capa kernel.
 *
 * Se instrumentan con kretprobes los puntos de decision de seguridad que el
 * kernel ya invoca en cada alta/cambio de VMA:
 *
 *   security_mmap_file()      <- do_mmap()/vm_mmap_pgoff(): alta del VMA
 *   security_file_mprotect()  <- do_mprotect_pkey(): cambio de permisos
 *
 * Entrada: se leen los argumentos y se evalua la politica.
 * Retorno: si el veredicto es "denegar" se sobrescribe el valor de retorno
 *          con -EACCES, de modo que el kernel aborta la operacion igual que
 *          si un LSM hubiese rechazado el acceso.
 *
 * Sin tabla de syscalls modificada, sin tocar CR0.WP, sin parchear texto.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/percpu.h>
#include "mmapguard.h"

struct mg_ri {
	enum mg_verdict verdict;   /* veredicto a aplicar en el retorno */
};

static DEFINE_PER_CPU(u64, mg_seen_cpu);

u64 mg_seen_total(void)
{
	u64 sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += per_cpu(mg_seen_cpu, cpu);
	return sum;
}

static void mg_account(enum mg_verdict v, bool is_mprotect)
{
	switch (v) {
	case MG_DENY_WRITE: atomic64_inc(&mg_stats.denied_write); break;
	case MG_DENY_WX:    atomic64_inc(&mg_stats.denied_wx);    break;
	case MG_DENY_RATE:  atomic64_inc(&mg_stats.denied_rate);  break;
	default: break;
	}
	if (is_mprotect)
		atomic64_inc(&mg_stats.mprotect_denied);
}

static void mg_log(const char *tag, const char *op, enum mg_verdict v,
		   const struct mg_target *t, unsigned long prot, bool shared)
{
	pr_warn_ratelimited("%s %s reason=%s comm=%s pid=%d euid=%u file=%s ino=%lu prot=%c%c%c %s\n",
		tag, op, mg_verdict_str(v), current->comm, task_tgid_nr(current),
		from_kuid(&init_user_ns, current_euid()), t->path, t->ino,
		(prot & PROT_READ)  ? 'r' : '-',
		(prot & PROT_WRITE) ? 'w' : '-',
		(prot & PROT_EXEC)  ? 'x' : '-',
		shared ? "SHARED" : "PRIVATE");
}

/*
 * Decide que hacer con un veredicto. Devuelve 0 si hay que ejecutar el
 * handler de retorno (para sobrescribir el errno); distinto de 0 si no
 * hace falta (el kretprobe omite el handler y ahorra ciclos).
 */
static int mg_decide(const char *op, const struct mg_target *t,
		     enum mg_verdict v, unsigned long prot, bool shared,
		     struct mg_ri *d)
{
	if (!t)
		return 1;                       /* archivo no protegido */

	atomic64_inc(&mg_stats.protected_hits);

	if (v == MG_ALLOW) {
		if (mg_verbose)
			mg_log("ALLOW", op, v, t, prot, shared);
		return 1;
	}

	if (mg_mode == MG_MODE_ENFORCE) {
		mg_account(v, !strcmp(op, "mprotect"));
		mg_log("DENY", op, v, t, prot, shared);
		d->verdict = v;
		return 0;                       /* aplicar -EACCES al retornar */
	}

	atomic64_inc(&mg_stats.audit_only);
	mg_log("AUDIT", op, v, t, prot, shared);
	return 1;
}

/* ---- security_mmap_file(struct file *file, unsigned long prot,
 *                         unsigned long flags) ------------------------- */

static int mmap_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mg_ri *d = (struct mg_ri *)ri->data;
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	unsigned long prot  = regs_get_kernel_argument(regs, 1);
	unsigned long flags = regs_get_kernel_argument(regs, 2);
	const struct mg_target *t;

	this_cpu_inc(mg_seen_cpu);
	d->verdict = MG_ALLOW;

	if (!file)                              /* mapeo anonimo */
		return 1;

	t = mg_policy_lookup(file);
	return mg_decide("mmap", t, mg_policy_eval_mmap(t, prot), prot,
			 (flags & MAP_TYPE) != MAP_PRIVATE, d);
}

/* ---- security_file_mprotect(struct vm_area_struct *vma,
 *                             unsigned long reqprot, unsigned long prot) -- */

static int mprotect_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mg_ri *d = (struct mg_ri *)ri->data;
	struct vm_area_struct *vma =
		(struct vm_area_struct *)regs_get_kernel_argument(regs, 0);
	unsigned long prot = regs_get_kernel_argument(regs, 2);
	const struct mg_target *t;

	d->verdict = MG_ALLOW;
	atomic64_inc(&mg_stats.mprotect_seen);

	if (!vma || !vma->vm_file)
		return 1;

	t = mg_policy_lookup(vma->vm_file);
	return mg_decide("mprotect", t, mg_policy_eval_mprotect(t, prot), prot,
			 !!(vma->vm_flags & VM_SHARED), d);
}

/* Handler comun de retorno: convierte el veredicto en -EACCES. */
static int guard_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mg_ri *d = (struct mg_ri *)ri->data;

	if (d->verdict != MG_ALLOW && regs_return_value(regs) == 0)
		regs_set_return_value(regs, -EACCES);
	return 0;
}

static struct kretprobe krp_mmap = {
	.kp.symbol_name = "security_mmap_file",
	.entry_handler  = mmap_entry,
	.handler        = guard_ret,
	.data_size      = sizeof(struct mg_ri),
	.maxactive      = 0,                   /* valor por defecto del kernel */
};

static struct kretprobe krp_mprotect = {
	.kp.symbol_name = "security_file_mprotect",
	.entry_handler  = mprotect_entry,
	.handler        = guard_ret,
	.data_size      = sizeof(struct mg_ri),
	.maxactive      = 0,
};

int mg_hooks_init(void)
{
	int ret;

	ret = register_kretprobe(&krp_mmap);
	if (ret < 0) {
		pr_err("register_kretprobe(security_mmap_file) fallo: %d\n", ret);
		return ret;
	}

	ret = register_kretprobe(&krp_mprotect);
	if (ret < 0) {
		pr_err("register_kretprobe(security_file_mprotect) fallo: %d\n", ret);
		unregister_kretprobe(&krp_mmap);
		return ret;
	}

	pr_info("hooks activos: security_mmap_file, security_file_mprotect\n");
	return 0;
}

void mg_hooks_exit(void)
{
	unregister_kretprobe(&krp_mprotect);
	unregister_kretprobe(&krp_mmap);
	pr_info("hooks retirados (mmap perdidos: %d, mprotect perdidos: %d)\n",
		krp_mmap.nmissed, krp_mprotect.nmissed);
}
