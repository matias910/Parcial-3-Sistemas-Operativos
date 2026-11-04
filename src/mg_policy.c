// SPDX-License-Identifier: GPL-2.0
/*
 * mg_policy.c - motor de politica de mmapguard.
 *
 * Los archivos protegidos se resuelven UNA vez al cargar el modulo
 * (kern_path puede dormir, el handler del kprobe no) y desde entonces
 * la decision en el hot path es una comparacion de enteros (dev, ino).
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include "mmapguard.h"

struct mg_stats mg_stats;

static struct mg_target targets[MG_MAX_PROTECTED];
static int ntargets;

/* ---- Limitador de tasa (deteccion de patrones anomalos) ------------- */

#define MG_RATE_SLOTS 64

struct mg_rate_slot {
	pid_t tgid;
	unsigned long window_start;
	unsigned int count;
};

static struct mg_rate_slot rate_tbl[MG_RATE_SLOTS];
static DEFINE_RAW_SPINLOCK(rate_lock);

/* true si el proceso (tgid) excedio rate_max mapeos en la ventana actual */
static bool mg_rate_exceeded(pid_t tgid)
{
	struct mg_rate_slot *s = &rate_tbl[(unsigned int)tgid % MG_RATE_SLOTS];
	unsigned long now = jiffies, flags;
	bool over;

	raw_spin_lock_irqsave(&rate_lock, flags);
	if (s->tgid != tgid ||
	    time_after(now, s->window_start + msecs_to_jiffies(mg_rate_window_ms))) {
		s->tgid = tgid;
		s->window_start = now;
		s->count = 0;
	}
	s->count++;
	over = s->count > mg_rate_max;
	raw_spin_unlock_irqrestore(&rate_lock, flags);

	return over;
}

/* ---- Registro de archivos protegidos -------------------------------- */

int mg_policy_init(char **paths, int n)
{
	int i;

	for (i = 0; i < n && ntargets < MG_MAX_PROTECTED; i++) {
		struct path p;
		struct inode *inode;
		int err;

		if (!paths[i] || !*paths[i])
			continue;

		err = kern_path(paths[i], LOOKUP_FOLLOW, &p);
		if (err) {
			pr_warn("no se pudo resolver '%s' (err=%d), se omite\n",
				paths[i], err);
			continue;
		}

		inode = d_inode(p.dentry);
		targets[ntargets].dev  = inode->i_sb->s_dev;
		targets[ntargets].ino  = inode->i_ino;
		targets[ntargets].path = kstrdup(paths[i], GFP_KERNEL);
		path_put(&p);

		if (!targets[ntargets].path)
			return -ENOMEM;

		pr_info("protegiendo %s (dev=%u:%u ino=%lu)\n", paths[i],
			MAJOR(targets[ntargets].dev), MINOR(targets[ntargets].dev),
			targets[ntargets].ino);
		ntargets++;
	}

	if (!ntargets) {
		pr_err("ningun archivo protegido valido (use protected=/ruta1,/ruta2)\n");
		return -EINVAL;
	}
	return 0;
}

void mg_policy_exit(void)
{
	int i;

	for (i = 0; i < ntargets; i++)
		kfree(targets[i].path);
	ntargets = 0;
}

int mg_policy_count(void)
{
	return ntargets;
}

const struct mg_target *mg_policy_get(int i)
{
	return (i >= 0 && i < ntargets) ? &targets[i] : NULL;
}

/* Hot path: seguro en contexto atomico (sin dormir, sin allocs). */
const struct mg_target *mg_policy_lookup(const struct file *file)
{
	const struct inode *inode = file_inode(file);
	int i;

	for (i = 0; i < ntargets; i++)
		if (targets[i].ino == inode->i_ino &&
		    targets[i].dev == inode->i_sb->s_dev)
			return &targets[i];
	return NULL;
}

/* ---- Reglas --------------------------------------------------------- */

static bool mg_uid_allowed(void)
{
	return (int)from_kuid(&init_user_ns, current_euid()) == mg_allow_uid;
}

/*
 * R1: PROT_WRITE|PROT_EXEC sobre archivo protegido -> denegar siempre (W^X).
 * R2: PROT_WRITE (SHARED o PRIVATE) y euid != allow_uid -> denegar.
 * R3: mas de rate_max mapeos/ventana por proceso -> denegar (anomalia).
 */
enum mg_verdict mg_policy_eval_mmap(const struct mg_target *t,
				    unsigned long prot)
{
	if (!t)
		return MG_ALLOW;

	if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
		return MG_DENY_WX;
	if ((prot & PROT_WRITE) && !mg_uid_allowed())
		return MG_DENY_WRITE;
	if (mg_rate_exceeded(task_tgid_nr(current)))
		return MG_DENY_RATE;
	return MG_ALLOW;
}

/* mprotect() sobre un VMA respaldado por archivo protegido (R1 y R2). */
enum mg_verdict mg_policy_eval_mprotect(const struct mg_target *t,
					unsigned long prot)
{
	if (!t)
		return MG_ALLOW;

	if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
		return MG_DENY_WX;
	if ((prot & PROT_WRITE) && !mg_uid_allowed())
		return MG_DENY_WRITE;
	return MG_ALLOW;
}

const char *mg_verdict_str(enum mg_verdict v)
{
	switch (v) {
	case MG_ALLOW:      return "allow";
	case MG_DENY_WRITE: return "unauthorized-write-map";
	case MG_DENY_WX:    return "wx-violation";
	case MG_DENY_RATE:  return "rate-anomaly";
	}
	return "unknown";
}
