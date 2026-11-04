// SPDX-License-Identifier: GPL-2.0
/* mg_proc.c - estadisticas y estado en /proc/mmapguard */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "mmapguard.h"

static int mg_proc_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "mode:             %s\n",
		   mg_mode == MG_MODE_ENFORCE ? "enforce" : "audit");
	seq_printf(m, "allow_uid:        %d\n", mg_allow_uid);
	seq_printf(m, "rate_limit:       %u mmap / %u ms\n",
		   mg_rate_max, mg_rate_window_ms);
	seq_printf(m, "mmap_seen:        %llu\n", mg_seen_total());
	seq_printf(m, "protected_hits:   %lld\n",
		   (long long)atomic64_read(&mg_stats.protected_hits));
	seq_printf(m, "denied_write:     %lld\n",
		   (long long)atomic64_read(&mg_stats.denied_write));
	seq_printf(m, "denied_wx:        %lld\n",
		   (long long)atomic64_read(&mg_stats.denied_wx));
	seq_printf(m, "denied_rate:      %lld\n",
		   (long long)atomic64_read(&mg_stats.denied_rate));
	seq_printf(m, "audit_only:       %lld\n",
		   (long long)atomic64_read(&mg_stats.audit_only));
	seq_printf(m, "mprotect_seen:    %lld\n",
		   (long long)atomic64_read(&mg_stats.mprotect_seen));
	seq_printf(m, "mprotect_denied:  %lld\n",
		   (long long)atomic64_read(&mg_stats.mprotect_denied));

	for (i = 0; i < mg_policy_count(); i++) {
		const struct mg_target *t = mg_policy_get(i);

		seq_printf(m, "protected[%d]:     %s (dev=%u:%u ino=%lu)\n", i,
			   t->path, MAJOR(t->dev), MINOR(t->dev), t->ino);
	}
	return 0;
}

int mg_proc_init(void)
{
	if (!proc_create_single("mmapguard", 0444, NULL, mg_proc_show))
		return -ENOMEM;
	return 0;
}

void mg_proc_exit(void)
{
	remove_proc_entry("mmapguard", NULL);
}
