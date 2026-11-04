// SPDX-License-Identifier: GPL-2.0
/*
 * mg_main.c - ciclo de vida del modulo y parametros.
 *
 * Carga:   sudo insmod mmapguard.ko protected=/ruta/a,/ruta/b mode=1
 * Runtime: /sys/module/mmapguard/parameters/{mode,allow_uid,rate_max,...}
 * Estado:  cat /proc/mmapguard
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include "mmapguard.h"

int mg_mode = MG_MODE_ENFORCE;
int mg_allow_uid;                       /* 0 = root puede mapear escribible */
unsigned int mg_rate_max = 100;
unsigned int mg_rate_window_ms = 1000;
bool mg_verbose;

static char *protected_paths[MG_MAX_PROTECTED];
static int nprotected;

module_param_named(mode, mg_mode, int, 0644);
MODULE_PARM_DESC(mode, "0=audit (solo registra), 1=enforce (bloquea) [1]");
module_param_named(allow_uid, mg_allow_uid, int, 0644);
MODULE_PARM_DESC(allow_uid, "euid autorizado a mapear escribible; -1 = nadie [0]");
module_param_named(rate_max, mg_rate_max, uint, 0644);
MODULE_PARM_DESC(rate_max, "maximo de mmap() sobre archivos protegidos por ventana [100]");
module_param_named(rate_window_ms, mg_rate_window_ms, uint, 0644);
MODULE_PARM_DESC(rate_window_ms, "duracion de la ventana del limitador en ms [1000]");
module_param_named(verbose, mg_verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "registrar tambien los mapeos permitidos [0]");
module_param_array_named(protected, protected_paths, charp, &nprotected, 0444);
MODULE_PARM_DESC(protected, "lista de rutas de archivos protegidos (max 16)");

static int __init mmapguard_init(void)
{
	int ret;

	ret = mg_policy_init(protected_paths, nprotected);
	if (ret)
		return ret;

	ret = mg_proc_init();
	if (ret)
		goto err_policy;

	ret = mg_hooks_init();
	if (ret)
		goto err_proc;

	pr_info("cargado: mode=%s allow_uid=%d rate=%u/%ums\n",
		mg_mode == MG_MODE_ENFORCE ? "enforce" : "audit",
		mg_allow_uid, mg_rate_max, mg_rate_window_ms);
	return 0;

err_proc:
	mg_proc_exit();
err_policy:
	mg_policy_exit();
	return ret;
}

static void __exit mmapguard_exit(void)
{
	mg_hooks_exit();        /* primero los hooks: nadie mas lee la politica */
	mg_proc_exit();
	mg_policy_exit();
	pr_info("descargado\n");
}

module_init(mmapguard_init);
module_exit(mmapguard_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matias Zapata Rojas, Samuel Valencia Montoya, Valentina Barbosa");
MODULE_DESCRIPTION("mmapguard: control de acceso, W^X y deteccion de anomalias sobre mmap() en capa kernel");
MODULE_VERSION("1.0");
