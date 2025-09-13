/* Miscellaneous system calls.				Author: Kees J. Bot
 *								31 Mar 2000
 * The entry points into this file are:
 *   do_reboot: kill all processes, then reboot system
 *   do_getsysinfo: request copy of PM data structure  (Jorrit N. Herder)
 *   do_getprocnr: lookup endpoint by process ID
 *   do_getepinfo: get the pid/uid/gid of a process given its endpoint
 *   do_getsetpriority: get/set process priority
 *   do_svrctl: process manager control
 *   do_getrusage: obtain process resource usage information
 */

#include "pm.h"
#include <minix/callnr.h>
#include <signal.h>
#include <sys/svrctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <minix/com.h>
#include <minix/config.h>
#include <minix/sysinfo.h>
#include <minix/type.h>
#include <minix/ds.h>
#include <machine/archtypes.h>
#include <lib.h>
#include <assert.h>
#include "mproc.h"
#include "kernel/proc.h"

/* START OF COMPATIBILITY BLOCK */
struct utsname uts_val = {
  OS_NAME,		/* system name */
  "noname",		/* node/network name */
  OS_RELEASE,		/* O.S. release (e.g. 3.3.0) */
  OS_VERSION,		/* O.S. version (e.g. Minix 3.3.0 (GENERIC)) */
#if defined(__i386__)
  "i386",		/* machine (cpu) type */
#elif defined(__arm__)
  "evbarm",		/* machine (cpu) type */
#else
#error			/* oops, no 'uname -mk' */
#endif
};

static char *uts_tbl[] = {
#if defined(__i386__)
  "i386",		/* architecture */
#elif defined(__arm__)
  "evbarm",		/* architecture */
#endif
  NULL,			/* No kernel architecture */
  uts_val.machine,
  NULL,			/* No hostname */
  uts_val.nodename,
  uts_val.release,
  uts_val.version,
  uts_val.sysname,
  NULL,			/* No bus */			/* No bus */
};
/* END OF COMPATIBILITY BLOCK */

#if ENABLE_SYSCALL_STATS
unsigned long calls_stats[NR_PM_CALLS];
#endif

/* START OF COMPATIBILITY BLOCK */
/*===========================================================================*
 *				do_sysuname				     *
 *===========================================================================*/
int
do_sysuname(void)
{
    char *string;
    size_t copy_len;
    int r;

    if (m_in.m_lc_pm_sysuname.req != 0) {
        return EINVAL;
    }

    if (m_in.m_lc_pm_sysuname.field >= __arraycount(uts_tbl)) {
        return EINVAL;
    }

    string = uts_tbl[m_in.m_lc_pm_sysuname.field];
    if (string == NULL) {
        return EINVAL;
    }

    copy_len = strlen(string) + 1;
    if (copy_len > m_in.m_lc_pm_sysuname.len) {
        copy_len = m_in.m_lc_pm_sysuname.len;
    }

    r = sys_datacopy(SELF, (vir_bytes)string, mp->mp_endpoint,
        m_in.m_lc_pm_sysuname.value, (phys_bytes)copy_len);
    if (r < 0) {
        return r;
    }

    return (int)copy_len;
}
/* END OF COMPATIBILITY BLOCK */


/*===========================================================================*
 *				do_getsysinfo			       	     *
 *===========================================================================*/
int do_getsysinfo(void)
{
    vir_bytes src_addr;
    size_t len;
    const int what = m_in.m_lsys_getsysinfo.what;
    const size_t size = m_in.m_lsys_getsysinfo.size;
    const vir_bytes dst_addr = m_in.m_lsys_getsysinfo.where;

    if (mp->mp_effuid != 0) {
        printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n",
               mp->mp_endpoint, mp->mp_name);
        sys_diagctl_stacktrace(mp->mp_endpoint);
        return EPERM;
    }

    switch (what) {
    case SI_PROC_TAB:
        src_addr = (vir_bytes)mproc;
        len = sizeof(struct mproc) * NR_PROCS;
        break;
#if ENABLE_SYSCALL_STATS
    case SI_CALL_STATS:
        src_addr = (vir_bytes)calls_stats;
        len = sizeof(calls_stats);
        break;
#endif
    default:
        return EINVAL;
    }

    if (len != size) {
        return EINVAL;
    }

    return sys_datacopy(SELF, src_addr, who_e, dst_addr, len);
}

/*===========================================================================*
 *				do_getprocnr			             *
 *===========================================================================*/
int do_getprocnr(void)
{
    struct mproc *rmp;

    /* This check should be replaced by per-call ACL checks. */
    if (who_e != RS_PROC_NR) {
        printf("PM: unauthorized call of do_getprocnr by %d\n", who_e);
        return EPERM;
    }

    rmp = find_proc(m_in.m_lsys_pm_getprocnr.pid);
    if (rmp == NULL) {
        return ESRCH;
    }

    mp->mp_reply.m_pm_lsys_getprocnr.endpt = rmp->mp_endpoint;
    return OK;
}

/*===========================================================================*
 *				do_getepinfo			             *
 *===========================================================================*/
int do_getepinfo(void)
{
    const endpoint_t ep = m_in.m_lsys_pm_getepinfo.endpt;
    int slot;

    if (pm_isokendpt(ep, &slot) != OK) {
        return ESRCH;
    }

    const struct mproc * const rmp = &mproc[slot];

    /* Populate the reply message with UID/GID information. */
    mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_realuid;
    mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp->mp_effuid;
    mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_realgid;
    mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp->mp_effgid;
    mp->mp_reply.m_pm_lsys_getepinfo.ngroups = rmp->mp_ngroups;

    /* Determine the number of groups to copy, limited by the caller's buffer. */
    int groups_to_copy = rmp->mp_ngroups;
    const int caller_max_groups = m_in.m_lsys_pm_getepinfo.ngroups;
    if (groups_to_copy > caller_max_groups) {
        groups_to_copy = caller_max_groups;
    }

    if (groups_to_copy > 0) {
        const size_t copy_size = (size_t)groups_to_copy * sizeof(gid_t);
        const int r = sys_datacopy(SELF, (vir_bytes)rmp->mp_sgroups, who_e,
            m_in.m_lsys_pm_getepinfo.groups, copy_size);

        if (r != OK) {
            return r;
        }
    }

    return rmp->mp_pid;
}

/*===========================================================================*
 *				do_reboot				     *
 *===========================================================================*/
int
do_reboot(void)
{
    if (mp->mp_effuid != SUPER_USER) {
        return EPERM;
    }

    abort_flag = m_in.m_lc_pm_reboot.how;

    if (abort_flag & RB_POWERDOWN) {
        endpoint_t readclock_ep;
        if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
            message pwr_off_msg = {0};
            _taskcall(readclock_ep, RTCDEV_PWR_OFF, &pwr_off_msg);
        }
    }

    check_sig(-1, SIGKILL, FALSE);
    sys_stop(INIT_PROC_NR);

    message vfs_msg = {0};
    vfs_msg.m_type = VFS_PM_REBOOT;
    tell_vfs(&mproc[VFS_PROC_NR], &vfs_msg);

    return SUSPEND;
}

/*===========================================================================*
 *				do_getsetpriority			     *
 *===========================================================================*/
int
do_getsetpriority(void)
{
	const int arg_which = m_in.m_lc_pm_priority.which;
	const int arg_who = m_in.m_lc_pm_priority.who;
	const int arg_pri = m_in.m_lc_pm_priority.prio;
	struct mproc *rmp;

	if (arg_which != PRIO_PROCESS) {
		return EINVAL;
	}

	rmp = (arg_who == 0) ? mp : find_proc(arg_who);
	if (rmp == NULL) {
		return ESRCH;
	}

	if (mp->mp_effuid != SUPER_USER &&
	    mp->mp_effuid != rmp->mp_effuid && mp->mp_effuid != rmp->mp_realuid) {
		return EPERM;
	}

	if (call_nr == PM_GETPRIORITY) {
		return rmp->mp_nice - PRIO_MIN;
	}

	/* SETPRIORITY continues here. */
	if (arg_pri < rmp->mp_nice && mp->mp_effuid != SUPER_USER) {
		return EACCES;
	}

	const int status = sched_nice(rmp, arg_pri);
	if (status != OK) {
		return status;
	}

	rmp->mp_nice = arg_pri;
	return OK;
}

/*===========================================================================*
 *				do_svrctl				     *
 *===========================================================================*/
#define MAX_LOCAL_PARAMS 2
#define PARAM_NAME_LEN 30
#define PARAM_VALUE_LEN 30
#define SEARCH_KEY_LEN 64

static struct {
	char name[PARAM_NAME_LEN];
	char value[PARAM_VALUE_LEN];
} local_param_overrides[MAX_LOCAL_PARAMS];

static int local_params = 0;

static int handle_set_param(int who_e, vir_bytes ptr)
{
	struct sysgetenv sg;
	int s;

	if ((s = sys_datacopy(who_e, ptr, SELF, (vir_bytes)&sg, sizeof(sg))) != OK) {
		return s;
	}

	if (local_params >= MAX_LOCAL_PARAMS) {
		return ENOSPC;
	}

	if (sg.keylen == 0 || sg.keylen >= PARAM_NAME_LEN ||
		sg.vallen == 0 || sg.vallen >= PARAM_VALUE_LEN) {
		return EINVAL;
	}

	char *name_buf = local_param_overrides[local_params].name;
	if ((s = sys_datacopy(who_e, (vir_bytes)sg.key, SELF, (vir_bytes)name_buf, sg.keylen)) != OK) {
		return s;
	}
	name_buf[sg.keylen] = '\0';

	char *value_buf = local_param_overrides[local_params].value;
	if ((s = sys_datacopy(who_e, (vir_bytes)sg.val, SELF, (vir_bytes)value_buf, sg.vallen)) != OK) {
		return s;
	}
	value_buf[sg.vallen] = '\0';

	local_params++;

	return OK;
}

static int handle_get_param(int who_e, vir_bytes ptr)
{
	struct sysgetenv sg;
	const void *data_start;
	size_t data_len;
	int s;

	if ((s = sys_datacopy(who_e, ptr, SELF, (vir_bytes)&sg, sizeof(sg))) != OK) {
		return s;
	}

	if (sg.keylen == 0) {
		data_start = monitor_params;
		data_len = sizeof(monitor_params);
	} else {
		char search_key[SEARCH_KEY_LEN];
		const char *val_start = NULL;
		int i;

		if (sg.keylen >= sizeof(search_key)) {
			return EINVAL;
		}

		if ((s = sys_datacopy(who_e, (vir_bytes)sg.key, SELF, (vir_bytes)search_key, sg.keylen)) != OK) {
			return s;
		}
		search_key[sg.keylen] = '\0';

		for (i = 0; i < local_params; i++) {
			if (strcmp(search_key, local_param_overrides[i].name) == 0) {
				val_start = local_param_overrides[i].value;
				break;
			}
		}

		if (val_start == NULL) {
			val_start = find_param(search_key);
		}

		if (val_start == NULL) {
			return ESRCH;
		}

		data_start = val_start;
		data_len = strlen(val_start) + 1;
	}

	if (data_len > sg.vallen) {
		return E2BIG;
	}

	return sys_datacopy(SELF, (vir_bytes)data_start, who_e, (vir_bytes)sg.val, data_len);
}

int do_svrctl(void)
{
	unsigned long req = m_in.m_lc_svrctl.request;
	vir_bytes ptr = m_in.m_lc_svrctl.arg;

	if (IOCGROUP(req) != 'P' && IOCGROUP(req) != 'M') {
		return EINVAL;
	}

	switch (req) {
	case OPMSETPARAM:
	case PMSETPARAM:
		return handle_set_param(who_e, ptr);

	case OPMGETPARAM:
	case PMGETPARAM:
		return handle_get_param(who_e, ptr);

	default:
		return EINVAL;
	}
}

/*===========================================================================*
 *				do_getrusage				     *
 *===========================================================================*/
int
do_getrusage(void)
{
	struct rusage r_usage;
	clock_t user_time, sys_time;
	int r, who;

	who = m_in.m_lc_pm_rusage.who;
	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN)
		return EINVAL;

	/*
	 * TODO: first relay the call to VFS.  As is, VFS does not have any
	 * fields it can fill with meaningful values, but this may change in
	 * the future.  In that case, PM would first have to use the tell_vfs()
	 * system to get those values from VFS, and do the rest here upon
	 * getting the response.
	 */

	memset(&r_usage, 0, sizeof(r_usage));

	if (who == RUSAGE_SELF) {
		if ((r = sys_times(who_e, &user_time, &sys_time, NULL,
		    NULL)) != OK)
			return r;
	} else { /* RUSAGE_CHILDREN */
		user_time = mp->mp_child_utime;
		sys_time = mp->mp_child_stime;
	}

	set_rusage_times(&r_usage, user_time, sys_time);

	if ((r = vm_getrusage(who_e, &r_usage,
	    (who == RUSAGE_CHILDREN))) != OK)
		return r;

	return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e,
	    m_in.m_lc_pm_rusage.addr, (vir_bytes)sizeof(r_usage));
}
