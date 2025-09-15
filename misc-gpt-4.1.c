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
int do_sysuname(void)
{
    int r;
    size_t n = 0;
    char *string;

    if (m_in.m_lc_pm_sysuname.field >= __arraycount(uts_tbl))
        return EINVAL;

    string = uts_tbl[m_in.m_lc_pm_sysuname.field];
    if (!string)
        return EINVAL;

    if (m_in.m_lc_pm_sysuname.req == 0) {
        n = strlen(string) + 1;
        if (n > m_in.m_lc_pm_sysuname.len)
            n = m_in.m_lc_pm_sysuname.len;

        r = sys_datacopy(SELF, (vir_bytes)string, mp->mp_endpoint,
                         m_in.m_lc_pm_sysuname.value, (phys_bytes)n);
        if (r != OK)
            return r;
    } else {
        return EINVAL;
    }

    return (int)n;
}
/* END OF COMPATIBILITY BLOCK */


/*===========================================================================*
 *				do_getsysinfo			       	     *
 *===========================================================================*/
int do_getsysinfo(void)
{
    vir_bytes src_addr, dst_addr;
    size_t len;

    if (mp->mp_effuid != 0) {
        printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n",
               mp->mp_endpoint, mp->mp_name);
        sys_diagctl_stacktrace(mp->mp_endpoint);
        return EPERM;
    }

    len = 0;
    switch (m_in.m_lsys_getsysinfo.what) {
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

    if (len == 0 || len != m_in.m_lsys_getsysinfo.size)
        return EINVAL;

    dst_addr = m_in.m_lsys_getsysinfo.where;
    return sys_datacopy(SELF, src_addr, who_e, dst_addr, len);
}

/*===========================================================================*
 *				do_getprocnr			             *
 *===========================================================================*/
int do_getprocnr(void)
{
    struct mproc *rmp;

    if (who_e != RS_PROC_NR) {
        printf("PM: unauthorized call of do_getprocnr by %d\n", who_e);
        return EPERM;
    }

    rmp = find_proc(m_in.m_lsys_pm_getprocnr.pid);
    if (!rmp)
        return ESRCH;

    mp->mp_reply.m_pm_lsys_getprocnr.endpt = rmp->mp_endpoint;
    return OK;
}

/*===========================================================================*
 *				do_getepinfo			             *
 *===========================================================================*/
int do_getepinfo(void)
{
    struct mproc *rmp;
    endpoint_t ep;
    int result = OK, slot, ngroups, groups_to_copy;

    ep = m_in.m_lsys_pm_getepinfo.endpt;
    if (pm_isokendpt(ep, &slot) != OK)
        return ESRCH;

    rmp = &mproc[slot];

    mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_realuid;
    mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp->mp_effuid;
    mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_realgid;
    mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp->mp_effgid;

    ngroups = rmp->mp_ngroups;
    mp->mp_reply.m_pm_lsys_getepinfo.ngroups = ngroups;

    groups_to_copy = ngroups;
    if (groups_to_copy > m_in.m_lsys_pm_getepinfo.ngroups)
        groups_to_copy = m_in.m_lsys_pm_getepinfo.ngroups;

    if (groups_to_copy > 0) {
        result = sys_datacopy(SELF, (vir_bytes)rmp->mp_sgroups, who_e,
                              m_in.m_lsys_pm_getepinfo.groups, groups_to_copy * sizeof(gid_t));
        if (result != OK)
            return result;
    }

    return rmp->mp_pid;
}

/*===========================================================================*
 *				do_reboot				     *
 *===========================================================================*/
int do_reboot(void)
{
    message m;
    endpoint_t readclock_ep;

    if (mp == NULL) {
        return EFAULT;
    }

    if (mp->mp_effuid != SUPER_USER) {
        return EPERM;
    }

    abort_flag = m_in.m_lc_pm_reboot.how;

    if (abort_flag & RB_POWERDOWN) {
        if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
            message m_rc;
            (void)_taskcall(readclock_ep, RTCDEV_PWR_OFF, &m_rc);
        }
    }

    check_sig(-1, SIGKILL, FALSE);
    sys_stop(INIT_PROC_NR);

    memset(&m, 0, sizeof(m));
    m.m_type = VFS_PM_REBOOT;

    tell_vfs(&mproc[VFS_PROC_NR], &m);

    return SUSPEND;
}


/*===========================================================================*
 *				do_getsetpriority			     *
 *===========================================================================*/
int do_getsetpriority(void)
{
	int r;
	int arg_which = m_in.m_lc_pm_priority.which;
	int arg_who = m_in.m_lc_pm_priority.who;
	int arg_pri = m_in.m_lc_pm_priority.prio;
	struct mproc *rmp = NULL;

	/* Only support PRIO_PROCESS for now. */
	if (arg_which != PRIO_PROCESS)
		return EINVAL;

	if (arg_who == 0) {
		rmp = mp;
	} else {
		rmp = find_proc(arg_who);
		if (rmp == NULL)
			return ESRCH;
	}

	if (mp->mp_effuid != SUPER_USER &&
	   mp->mp_effuid != rmp->mp_effuid &&
	   mp->mp_effuid != rmp->mp_realuid)
		return EPERM;

	if (call_nr == PM_GETPRIORITY)
		return rmp->mp_nice - PRIO_MIN;

	if (rmp->mp_nice > arg_pri && mp->mp_effuid != SUPER_USER)
		return EACCES;

	r = sched_nice(rmp, arg_pri);
	if (r != OK)
		return r;

	rmp->mp_nice = arg_pri;
	return OK;
}

/*===========================================================================*
 *				do_svrctl				     *
 *===========================================================================*/
int do_svrctl(void)
{
    unsigned long req;
    int s;
    vir_bytes ptr;
    #define MAX_LOCAL_PARAMS 2
    enum { KEY_MAXLEN = 29, VALUE_MAXLEN = 29 };  // for null termination
    static struct {
        char name[KEY_MAXLEN + 1];
        char value[VALUE_MAXLEN + 1];
    } local_param_overrides[MAX_LOCAL_PARAMS];
    static int local_params = 0;

    req = m_in.m_lc_svrctl.request;
    ptr = m_in.m_lc_svrctl.arg;

    if (IOCGROUP(req) != 'P' && IOCGROUP(req) != 'M')
        return EINVAL;

    switch(req) {
    case OPMSETPARAM:
    case OPMGETPARAM:
    case PMSETPARAM:
    case PMGETPARAM: {
        struct sysgetenv sysgetenv;
        char search_key[64];
        char *val_start = NULL;
        size_t val_len, copy_len;

        if (sys_datacopy(who_e, ptr, SELF, (vir_bytes) &sysgetenv, sizeof(sysgetenv)) != OK)
            return EFAULT;

        if (req == PMSETPARAM || req == OPMSETPARAM) {
            if (local_params >= MAX_LOCAL_PARAMS) return ENOSPC;
            if (sysgetenv.keylen <= 0 || sysgetenv.keylen > KEY_MAXLEN)
                return EINVAL;
            if (sysgetenv.vallen <= 0 || sysgetenv.vallen > VALUE_MAXLEN)
                return EINVAL;

            s = sys_datacopy(who_e, (vir_bytes) sysgetenv.key, SELF,
                             (vir_bytes) local_param_overrides[local_params].name,
                             sysgetenv.keylen);
            if (s != OK) return s;
            s = sys_datacopy(who_e, (vir_bytes) sysgetenv.val, SELF,
                             (vir_bytes) local_param_overrides[local_params].value,
                             sysgetenv.vallen);
            if (s != OK) return s;

            local_param_overrides[local_params].name[sysgetenv.keylen] = '\0';
            local_param_overrides[local_params].value[sysgetenv.vallen] = '\0';
            local_params++;
            return OK;
        }

        if (sysgetenv.keylen == 0) {
            val_start = monitor_params;
            val_len = sizeof(monitor_params);
        } else {
            int p;
            if (sysgetenv.keylen > sizeof(search_key))
                return EINVAL;
            s = sys_datacopy(who_e, (vir_bytes) sysgetenv.key, SELF,
                             (vir_bytes) search_key, sysgetenv.keylen);
            if (s != OK) return s;
            if (sysgetenv.keylen >= sizeof(search_key))
                search_key[sizeof(search_key) - 1] = '\0';
            else
                search_key[sysgetenv.keylen - 1] = '\0';

            for (p = 0; p < local_params; p++) {
                if (strcmp(search_key, local_param_overrides[p].name) == 0) {
                    val_start = local_param_overrides[p].value;
                    break;
                }
            }
            if (p >= local_params) {
                val_start = find_param(search_key);
                if (!val_start)
                    return ESRCH;
            }
            val_len = strlen(val_start) + 1;
        }

        if (val_len > sysgetenv.vallen)
            return E2BIG;

        copy_len = val_len < sysgetenv.vallen ? val_len : sysgetenv.vallen;
        s = sys_datacopy(SELF, (vir_bytes) val_start, who_e, (vir_bytes) sysgetenv.val, copy_len);
        if (s != OK) return s;

        return OK;
    }
    default:
        return EINVAL;
    }
}

/*===========================================================================*
 *				do_getrusage				     *
 *===========================================================================*/
int do_getrusage(void)
{
    clock_t user_time = 0, sys_time = 0;
    struct rusage r_usage;
    int r = OK;
    int is_children = 0;

    if (m_in.m_lc_pm_rusage.who != RUSAGE_SELF &&
        m_in.m_lc_pm_rusage.who != RUSAGE_CHILDREN)
        return EINVAL;

    memset(&r_usage, 0, sizeof(r_usage));
    is_children = (m_in.m_lc_pm_rusage.who == RUSAGE_CHILDREN);

    if (!is_children) {
        r = sys_times(who_e, &user_time, &sys_time, NULL, NULL);
        if (r != OK)
            return r;
    } else {
        user_time = mp->mp_child_utime;
        sys_time = mp->mp_child_stime;
    }

    set_rusage_times(&r_usage, user_time, sys_time);

    r = vm_getrusage(who_e, &r_usage, is_children);
    if (r != OK)
        return r;

    return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e,
                        m_in.m_lc_pm_rusage.addr, (vir_bytes)sizeof(r_usage));
}
