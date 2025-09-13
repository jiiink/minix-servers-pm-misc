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
int do_sysuname(void) {
    int r;
    size_t n;
    char *string;

    if (m_in.m_lc_pm_sysuname.field >= __arraycount(uts_tbl) || 
        (string = uts_tbl[m_in.m_lc_pm_sysuname.field]) == NULL) {
        return EINVAL;
    }

    if (m_in.m_lc_pm_sysuname.req == 0) {
        n = strlen(string) + 1;
        if (n > m_in.m_lc_pm_sysuname.len) {
            n = m_in.m_lc_pm_sysuname.len;
        }
        r = sys_datacopy(SELF, (vir_bytes)string, mp->mp_endpoint,
                         m_in.m_lc_pm_sysuname.value, (phys_bytes)n);
        if (r < 0) {
            return r;
        }
        return n;
    }

    return EINVAL;
}
/* END OF COMPATIBILITY BLOCK */


/*===========================================================================*
 *				do_getsysinfo			       	     *
 *===========================================================================*/
#include <errno.h>
#include <stddef.h>

int do_getsysinfo(void) {
    vir_bytes src_addr, dst_addr;
    size_t len;

    if (mp->mp_effuid != 0) {
        printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n", mp->mp_endpoint, mp->mp_name);
        sys_diagctl_stacktrace(mp->mp_endpoint);
        return EPERM;
    }

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

    if (len != m_in.m_lsys_getsysinfo.size) {
        return EINVAL;
    }

    dst_addr = m_in.m_lsys_getsysinfo.where;
    return sys_datacopy(SELF, src_addr, who_e, dst_addr, len);
}

/*===========================================================================*
 *				do_getprocnr			             *
 *===========================================================================*/
#include <stdio.h>

int do_getprocnr(void) {
    struct mproc *rmp;

    if (who_e != RS_PROC_NR) {
        fprintf(stderr, "PM: unauthorized call of do_getprocnr by %d\n", who_e);
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
#include <errno.h>

int do_getepinfo(void) {
    struct mproc *rmp;
    endpoint_t ep;
    int r, slot, ngroups;

    ep = m_in.m_lsys_pm_getepinfo.endpt;
    if (pm_isokendpt(ep, &slot) != OK) {
        return ESRCH;
    }

    rmp = &mproc[slot];

    if (rmp == NULL) {
        return EFAULT;
    }

    mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_realuid;
    mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp->mp_effuid;
    mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_realgid;
    mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp->mp_effgid;
    mp->mp_reply.m_pm_lsys_getepinfo.ngroups = rmp->mp_ngroups;

    ngroups = rmp->mp_ngroups;
    int max_groups = m_in.m_lsys_pm_getepinfo.ngroups;
    ngroups = (ngroups > max_groups) ? max_groups : ngroups;

    if (ngroups > 0) {
        r = sys_datacopy(SELF, (vir_bytes)rmp->mp_sgroups, who_e, m_in.m_lsys_pm_getepinfo.groups, ngroups * sizeof(gid_t));
        if (r != OK) {
            return r;
        }
    }

    return rmp->mp_pid;
}

/*===========================================================================*
 *				do_reboot				     *
 *===========================================================================*/
#include <errno.h>
#include <string.h>

int do_reboot(void) {
    message m;
    
    if (mp->mp_effuid != SUPER_USER) {
        return EPERM;
    }

    abort_flag = m_in.m_lc_pm_reboot.how;

    if (abort_flag & RB_POWERDOWN) {
        endpoint_t readclock_ep;
        if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
            message rtc_message;
            _taskcall(readclock_ep, RTCDEV_PWR_OFF, &rtc_message);
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
int do_getsetpriority(void) {
    int r, arg_which, arg_who, arg_pri;
    struct mproc *rmp;

    arg_which = m_in.m_lc_pm_priority.which;
    arg_who = m_in.m_lc_pm_priority.who;
    arg_pri = m_in.m_lc_pm_priority.prio;

    if (arg_which != PRIO_PROCESS) {
        return EINVAL;
    }

    if (arg_who == 0) {
        rmp = mp;
    } else if ((rmp = find_proc(arg_who)) == NULL) {
        return ESRCH;
    }

    if (mp->mp_effuid != SUPER_USER && mp->mp_effuid != rmp->mp_effuid && mp->mp_effuid != rmp->mp_realuid) {
        return EPERM;
    }

    if (call_nr == PM_GETPRIORITY) {
        return (rmp->mp_nice - PRIO_MIN);
    }

    if (rmp->mp_nice > arg_pri && mp->mp_effuid != SUPER_USER) {
        return EACCES;
    }

    r = sched_nice(rmp, arg_pri);
    if (r != OK) {
        return r;
    }

    rmp->mp_nice = arg_pri;
    return OK;
}

/*===========================================================================*
 *				do_svrctl				     *
 *===========================================================================*/
int do_svrctl(void) {
    unsigned long req = m_in.m_lc_svrctl.request;
    vir_bytes ptr = m_in.m_lc_svrctl.arg;
    int status;
    #define MAX_LOCAL_PARAMS 2
    struct {
        char name[30];
        char value[30];
    } static local_param_overrides[MAX_LOCAL_PARAMS];
    static int local_params = 0;

    if (IOCGROUP(req) != 'P' && IOCGROUP(req) != 'M') return EINVAL;

    switch (req) {
        case OPMSETPARAM:
        case PMSETPARAM: {
            struct sysgetenv sysgetenv;
            if (sys_datacopy(who_e, ptr, SELF, (vir_bytes)&sysgetenv, sizeof(sysgetenv)) != OK) return EFAULT;

            if (local_params >= MAX_LOCAL_PARAMS || sysgetenv.keylen <= 0 || 
                sysgetenv.keylen >= sizeof(local_param_overrides[local_params].name) || 
                sysgetenv.vallen <= 0 || 
                sysgetenv.vallen >= sizeof(local_param_overrides[local_params].value)) 
                return EINVAL;

            if ((status = sys_datacopy(who_e, (vir_bytes)sysgetenv.key, SELF, 
                (vir_bytes)local_param_overrides[local_params].name, sysgetenv.keylen)) != OK) 
                return status;

            if ((status = sys_datacopy(who_e, (vir_bytes)sysgetenv.val, SELF, 
                (vir_bytes)local_param_overrides[local_params].value, sysgetenv.vallen)) != OK) 
                return status;

            local_param_overrides[local_params].name[sysgetenv.keylen] = '\0';
            local_param_overrides[local_params].value[sysgetenv.vallen] = '\0';
            local_params++;
            return OK;
        }

        case OPMGETPARAM:
        case PMGETPARAM: {
            struct sysgetenv sysgetenv;
            char search_key[64];
            char *val_start;
            size_t val_len;
            size_t copy_len;

            if (sys_datacopy(who_e, ptr, SELF, (vir_bytes)&sysgetenv, sizeof(sysgetenv)) != OK) return EFAULT;

            if (sysgetenv.keylen == 0) {
                val_start = monitor_params;
                val_len = sizeof(monitor_params);
            } else {
                if (sysgetenv.keylen > sizeof(search_key)) return EINVAL;
                if ((status = sys_datacopy(who_e, (vir_bytes)sysgetenv.key, SELF, (vir_bytes)search_key, sysgetenv.keylen)) != OK) 
                    return status;

                search_key[sysgetenv.keylen - 1] = '\0';
                val_start = NULL;

                for (int p = 0; p < local_params; p++) {
                    if (!strcmp(search_key, local_param_overrides[p].name)) {
                        val_start = local_param_overrides[p].value;
                        break;
                    }
                }

                if (!val_start) val_start = find_param(search_key);
                if (!val_start) return ESRCH;

                val_len = strlen(val_start) + 1;
            }

            if (val_len > sysgetenv.vallen) return E2BIG;

            copy_len = MIN(val_len, sysgetenv.vallen);
            if ((status = sys_datacopy(SELF, (vir_bytes)val_start, who_e, (vir_bytes)sysgetenv.val, copy_len)) != OK) 
                return status;

            return OK;
        }

        default:
            return EINVAL;
    }
}

/*===========================================================================*
 *				do_getrusage				     *
 *===========================================================================*/
int do_getrusage(void) {
    clock_t user_time, sys_time;
    struct rusage r_usage;
    int r;
    int is_children = (m_in.m_lc_pm_rusage.who == RUSAGE_CHILDREN);

    if (m_in.m_lc_pm_rusage.who != RUSAGE_SELF && !is_children) {
        return EINVAL;
    }

    memset(&r_usage, 0, sizeof(r_usage));

    if (!is_children) {
        r = sys_times(who_e, &user_time, &sys_time, NULL, NULL);
        if (r != OK) {
            return r;
        }
    } else {
        user_time = mp->mp_child_utime;
        sys_time = mp->mp_child_stime;
    }

    set_rusage_times(&r_usage, user_time, sys_time);

    r = vm_getrusage(who_e, &r_usage, is_children);
    if (r != OK) {
        return r;
    }

    return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e, m_in.m_lc_pm_rusage.addr, (vir_bytes)sizeof(r_usage));
}
