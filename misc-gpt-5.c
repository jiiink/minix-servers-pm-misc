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
    size_t src_len, copy_len;
    const char *uname_str;

    if (m_in.m_lc_pm_sysuname.field >= __arraycount(uts_tbl)) {
        return EINVAL;
    }

    uname_str = uts_tbl[m_in.m_lc_pm_sysuname.field];
    if (uname_str == NULL) {
        return EINVAL;
    }

    if (m_in.m_lc_pm_sysuname.req != 0) {
        return EINVAL;
    }

    src_len = strlen(uname_str) + 1;
    copy_len = src_len;
    if (copy_len > m_in.m_lc_pm_sysuname.len) {
        copy_len = m_in.m_lc_pm_sysuname.len;
    }

    r = sys_datacopy(SELF, (vir_bytes)uname_str, mp->mp_endpoint,
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
    vir_bytes src_addr = 0;
    vir_bytes dst_addr;
    size_t len = 0;
    int what;
    size_t size;

    if (mp == NULL || mp->mp_effuid != 0) {
        printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n",
               mp ? mp->mp_endpoint : -1, mp ? mp->mp_name : "(null)");
        if (mp) sys_diagctl_stacktrace(mp->mp_endpoint);
        return EPERM;
    }

    what = m_in.m_lsys_getsysinfo.what;
    size = m_in.m_lsys_getsysinfo.size;
    dst_addr = m_in.m_lsys_getsysinfo.where;

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
  struct mproc *proc;

  if (who_e != RS_PROC_NR) {
    printf("PM: unauthorized call of do_getprocnr by %d\n", who_e);
    return EPERM;
  }

  proc = find_proc(m_in.m_lsys_pm_getprocnr.pid);
  if (proc == NULL) {
    return ESRCH;
  }

  mp->mp_reply.m_pm_lsys_getprocnr.endpt = proc->mp_endpoint;
  return OK;
}

/*===========================================================================*
 *				do_getepinfo			             *
 *===========================================================================*/
int do_getepinfo(void)
{
  struct mproc *rmp;
  endpoint_t ep = m_in.m_lsys_pm_getepinfo.endpt;
  int slot;

  if (pm_isokendpt(ep, &slot) != OK)
    return ESRCH;

  rmp = &mproc[slot];

  mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_realuid;
  mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp->mp_effuid;
  mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_realgid;
  mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp->mp_effgid;

  {
    int total = rmp->mp_ngroups;
    int req = m_in.m_lsys_pm_getepinfo.ngroups;

    if (total < 0) total = 0;
    mp->mp_reply.m_pm_lsys_getepinfo.ngroups = total;

    if (req < 0) req = 0;

    {
      int to_copy = (total < req) ? total : req;

      if (to_copy > 0) {
        size_t bytes = (size_t)to_copy * sizeof(gid_t);
        int r = sys_datacopy(SELF, (vir_bytes) rmp->mp_sgroups,
                             who_e, m_in.m_lsys_pm_getepinfo.groups, bytes);
        if (r != OK)
          return r;
      }
    }
  }

  return rmp->mp_pid;
}

/*===========================================================================*
 *				do_reboot				     *
 *===========================================================================*/
int do_reboot(void)
{
  message vfs_msg;
  message rc_msg;
  endpoint_t readclock_ep;

  if (mp->mp_effuid != SUPER_USER) return EPERM;

  abort_flag = m_in.m_lc_pm_reboot.how;

  if (abort_flag & RB_POWERDOWN) {
    if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
      memset(&rc_msg, 0, sizeof(rc_msg));
      _taskcall(readclock_ep, RTCDEV_PWR_OFF, &rc_msg);
    }
  }

  check_sig(-1, SIGKILL, FALSE);
  sys_stop(INIT_PROC_NR);

  memset(&vfs_msg, 0, sizeof(vfs_msg));
  vfs_msg.m_type = VFS_PM_REBOOT;
  tell_vfs(&mproc[VFS_PROC_NR], &vfs_msg);

  return SUSPEND;
}

/*===========================================================================*
 *				do_getsetpriority			     *
 *===========================================================================*/
int do_getsetpriority(void)
{
	int which = m_in.m_lc_pm_priority.which;
	int who = m_in.m_lc_pm_priority.who;
	int pri = m_in.m_lc_pm_priority.prio;
	struct mproc *target;

	if (which != PRIO_PROCESS)
		return EINVAL;

	if (who == 0) {
		target = mp;
	} else {
		target = find_proc(who);
		if (target == NULL)
			return ESRCH;
	}

	if (mp->mp_effuid != SUPER_USER &&
	    mp->mp_effuid != target->mp_effuid &&
	    mp->mp_effuid != target->mp_realuid)
		return EPERM;

	if (call_nr == PM_GETPRIORITY)
		return target->mp_nice - PRIO_MIN;

	if (target->mp_nice > pri && mp->mp_effuid != SUPER_USER)
		return EACCES;

	{
		int res = sched_nice(target, pri);
		if (res != OK)
			return res;
	}

	target->mp_nice = pri;
	return OK;
}

/*===========================================================================*
 *				do_svrctl				     *
 *===========================================================================*/
int do_svrctl(void)
{
  unsigned long req;
  int r;
  vir_bytes ptr;
#define MAX_LOCAL_PARAMS 2
  static struct {
    char name[30];
    char value[30];
  } local_param_overrides[MAX_LOCAL_PARAMS];
  static int local_params = 0;

  req = m_in.m_lc_svrctl.request;
  ptr = m_in.m_lc_svrctl.arg;

  if (IOCGROUP(req) != 'P' && IOCGROUP(req) != 'M') {
    return EINVAL;
  }

  switch (req) {
    case OPMSETPARAM:
    case OPMGETPARAM:
    case PMSETPARAM:
    case PMGETPARAM: {
      struct sysgetenv sysgetenv;
      char search_key[64] = {0};
      char *val_start = NULL;
      size_t val_len = 0;
      size_t copy_len;

      if (sys_datacopy(who_e, ptr, SELF, (vir_bytes)&sysgetenv, sizeof(sysgetenv)) != OK) {
        return EFAULT;
      }

      if (req == PMSETPARAM || req == OPMSETPARAM) {
        if (local_params >= MAX_LOCAL_PARAMS) {
          return ENOSPC;
        }
        if (sysgetenv.keylen <= 0 ||
            sysgetenv.keylen >= sizeof(local_param_overrides[local_params].name) ||
            sysgetenv.vallen <= 0 ||
            sysgetenv.vallen >= sizeof(local_param_overrides[local_params].value)) {
          return EINVAL;
        }

        r = sys_datacopy(who_e, (vir_bytes)sysgetenv.key,
                         SELF, (vir_bytes)local_param_overrides[local_params].name,
                         sysgetenv.keylen);
        if (r != OK) {
          return r;
        }
        r = sys_datacopy(who_e, (vir_bytes)sysgetenv.val,
                         SELF, (vir_bytes)local_param_overrides[local_params].value,
                         sysgetenv.vallen);
        if (r != OK) {
          return r;
        }

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

        if (sysgetenv.keylen > sizeof(search_key)) {
          return EINVAL;
        }

        r = sys_datacopy(who_e, (vir_bytes)sysgetenv.key,
                         SELF, (vir_bytes)search_key, sysgetenv.keylen);
        if (r != OK) {
          return r;
        }

        search_key[sysgetenv.keylen - 1] = '\0';

        for (p = 0; p < local_params; p++) {
          if (!strcmp(search_key, local_param_overrides[p].name)) {
            val_start = local_param_overrides[p].value;
            break;
          }
        }

        if (val_start == NULL) {
          val_start = find_param(search_key);
          if (val_start == NULL) {
            return ESRCH;
          }
        }

        val_len = strlen(val_start) + 1;
      }

      if (val_len > (size_t)sysgetenv.vallen) {
        return E2BIG;
      }

      copy_len = val_len;
      r = sys_datacopy(SELF, (vir_bytes)val_start, who_e, (vir_bytes)sysgetenv.val, copy_len);
      if (r != OK) {
        return r;
      }

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
	int r;
	const int who = m_in.m_lc_pm_rusage.who;
	const vir_bytes addr = m_in.m_lc_pm_rusage.addr;

	switch (who) {
	case RUSAGE_SELF:
	case RUSAGE_CHILDREN:
		break;
	default:
		return EINVAL;
	}

	memset(&r_usage, 0, sizeof(struct rusage));

	if (who == RUSAGE_CHILDREN) {
		user_time = mp->mp_child_utime;
		sys_time = mp->mp_child_stime;
	} else {
		r = sys_times(who_e, &user_time, &sys_time, NULL, NULL);
		if (r != OK)
			return r;
	}

	set_rusage_times(&r_usage, user_time, sys_time);

	r = vm_getrusage(who_e, &r_usage, who == RUSAGE_CHILDREN);
	if (r != OK)
		return r;

	return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e, addr,
	    (vir_bytes)sizeof(struct rusage));
}
