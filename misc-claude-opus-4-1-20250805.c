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
  size_t field_index;
  size_t request_type;
  size_t buffer_len;
  vir_bytes user_buffer;
  char *field_string;
  size_t copy_len;
  int result;

  field_index = m_in.m_lc_pm_sysuname.field;
  request_type = m_in.m_lc_pm_sysuname.req;
  buffer_len = m_in.m_lc_pm_sysuname.len;
  user_buffer = m_in.m_lc_pm_sysuname.value;

  if (field_index >= __arraycount(uts_tbl)) {
    return EINVAL;
  }

  field_string = uts_tbl[field_index];
  if (field_string == NULL) {
    return EINVAL;
  }

  if (request_type != 0) {
    return EINVAL;
  }

  copy_len = strlen(field_string) + 1;
  if (copy_len > buffer_len) {
    copy_len = buffer_len;
  }

  result = sys_datacopy(SELF, (vir_bytes)field_string, mp->mp_endpoint,
                        user_buffer, (phys_bytes)copy_len);
  if (result < 0) {
    return result;
  }

  return copy_len;
}
/* END OF COMPATIBILITY BLOCK */


/*===========================================================================*
 *				do_getsysinfo			       	     *
 *===========================================================================*/
int
do_getsysinfo(void)
{
  vir_bytes src_addr;
  vir_bytes dst_addr;
  size_t len;
  int request_type;

  if (mp->mp_effuid != 0) {
    printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n",
           mp->mp_endpoint, mp->mp_name);
    sys_diagctl_stacktrace(mp->mp_endpoint);
    return EPERM;
  }

  request_type = m_in.m_lsys_getsysinfo.what;
  
  if (request_type == SI_PROC_TAB) {
    src_addr = (vir_bytes) mproc;
    len = sizeof(struct mproc) * NR_PROCS;
  }
#if ENABLE_SYSCALL_STATS
  else if (request_type == SI_CALL_STATS) {
    src_addr = (vir_bytes) calls_stats;
    len = sizeof(calls_stats);
  }
#endif
  else {
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
int do_getprocnr(void)
{
  register struct mproc *rmp;

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
  struct mproc *rmp;
  endpoint_t ep;
  int slot;
  int ngroups_to_copy;
  int result;

  ep = m_in.m_lsys_pm_getepinfo.endpt;
  
  if (pm_isokendpt(ep, &slot) != OK) {
    return ESRCH;
  }
  
  rmp = &mproc[slot];

  mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_realuid;
  mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp->mp_effuid;
  mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_realgid;
  mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp->mp_effgid;
  mp->mp_reply.m_pm_lsys_getepinfo.ngroups = rmp->mp_ngroups;
  
  ngroups_to_copy = rmp->mp_ngroups;
  
  if (ngroups_to_copy > m_in.m_lsys_pm_getepinfo.ngroups) {
    ngroups_to_copy = m_in.m_lsys_pm_getepinfo.ngroups;
  }
  
  if (ngroups_to_copy > 0) {
    result = sys_datacopy(SELF, 
                         (vir_bytes)rmp->mp_sgroups, 
                         who_e,
                         m_in.m_lsys_pm_getepinfo.groups, 
                         ngroups_to_copy * sizeof(gid_t));
    
    if (result != OK) {
      return result;
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
  message m;
  endpoint_t readclock_ep;
  int result;

  if (mp->mp_effuid != SUPER_USER) {
    return EPERM;
  }

  abort_flag = m_in.m_lc_pm_reboot.how;

  if ((abort_flag & RB_POWERDOWN) != 0) {
    result = ds_retrieve_label_endpt("readclock.drv", &readclock_ep);
    if (result == OK) {
      message power_msg;
      memset(&power_msg, 0, sizeof(power_msg));
      _taskcall(readclock_ep, RTCDEV_PWR_OFF, &power_msg);
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
int
do_getsetpriority(void)
{
	int arg_which = m_in.m_lc_pm_priority.which;
	int arg_who = m_in.m_lc_pm_priority.who;
	int arg_pri = m_in.m_lc_pm_priority.prio;
	struct mproc *rmp;

	if (arg_which != PRIO_PROCESS) {
		return EINVAL;
	}

	if (arg_who == 0) {
		rmp = mp;
	} else {
		rmp = find_proc(arg_who);
		if (rmp == NULL) {
			return ESRCH;
		}
	}

	if (mp->mp_effuid != SUPER_USER &&
	    mp->mp_effuid != rmp->mp_effuid && 
	    mp->mp_effuid != rmp->mp_realuid) {
		return EPERM;
	}

	if (call_nr == PM_GETPRIORITY) {
		return rmp->mp_nice - PRIO_MIN;
	}

	if (rmp->mp_nice > arg_pri && mp->mp_effuid != SUPER_USER) {
		return EACCES;
	}

	int r = sched_nice(rmp, arg_pri);
	if (r != OK) {
		return r;
	}

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

    if (req != OPMSETPARAM && req != OPMGETPARAM && 
        req != PMSETPARAM && req != PMGETPARAM) {
        return EINVAL;
    }

    struct sysgetenv sysgetenv;
    if (sys_datacopy(who_e, ptr, SELF, (vir_bytes)&sysgetenv, 
                     sizeof(sysgetenv)) != OK) {
        return EFAULT;
    }

    if (req == PMSETPARAM || req == OPMSETPARAM) {
        if (local_params >= MAX_LOCAL_PARAMS) {
            return ENOSPC;
        }
        
        if (sysgetenv.keylen <= 0 || 
            sysgetenv.keylen >= sizeof(local_param_overrides[0].name) ||
            sysgetenv.vallen <= 0 || 
            sysgetenv.vallen >= sizeof(local_param_overrides[0].value)) {
            return EINVAL;
        }

        s = sys_datacopy(who_e, (vir_bytes)sysgetenv.key, SELF,
                         (vir_bytes)local_param_overrides[local_params].name,
                         sysgetenv.keylen);
        if (s != OK) {
            return s;
        }

        s = sys_datacopy(who_e, (vir_bytes)sysgetenv.val, SELF,
                         (vir_bytes)local_param_overrides[local_params].value,
                         sysgetenv.vallen);
        if (s != OK) {
            return s;
        }

        local_param_overrides[local_params].name[sysgetenv.keylen] = '\0';
        local_param_overrides[local_params].value[sysgetenv.vallen] = '\0';
        local_params++;
        
        return OK;
    }

    char *val_start;
    size_t val_len;

    if (sysgetenv.keylen == 0) {
        val_start = monitor_params;
        val_len = sizeof(monitor_params);
    } else {
        char search_key[64];
        
        if (sysgetenv.keylen > sizeof(search_key)) {
            return EINVAL;
        }
        
        s = sys_datacopy(who_e, (vir_bytes)sysgetenv.key, SELF,
                         (vir_bytes)search_key, sysgetenv.keylen);
        if (s != OK) {
            return s;
        }

        search_key[sysgetenv.keylen - 1] = '\0';
        
        val_start = NULL;
        for (int p = 0; p < local_params; p++) {
            if (strcmp(search_key, local_param_overrides[p].name) == 0) {
                val_start = local_param_overrides[p].value;
                break;
            }
        }
        
        if (val_start == NULL) {
            val_start = find_param(search_key);
        }
        
        if (val_start == NULL) {
            return ESRCH;
        }
        
        val_len = strlen(val_start) + 1;
    }

    if (val_len > sysgetenv.vallen) {
        return E2BIG;
    }

    size_t copy_len = MIN(val_len, sysgetenv.vallen);
    s = sys_datacopy(SELF, (vir_bytes)val_start, who_e,
                     (vir_bytes)sysgetenv.val, copy_len);
    if (s != OK) {
        return s;
    }

    return OK;
}

/*===========================================================================*
 *				do_getrusage				     *
 *===========================================================================*/
int
do_getrusage(void)
{
	clock_t user_time, sys_time;
	struct rusage r_usage;
	int r;
	int who = m_in.m_lc_pm_rusage.who;
	int is_children = (who == RUSAGE_CHILDREN);

	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN)
		return EINVAL;

	memset(&r_usage, 0, sizeof(r_usage));

	if (is_children) {
		user_time = mp->mp_child_utime;
		sys_time = mp->mp_child_stime;
	} else {
		r = sys_times(who_e, &user_time, &sys_time, NULL, NULL);
		if (r != OK)
			return r;
	}

	set_rusage_times(&r_usage, user_time, sys_time);

	r = vm_getrusage(who_e, &r_usage, is_children);
	if (r != OK)
		return r;

	return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e,
	    m_in.m_lc_pm_rusage.addr, (vir_bytes)sizeof(r_usage));
}
