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
  if (m_in.m_lc_pm_sysuname.field >= __arraycount(uts_tbl)) 
    return EINVAL;

  char *string = uts_tbl[m_in.m_lc_pm_sysuname.field];
  if (string == NULL)
    return EINVAL;

  if (m_in.m_lc_pm_sysuname.req != 0)
    return EINVAL;

  size_t n = strlen(string) + 1;
  if (n > m_in.m_lc_pm_sysuname.len) 
    n = m_in.m_lc_pm_sysuname.len;
  
  int r = sys_datacopy(SELF, (vir_bytes)string, mp->mp_endpoint,
    m_in.m_lc_pm_sysuname.value, (phys_bytes)n);
  
  if (r < 0) 
    return r;
  
  return n;
}
/* END OF COMPATIBILITY BLOCK */


/*===========================================================================*
 *				do_getsysinfo			       	     *
 *===========================================================================*/
int
do_getsysinfo(void)
{
  vir_bytes src_addr, dst_addr;
  size_t len;

  if (mp->mp_effuid != 0)
  {
	printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n",
		mp->mp_endpoint, mp->mp_name);
	sys_diagctl_stacktrace(mp->mp_endpoint);
	return EPERM;
  }

  switch(m_in.m_lsys_getsysinfo.what) {
  case SI_PROC_TAB:
        src_addr = (vir_bytes) mproc;
        len = sizeof(struct mproc) * NR_PROCS;
        break;
#if ENABLE_SYSCALL_STATS
  case SI_CALL_STATS:
  	src_addr = (vir_bytes) calls_stats;
  	len = sizeof(calls_stats);
  	break;
#endif
  default:
  	return(EINVAL);
  }

  if (len != m_in.m_lsys_getsysinfo.size)
	return(EINVAL);

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

  ep = m_in.m_lsys_pm_getepinfo.endpt;
  if (pm_isokendpt(ep, &slot) != OK)
	return(ESRCH);
  rmp = &mproc[slot];

  populate_reply_credentials(rmp);
  
  int result = copy_supplementary_groups(rmp);
  if (result != OK)
	return(result);
  
  return(rmp->mp_pid);
}

static void populate_reply_credentials(struct mproc *rmp)
{
  mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_realuid;
  mp->mp_reply.m_pm_lsys_getepinfo.euid = rmp->mp_effuid;
  mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_realgid;
  mp->mp_reply.m_pm_lsys_getepinfo.egid = rmp->mp_effgid;
  mp->mp_reply.m_pm_lsys_getepinfo.ngroups = rmp->mp_ngroups;
}

static int copy_supplementary_groups(struct mproc *rmp)
{
  int ngroups = rmp->mp_ngroups;
  if (ngroups > m_in.m_lsys_pm_getepinfo.ngroups)
	ngroups = m_in.m_lsys_pm_getepinfo.ngroups;
  
  if (ngroups <= 0)
	return(OK);
	
  return sys_datacopy(SELF, (vir_bytes)rmp->mp_sgroups, who_e,
	m_in.m_lsys_pm_getepinfo.groups, ngroups * sizeof(gid_t));
}

/*===========================================================================*
 *				do_reboot				     *
 *===========================================================================*/
int
do_reboot(void)
{
  message m;

  if (mp->mp_effuid != SUPER_USER) return(EPERM);

  abort_flag = m_in.m_lc_pm_reboot.how;

  notify_readclock_if_powerdown();
  kill_all_processes();
  send_reboot_to_vfs(&m);

  return(SUSPEND);
}

static void
notify_readclock_if_powerdown(void)
{
  endpoint_t readclock_ep;
  message m;

  if (!(abort_flag & RB_POWERDOWN)) return;
  
  if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
    _taskcall(readclock_ep, RTCDEV_PWR_OFF, &m);
  }
}

static void
kill_all_processes(void)
{
  check_sig(-1, SIGKILL, FALSE);
  sys_stop(INIT_PROC_NR);
}

static void
send_reboot_to_vfs(message *m)
{
  memset(m, 0, sizeof(message));
  m->m_type = VFS_PM_REBOOT;
  tell_vfs(&mproc[VFS_PROC_NR], m);
}

/*===========================================================================*
 *				do_getsetpriority			     *
 *===========================================================================*/
int
do_getsetpriority(void)
{
	int arg_which, arg_who, arg_pri;
	struct mproc *rmp;

	arg_which = m_in.m_lc_pm_priority.which;
	arg_who = m_in.m_lc_pm_priority.who;
	arg_pri = m_in.m_lc_pm_priority.prio;

	if (arg_which != PRIO_PROCESS)
		return EINVAL;

	rmp = get_target_process(arg_who);
	if (rmp == NULL)
		return ESRCH;

	if (!has_permission_for_process(rmp))
		return EPERM;

	if (call_nr == PM_GETPRIORITY)
		return rmp->mp_nice - PRIO_MIN;

	return set_process_priority(rmp, arg_pri);
}

static struct mproc *
get_target_process(int who)
{
	if (who == 0)
		return mp;
	return find_proc(who);
}

static int
has_permission_for_process(struct mproc *rmp)
{
	if (mp->mp_effuid == SUPER_USER)
		return 1;
	if (mp->mp_effuid == rmp->mp_effuid)
		return 1;
	if (mp->mp_effuid == rmp->mp_realuid)
		return 1;
	return 0;
}

static int
set_process_priority(struct mproc *rmp, int new_priority)
{
	int r;

	if (rmp->mp_nice > new_priority && mp->mp_effuid != SUPER_USER)
		return EACCES;

	r = sched_nice(rmp, new_priority);
	if (r != OK)
		return r;

	rmp->mp_nice = new_priority;
	return OK;
}

/*===========================================================================*
 *				do_svrctl				     *
 *===========================================================================*/
#define MAX_LOCAL_PARAMS 2
#define MAX_NAME_LEN 30
#define MAX_VALUE_LEN 30
#define MAX_SEARCH_KEY_LEN 64

static struct {
    char name[MAX_NAME_LEN];
    char value[MAX_VALUE_LEN];
} local_param_overrides[MAX_LOCAL_PARAMS];
static int local_params = 0;

static int validate_sysgetenv_lengths(struct sysgetenv *sysgetenv, int is_set_param) {
    if (!is_set_param) return OK;
    
    if (sysgetenv->keylen <= 0 || sysgetenv->keylen >= MAX_NAME_LEN ||
        sysgetenv->vallen <= 0 || sysgetenv->vallen >= MAX_VALUE_LEN) {
        return EINVAL;
    }
    return OK;
}

static int copy_param_data(int who_e, struct sysgetenv *sysgetenv, int index) {
    int s;
    
    if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv->key,
        SELF, (vir_bytes) local_param_overrides[index].name,
        sysgetenv->keylen)) != OK)
        return s;
        
    if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv->val,
        SELF, (vir_bytes) local_param_overrides[index].value,
        sysgetenv->vallen)) != OK)
        return s;
        
    local_param_overrides[index].name[sysgetenv->keylen] = '\0';
    local_param_overrides[index].value[sysgetenv->vallen] = '\0';
    
    return OK;
}

static int handle_set_param(int who_e, struct sysgetenv *sysgetenv) {
    if (local_params >= MAX_LOCAL_PARAMS) return ENOSPC;
    
    int s = validate_sysgetenv_lengths(sysgetenv, 1);
    if (s != OK) return s;
    
    s = copy_param_data(who_e, sysgetenv, local_params);
    if (s != OK) return s;
    
    local_params++;
    return OK;
}

static char* find_local_override(char *search_key) {
    for (int p = 0; p < local_params; p++) {
        if (!strcmp(search_key, local_param_overrides[p].name)) {
            return local_param_overrides[p].value;
        }
    }
    return NULL;
}

static int get_search_key(int who_e, struct sysgetenv *sysgetenv, char *search_key) {
    if (sysgetenv->keylen > MAX_SEARCH_KEY_LEN) return EINVAL;
    
    int s = sys_datacopy(who_e, (vir_bytes) sysgetenv->key,
            SELF, (vir_bytes) search_key, sysgetenv->keylen);
    if (s != OK) return s;
    
    search_key[sysgetenv->keylen - 1] = '\0';
    return OK;
}

static int handle_get_param(int who_e, struct sysgetenv *sysgetenv) {
    char search_key[MAX_SEARCH_KEY_LEN];
    char *val_start;
    size_t val_len;
    
    if (sysgetenv->keylen == 0) {
        val_start = monitor_params;
        val_len = sizeof(monitor_params);
    } else {
        int s = get_search_key(who_e, sysgetenv, search_key);
        if (s != OK) return s;
        
        val_start = find_local_override(search_key);
        if (val_start == NULL) {
            val_start = find_param(search_key);
            if (val_start == NULL) return ESRCH;
        }
        val_len = strlen(val_start) + 1;
    }
    
    if (val_len > sysgetenv->vallen) return E2BIG;
    
    size_t copy_len = MIN(val_len, sysgetenv->vallen);
    return sys_datacopy(SELF, (vir_bytes) val_start,
            who_e, (vir_bytes) sysgetenv->val, copy_len);
}

static int handle_param_request(int who_e, vir_bytes ptr, unsigned long req) {
    struct sysgetenv sysgetenv;
    
    if (sys_datacopy(who_e, ptr, SELF, (vir_bytes) &sysgetenv,
            sizeof(sysgetenv)) != OK) return EFAULT;
    
    if (req == PMSETPARAM || req == OPMSETPARAM) {
        return handle_set_param(who_e, &sysgetenv);
    }
    
    return handle_get_param(who_e, &sysgetenv);
}

int do_svrctl(void) {
    unsigned long req = m_in.m_lc_svrctl.request;
    vir_bytes ptr = m_in.m_lc_svrctl.arg;
    
    if (IOCGROUP(req) != 'P' && IOCGROUP(req) != 'M') return EINVAL;
    
    switch(req) {
    case OPMSETPARAM:
    case OPMGETPARAM:
    case PMSETPARAM:
    case PMGETPARAM:
        return handle_param_request(who_e, ptr, req);
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
	int who = m_in.m_lc_pm_rusage.who;
	
	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN)
		return EINVAL;

	struct rusage r_usage;
	memset(&r_usage, 0, sizeof(r_usage));

	clock_t user_time, sys_time;
	int r = get_process_times(who, &user_time, &sys_time);
	if (r != OK)
		return r;

	set_rusage_times(&r_usage, user_time, sys_time);

	int children = (who == RUSAGE_CHILDREN);
	r = vm_getrusage(who_e, &r_usage, children);
	if (r != OK)
		return r;

	return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e,
	    m_in.m_lc_pm_rusage.addr, (vir_bytes)sizeof(r_usage));
}

int
get_process_times(int who, clock_t *user_time, clock_t *sys_time)
{
	if (who == RUSAGE_CHILDREN) {
		*user_time = mp->mp_child_utime;
		*sys_time = mp->mp_child_stime;
		return OK;
	}
	
	return sys_times(who_e, user_time, sys_time, NULL, NULL);
}
