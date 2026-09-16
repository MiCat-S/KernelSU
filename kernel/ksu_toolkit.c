#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/utsname.h>
#include <linux/wait.h>

#include "arch.h"
#include "feature/sucompat.h"
#include "klog.h"
#include "ksu.h"
#include "ksu_toolkit.h"
#include "manager/manager_identity.h"
#include "policy/allowlist.h"
#include "runtime/ksud.h"
#include "selinux/selinux.h"
#include "sulog/event.h"
#include "uapi/supercall.h"

#define TOOLKIT_CHANGE_MANAGER_UID 10006
#define TOOLKIT_GET_SULOG_DUMP_V2 10010
#define TOOLKIT_CHANGE_KSUVER 10011
#define TOOLKIT_CHANGE_SPOOF_UNAME 10012
#define TOOLKIT_CHANGE_KSUFLAGS 10013

#define TOOLKIT_SU_PATH "/system/bin/su"
#define TOOLKIT_SH_PATH "/system/bin/sh"
#define TOOLKIT_SULOG_ENTRY_MAX 250U

struct toolkit_sulog_entry {
    u32 s_time;
    u32 data;
} __packed;

struct toolkit_sulog_receive {
    u64 index_ptr;
    u64 buf_ptr;
    u64 uptime_ptr;
};

struct toolkit_work {
    struct callback_head work;
    u32 op;
    u32 value;
    unsigned long user_arg;
};

#ifdef CONFIG_KSU_SUSFS
struct toolkit_susfs_as_data {
    struct filename *filename;
    u32 uid;
    u8 sym;
    bool was_su;
};
#else
struct toolkit_nosus_as_data {
    struct hlist_node node;
    struct task_struct *task;
    u32 uid;
    u8 sym;
    bool active;
};

struct toolkit_nosus_ksud_data {
    u32 uid;
    u8 sym;
    bool active;
};
#endif

static u32 ksuver_override;
static u32 ksuflags_override;

__ADDRESSABLE(ksu_sulog_emit_grant_root);
__ADDRESSABLE(ksu_sulog_capture_sucompat);
#ifdef CONFIG_KSU_SUSFS
__ADDRESSABLE(ksu_handle_faccessat);
__ADDRESSABLE(ksu_handle_stat);
#else
__ADDRESSABLE(ksu_handle_faccessat_sucompat);
__ADDRESSABLE(ksu_handle_stat_sucompat);
#endif

u32 ksu_toolkit_version_override(void)
{
    return READ_ONCE(ksuver_override);
}

u32 ksu_toolkit_flags_override(void)
{
    return READ_ONCE(ksuflags_override);
}

static struct toolkit_sulog_entry toolkit_sulog_entries[TOOLKIT_SULOG_ENTRY_MAX];
static DEFINE_SPINLOCK(toolkit_sulog_lock);
static u32 toolkit_sulog_next;
static bool toolkit_sulog_enabled;
static atomic_t toolkit_accepting = ATOMIC_INIT(0);

static bool reboot_registered;
static bool grant_registered;
static bool exec_registered;
static bool faccess_registered;
static bool stat_registered;
#ifndef CONFIG_KSU_SUSFS
static bool ksud_registered;
static HLIST_HEAD(toolkit_nosus_active);
static DEFINE_SPINLOCK(toolkit_nosus_active_lock);
static atomic_t toolkit_nosus_active_count = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(toolkit_nosus_active_wait);
#endif

#ifdef MODULE
static struct rw_semaphore *toolkit_uts_sem;

#ifdef CONFIG_ARM64
typedef unsigned long (*toolkit_lookup_name_fn)(const char *name);

static int __nocfi toolkit_resolve_uts_sem(void)
{
    struct kprobe lookup_probe = {
        .symbol_name = "kallsyms_lookup_name",
    };
    toolkit_lookup_name_fn lookup_name;
    int ret;

    ret = register_kprobe(&lookup_probe);
    if (ret)
        return ret;

    lookup_name = (toolkit_lookup_name_fn)lookup_probe.addr;
    unregister_kprobe(&lookup_probe);
    if (!lookup_name)
        return -ENOENT;

    toolkit_uts_sem = (struct rw_semaphore *)lookup_name("uts_sem");
    return toolkit_uts_sem ? 0 : -ENOENT;
}
#else
static int toolkit_resolve_uts_sem(void)
{
    return -EOPNOTSUPP;
}
#endif
#else
#define toolkit_uts_sem (&uts_sem)
#endif

static void toolkit_sulog_write(u8 sym, u32 uid)
{
    struct toolkit_sulog_entry entry;
    unsigned long flags;

    if (!atomic_read(&toolkit_accepting) || !READ_ONCE(toolkit_sulog_enabled))
        return;

    entry.s_time = (u32)ktime_get_boottime_seconds();
    entry.data = (uid & 0x00ffffffU) | ((u32)sym << 24);

    spin_lock_irqsave(&toolkit_sulog_lock, flags);
    if (toolkit_sulog_enabled) {
        toolkit_sulog_entries[toolkit_sulog_next] = entry;
        toolkit_sulog_next = (toolkit_sulog_next + 1U) % TOOLKIT_SULOG_ENTRY_MAX;
    }
    spin_unlock_irqrestore(&toolkit_sulog_lock, flags);
}

static bool toolkit_user_path_is_su(const char __user *path)
{
    char value[sizeof(TOOLKIT_SU_PATH) + 1];
    long copied;

    if (!path)
        return false;

    copied = strncpy_from_user_nofault(
        value, (const void __user *)untagged_addr((unsigned long)path),
        sizeof(value));
    if (copied < 0 || copied >= sizeof(value))
        return false;

    return !strcmp(value, TOOLKIT_SU_PATH);
}

static bool toolkit_kernel_path_is(const char *path, const char *expected)
{
    return !IS_ERR_OR_NULL(path) && expected && !strcmp(path, expected);
}

static int toolkit_ack(unsigned long user_arg)
{
    unsigned long reply = user_arg;

    if (!user_arg)
        return -EINVAL;

    return copy_to_user((void __user *)user_arg, &reply, sizeof(reply)) ? -EFAULT : 0;
}

static int toolkit_dump_sulog(unsigned long user_arg)
{
    struct toolkit_sulog_entry *snapshot;
    struct toolkit_sulog_receive receive;
    unsigned long flags;
    u32 next;
    u32 uptime;
    int ret = 0;

    if (!READ_ONCE(toolkit_sulog_enabled))
        return -EOPNOTSUPP;

    if (copy_from_user(&receive, (void __user *)user_arg, sizeof(receive)))
        return -EFAULT;
    if (!receive.index_ptr || !receive.buf_ptr || !receive.uptime_ptr)
        return -EINVAL;

    snapshot = kmalloc(sizeof(toolkit_sulog_entries), GFP_KERNEL);
    if (!snapshot)
        return -ENOMEM;

    spin_lock_irqsave(&toolkit_sulog_lock, flags);
    if (!toolkit_sulog_enabled) {
        spin_unlock_irqrestore(&toolkit_sulog_lock, flags);
        kfree(snapshot);
        return -EOPNOTSUPP;
    }
    memcpy(snapshot, toolkit_sulog_entries, sizeof(toolkit_sulog_entries));
    next = toolkit_sulog_next;
    uptime = (u32)ktime_get_boottime_seconds();
    spin_unlock_irqrestore(&toolkit_sulog_lock, flags);

    if (copy_to_user((void __user *)(uintptr_t)receive.buf_ptr, snapshot,
                     sizeof(toolkit_sulog_entries)) ||
        copy_to_user((void __user *)(uintptr_t)receive.index_ptr, &next, sizeof(next)) ||
        copy_to_user((void __user *)(uintptr_t)receive.uptime_ptr, &uptime, sizeof(uptime)))
        ret = -EFAULT;

    kfree(snapshot);
    return ret;
}

static int toolkit_spoof_uname(unsigned long user_arg)
{
    static char original_release[__NEW_UTS_LEN + 1];
    static char original_version[__NEW_UTS_LEN + 1];
    char release[__NEW_UTS_LEN + 1];
    char version[__NEW_UTS_LEN + 1];
    struct new_utsname *name;
    u64 strings_ptr;
    u64 release_ptr;
    long copied;
    size_t release_len;

    if (copy_from_user(&strings_ptr, (void __user *)user_arg, sizeof(strings_ptr)) ||
        !strings_ptr)
        return -EFAULT;
    if (copy_from_user(&release_ptr, (void __user *)(uintptr_t)strings_ptr,
                       sizeof(release_ptr)) ||
        !release_ptr)
        return -EFAULT;

    copied = strncpy_from_user(release, (char __user *)(uintptr_t)release_ptr,
                               sizeof(release));
    if (copied < 0)
        return -EFAULT;
    if (copied >= sizeof(release))
        return -ENAMETOOLONG;
    release[sizeof(release) - 1] = '\0';
    release_len = strnlen(release, sizeof(release));

    copied = strncpy_from_user(version,
                               (char __user *)(uintptr_t)(release_ptr + release_len + 1),
                               sizeof(version));
    if (copied < 0)
        return -EFAULT;
    if (copied >= sizeof(version))
        return -ENAMETOOLONG;
    version[sizeof(version) - 1] = '\0';

    down_write(toolkit_uts_sem);
    name = utsname();
    if (!original_release[0]) {
        strscpy(original_release, name->release, sizeof(original_release));
        strscpy(original_version, name->version, sizeof(original_version));
    }
    if (!strcmp(release, "default"))
        strscpy(release, original_release, sizeof(release));
    if (!strcmp(version, "default"))
        strscpy(version, original_version, sizeof(version));
    strscpy(name->release, release, sizeof(name->release));
    strscpy(name->version, version, sizeof(name->version));
    up_write(toolkit_uts_sem);

    return 0;
}

static int toolkit_handle_command(struct toolkit_work *tw)
{
    int ret;

    switch (tw->op) {
    case TOOLKIT_CHANGE_MANAGER_UID:
        ksu_set_manager_appid(tw->value);
        ret = tw->value == ksu_get_manager_appid() ? 0 : -EINVAL;
        break;
    case TOOLKIT_GET_SULOG_DUMP_V2:
        ret = toolkit_dump_sulog(tw->user_arg);
        break;
    case TOOLKIT_CHANGE_KSUVER:
        WRITE_ONCE(ksuver_override, tw->value);
        ret = 0;
        break;
    case TOOLKIT_CHANGE_SPOOF_UNAME:
        ret = toolkit_spoof_uname(tw->user_arg);
        break;
    case TOOLKIT_CHANGE_KSUFLAGS:
        WRITE_ONCE(ksuflags_override, tw->value);
        ret = 0;
        break;
    default:
        return -EINVAL;
    }

    if (!ret)
        ret = toolkit_ack(tw->user_arg);
    return ret;
}

static void toolkit_work_func(struct callback_head *work)
{
    struct toolkit_work *tw = container_of(work, struct toolkit_work, work);

    if (atomic_read(&toolkit_accepting) && current->mm &&
        !(current->flags & PF_EXITING) &&
        uid_eq(current_uid(), GLOBAL_ROOT_UID) && toolkit_handle_command(tw))
        pr_debug("toolkit command %u failed\n", tw->op);

    kfree(tw);
    module_put(THIS_MODULE);
}

static bool toolkit_queue_work(u32 op, u32 value, unsigned long user_arg)
{
    struct toolkit_work *tw;

    if (!atomic_read(&toolkit_accepting))
        return false;

    tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw)
        return false;

    if (!try_module_get(THIS_MODULE)) {
        kfree(tw);
        return false;
    }

    init_task_work(&tw->work, toolkit_work_func);
    tw->op = op;
    tw->value = value;
    tw->user_arg = user_arg;

    if (task_work_add(current, &tw->work, TWA_RESUME)) {
        module_put(THIS_MODULE);
        kfree(tw);
        return false;
    }
    return true;
}

static bool toolkit_is_command(u32 op)
{
    return op == TOOLKIT_CHANGE_MANAGER_UID || op == TOOLKIT_GET_SULOG_DUMP_V2 ||
           op == TOOLKIT_CHANGE_KSUVER || op == TOOLKIT_CHANGE_SPOOF_UNAME ||
           op == TOOLKIT_CHANGE_KSUFLAGS;
}

static int toolkit_reboot_pre(struct kprobe *probe, struct pt_regs *regs)
{
    struct pt_regs *sys_regs = PT_REAL_REGS(regs);
    u32 magic1 = (u32)PT_REGS_PARM1(sys_regs);
    u32 op = (u32)PT_REGS_PARM2(sys_regs);

    if (magic1 != KSU_INSTALL_MAGIC1 || !toolkit_is_command(op) ||
        !uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return 0;

    toolkit_queue_work(op, (u32)PT_REGS_PARM3(sys_regs),
                       (unsigned long)PT_REGS_SYSCALL_PARM4(sys_regs));
    return 0;
}

static int toolkit_grant_pre(struct kprobe *probe, struct pt_regs *regs)
{
    toolkit_sulog_write('i', (u32)PT_REGS_PARM2(regs));
    return 0;
}

static int toolkit_exec_pre(struct kprobe *probe, struct pt_regs *regs)
{
    const char __user *path = (const char __user *)PT_REGS_PARM1(regs);

    if (toolkit_user_path_is_su(path))
        toolkit_sulog_write('x', current_uid().val);
    return 0;
}

#ifdef CONFIG_KSU_SUSFS
static int toolkit_susfs_as_entry(struct kretprobe_instance *instance,
                                  struct pt_regs *regs, u8 sym)
{
    struct toolkit_susfs_as_data *data = (void *)instance->data;
    struct filename **filename_ptr = (struct filename **)PT_REGS_PARM2(regs);
    struct filename *filename = filename_ptr ? READ_ONCE(*filename_ptr) : NULL;

    data->filename = filename;
    data->uid = current_uid().val;
    data->sym = sym;
    data->was_su = !IS_ERR_OR_NULL(filename) &&
                   toolkit_kernel_path_is(filename->name, TOOLKIT_SU_PATH);
    return data->was_su ? 0 : 1;
}

static int toolkit_susfs_faccess_entry(struct kretprobe_instance *instance,
                                       struct pt_regs *regs)
{
    return toolkit_susfs_as_entry(instance, regs, 'a');
}

static int toolkit_susfs_stat_entry(struct kretprobe_instance *instance,
                                    struct pt_regs *regs)
{
    return toolkit_susfs_as_entry(instance, regs, 's');
}

static int toolkit_susfs_as_return(struct kretprobe_instance *instance,
                                   struct pt_regs *regs)
{
    struct toolkit_susfs_as_data *data = (void *)instance->data;

    if (data->was_su && !IS_ERR_OR_NULL(data->filename) &&
        toolkit_kernel_path_is(data->filename->name, TOOLKIT_SH_PATH))
        toolkit_sulog_write(data->sym, data->uid);
    return 0;
}
#else
static int toolkit_nosus_as_entry(struct kretprobe_instance *instance,
                                  struct pt_regs *regs, u8 sym)
{
    struct toolkit_nosus_as_data *data = (void *)instance->data;
    struct pt_regs *sys_regs = (struct pt_regs *)PT_REGS_PARM2(regs);
    const char __user *path;
    unsigned long flags;

    INIT_HLIST_NODE(&data->node);
    data->active = false;

    if (!sys_regs || !ksu_is_allow_uid_for_current(current_uid().val))
        return 1;

    path = (const char __user *)PT_REGS_PARM2(sys_regs);
    if (!toolkit_user_path_is_su(path))
        return 1;

    data->task = current;
    data->uid = current_uid().val;
    data->sym = sym;
    data->active = true;

    spin_lock_irqsave(&toolkit_nosus_active_lock, flags);
    if (!atomic_read(&toolkit_accepting)) {
        spin_unlock_irqrestore(&toolkit_nosus_active_lock, flags);
        data->active = false;
        return 1;
    }
    hlist_add_head(&data->node, &toolkit_nosus_active);
    atomic_inc(&toolkit_nosus_active_count);
    spin_unlock_irqrestore(&toolkit_nosus_active_lock, flags);
    return 0;
}

static int toolkit_nosus_faccess_entry(struct kretprobe_instance *instance,
                                       struct pt_regs *regs)
{
    return toolkit_nosus_as_entry(instance, regs, 'a');
}

static int toolkit_nosus_stat_entry(struct kretprobe_instance *instance,
                                    struct pt_regs *regs)
{
    return toolkit_nosus_as_entry(instance, regs, 's');
}

static int toolkit_nosus_as_return(struct kretprobe_instance *instance,
                                   struct pt_regs *regs)
{
    struct toolkit_nosus_as_data *data = (void *)instance->data;
    unsigned long flags;
    bool wake = false;

    if (!data->active)
        return 0;

    spin_lock_irqsave(&toolkit_nosus_active_lock, flags);
    if (!hlist_unhashed(&data->node)) {
        hlist_del_init(&data->node);
        wake = atomic_dec_and_test(&toolkit_nosus_active_count);
    }
    spin_unlock_irqrestore(&toolkit_nosus_active_lock, flags);
    data->active = false;

    if (wake)
        wake_up_all(&toolkit_nosus_active_wait);
    return 0;
}

static int toolkit_nosus_ksud_entry(struct kretprobe_instance *instance,
                                    struct pt_regs *regs)
{
    struct toolkit_nosus_ksud_data *data = (void *)instance->data;
    struct toolkit_nosus_as_data *active;
    unsigned long flags;

    data->active = false;
    spin_lock_irqsave(&toolkit_nosus_active_lock, flags);
    hlist_for_each_entry(active, &toolkit_nosus_active, node) {
        if (active->task == current) {
            data->uid = active->uid;
            data->sym = active->sym;
            data->active = true;
            break;
        }
    }
    spin_unlock_irqrestore(&toolkit_nosus_active_lock, flags);

    return data->active ? 0 : 1;
}

static int toolkit_nosus_ksud_return(struct kretprobe_instance *instance,
                                     struct pt_regs *regs)
{
    struct toolkit_nosus_ksud_data *data = (void *)instance->data;

    if (data->active && (u8)regs_return_value(regs))
        toolkit_sulog_write(data->sym, data->uid);
    return 0;
}
#endif

static struct kprobe reboot_probe = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = toolkit_reboot_pre,
};

static struct kprobe grant_probe = {
    .symbol_name = "ksu_sulog_emit_grant_root",
    .pre_handler = toolkit_grant_pre,
};

static struct kprobe exec_probe = {
    .symbol_name = "ksu_sulog_capture_sucompat",
    .pre_handler = toolkit_exec_pre,
};

#ifdef CONFIG_KSU_SUSFS
static struct kretprobe faccess_probe = {
    .kp.symbol_name = "ksu_handle_faccessat",
    .entry_handler = toolkit_susfs_faccess_entry,
    .handler = toolkit_susfs_as_return,
    .data_size = sizeof(struct toolkit_susfs_as_data),
    .maxactive = 64,
};

static struct kretprobe stat_probe = {
    .kp.symbol_name = "ksu_handle_stat",
    .entry_handler = toolkit_susfs_stat_entry,
    .handler = toolkit_susfs_as_return,
    .data_size = sizeof(struct toolkit_susfs_as_data),
    .maxactive = 64,
};
#else
static struct kretprobe faccess_probe = {
    .kp.symbol_name = "ksu_handle_faccessat_sucompat",
    .entry_handler = toolkit_nosus_faccess_entry,
    .handler = toolkit_nosus_as_return,
    .data_size = sizeof(struct toolkit_nosus_as_data),
    .maxactive = 64,
};

static struct kretprobe stat_probe = {
    .kp.symbol_name = "ksu_handle_stat_sucompat",
    .entry_handler = toolkit_nosus_stat_entry,
    .handler = toolkit_nosus_as_return,
    .data_size = sizeof(struct toolkit_nosus_as_data),
    .maxactive = 64,
};

static struct kretprobe ksud_probe = {
    .kp.symbol_name = "ksu_toolkit_is_ksud_exists",
    .entry_handler = toolkit_nosus_ksud_entry,
    .handler = toolkit_nosus_ksud_return,
    .data_size = sizeof(struct toolkit_nosus_ksud_data),
    .maxactive = 128,
};
#endif

static void toolkit_unregister_sulog_probes(void)
{
#ifdef CONFIG_KSU_SUSFS
    if (stat_registered)
        unregister_kretprobe(&stat_probe);
    if (faccess_registered)
        unregister_kretprobe(&faccess_probe);
#else
    if (stat_registered)
        unregister_kretprobe(&stat_probe);
    if (faccess_registered)
        unregister_kretprobe(&faccess_probe);
    if (ksud_registered)
        unregister_kretprobe(&ksud_probe);
#endif
    if (exec_registered)
        unregister_kprobe(&exec_probe);
    if (grant_registered)
        unregister_kprobe(&grant_probe);

    stat_registered = false;
    faccess_registered = false;
#ifndef CONFIG_KSU_SUSFS
    ksud_registered = false;
#endif
    exec_registered = false;
    grant_registered = false;
}

static int toolkit_register_sulog_probes(void)
{
    int ret;

    ret = register_kprobe(&grant_probe);
    if (ret) {
        pr_err("toolkit SULOG disabled: required probe %s failed: %d\n",
               grant_probe.symbol_name, ret);
        return ret;
    }
    grant_registered = true;

    ret = register_kprobe(&exec_probe);
    if (ret) {
        pr_err("toolkit SULOG disabled: required probe %s failed: %d\n",
               exec_probe.symbol_name, ret);
        goto error;
    }
    exec_registered = true;

#ifndef CONFIG_KSU_SUSFS
    ret = register_kretprobe(&ksud_probe);
    if (ret) {
        pr_err("toolkit SULOG disabled: required probe %s failed: %d\n",
               ksud_probe.kp.symbol_name, ret);
        goto error;
    }
    ksud_registered = true;
#endif

    ret = register_kretprobe(&faccess_probe);
    if (ret) {
        pr_err("toolkit SULOG disabled: required probe %s failed: %d\n",
               faccess_probe.kp.symbol_name, ret);
        goto error;
    }
    faccess_registered = true;

    ret = register_kretprobe(&stat_probe);
    if (ret) {
        pr_err("toolkit SULOG disabled: required probe %s failed: %d\n",
               stat_probe.kp.symbol_name, ret);
        goto error;
    }
    stat_registered = true;
    return 0;

error:
    toolkit_unregister_sulog_probes();
    return ret;
}

noinline void ksu_toolkit_init(void)
{
    unsigned long flags;
    int ret;

    BUILD_BUG_ON(sizeof(struct toolkit_sulog_entry) != 8);

    atomic_set(&toolkit_accepting, 0);
    WRITE_ONCE(ksuver_override, 0);
    WRITE_ONCE(ksuflags_override, 0);

#ifdef MODULE
    ret = toolkit_resolve_uts_sem();
    if (ret) {
        pr_err("toolkit cannot resolve uts_sem: %d\n", ret);
        return;
    }
#endif

    spin_lock_irqsave(&toolkit_sulog_lock, flags);
    memset(toolkit_sulog_entries, 0, sizeof(toolkit_sulog_entries));
    toolkit_sulog_next = 0;
    toolkit_sulog_enabled = false;
    spin_unlock_irqrestore(&toolkit_sulog_lock, flags);

#ifndef CONFIG_KSU_SUSFS
    INIT_HLIST_HEAD(&toolkit_nosus_active);
    atomic_set(&toolkit_nosus_active_count, 0);
#endif

    ret = register_kprobe(&reboot_probe);
    if (ret) {
        pr_err("toolkit reboot probe %s failed: %d\n", reboot_probe.symbol_name,
               ret);
        return;
    }
    reboot_registered = true;

    ret = toolkit_register_sulog_probes();
    if (ret) {
        pr_err("toolkit SULOG probes failed: %d\n", ret);
    } else {
        spin_lock_irqsave(&toolkit_sulog_lock, flags);
        toolkit_sulog_enabled = true;
        spin_unlock_irqrestore(&toolkit_sulog_lock, flags);
        pr_info("toolkit SULOG probes registered\n");
    }

    atomic_set(&toolkit_accepting, 1);
    pr_info("toolkit reboot probe registered\n");
}

noinline void ksu_toolkit_exit(void)
{
    unsigned long flags;

    atomic_set(&toolkit_accepting, 0);
    if (reboot_registered) {
        unregister_kprobe(&reboot_probe);
        reboot_registered = false;
    }

#ifndef CONFIG_KSU_SUSFS
    spin_lock_irqsave(&toolkit_nosus_active_lock, flags);
    spin_unlock_irqrestore(&toolkit_nosus_active_lock, flags);
    wait_event(toolkit_nosus_active_wait,
               atomic_read(&toolkit_nosus_active_count) == 0);
#endif

    toolkit_unregister_sulog_probes();

#ifdef CONFIG_KSU_SUSFS
    if (faccess_probe.nmissed || stat_probe.nmissed)
        pr_warn("toolkit SULOG probes missed events: faccessat=%d stat=%d\n",
                faccess_probe.nmissed, stat_probe.nmissed);
#else
    if (faccess_probe.nmissed || stat_probe.nmissed || ksud_probe.nmissed)
        pr_warn("toolkit SULOG probes missed events: faccessat=%d stat=%d ksud=%d\n",
                faccess_probe.nmissed, stat_probe.nmissed, ksud_probe.nmissed);
#endif

    spin_lock_irqsave(&toolkit_sulog_lock, flags);
    toolkit_sulog_enabled = false;
    memset(toolkit_sulog_entries, 0, sizeof(toolkit_sulog_entries));
    toolkit_sulog_next = 0;
    spin_unlock_irqrestore(&toolkit_sulog_lock, flags);

#ifdef MODULE
    toolkit_uts_sem = NULL;
#endif
}
