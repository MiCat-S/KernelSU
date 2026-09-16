#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT
#include <asm/ptrace.h>
#include <linux/types.h>

extern bool ksu_su_compat_enabled;

void ksu_sucompat_init(void);

#ifdef CONFIG_KSU_SUSFS
struct filename;
noinline int ksu_handle_faccessat(int *dfd, struct filename **filename,
                                  int *mode, int *__unused_flags);
noinline int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);
#else
noinline long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs);
noinline long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs);
#ifdef KSU_TOOLKIT_SUCOMPAT_TU
#define is_ksud_exists ksu_toolkit_is_ksud_exists
static noinline __used bool ksu_toolkit_is_ksud_exists(void)
    __asm__("ksu_toolkit_is_ksud_exists");
#endif
#endif

void ksu_sucompat_exit(void);

// Handler functions exported for hook_manager
long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs);
long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs);
long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs);
long ksu_handle_execveat_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs);

#endif
