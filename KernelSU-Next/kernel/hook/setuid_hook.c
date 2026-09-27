#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#include "selinux/selinux.h"
#endif

#include "policy/allowlist.h"
#include "hook/setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "infra/seccomp_cache.h"
#include "supercall/supercall.h"
#include "hook/hook_manager.h"
#include "feature/kernel_umount.h"
#include "compat/kernel_compat.h"

extern void disable_seccomp(struct task_struct *tsk);

#ifdef CONFIG_KSU_SUSFS
// defined in selinux/selinux.c (SUSFS glue)
extern u32 susfs_zygote_sid;
#endif // #ifdef CONFIG_KSU_SUSFS

int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids

#ifdef CONFIG_KSU_SUSFS
    // SUSFS (wodanesdag susfs@08ea4ab9): we only interest in process spawned
    // by zygote
    if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid)) {
        return 0;
    }

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    // Isolated service spawned by zygote: force to do umount (native KSUN
    // semantics: isolated processes bypass the should_umount table)
    if (is_isolated_process(new_uid)) {
        goto do_umount;
    }
    // System process spawned by zygote (uid 1000..9999, except the webview
    // zygote which the native gate handles): umount only when the
    // /data/adb/susfs_umount_for_zygote_system_process flag file existed at
    // post-fs-data (simonpunk v1.5.5 10_enable semantics)
    if (new_uid >= 1000 && new_uid < 10000 &&
        new_uid != WEBVIEW_ZYGOTE_UID &&
        susfs_umount_for_zygote_system_process_enabled()) {
        goto do_umount;
    }
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#endif // #ifdef CONFIG_KSU_SUSFS

    pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

    if (unlikely(is_uid_manager(new_uid))) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp(current);
#endif

#ifdef KSU_KPROBES_HOOK
        ksu_set_task_tracepoint_flag(current);
#endif

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp(current);
#endif

#ifdef KSU_KPROBES_HOOK
		ksu_set_task_tracepoint_flag(current);
#endif
	} else {
#ifdef KSU_KPROBES_HOOK
		ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
#ifdef CONFIG_KSU_SUSFS
		// v1.5.5 10_enable: mark non-root-granted zygote-spawned user
		// app processes so SUS_PATH/SUS_KSTAT kernel gates activate
		if (is_appuid(new_uid) || is_isolated_process(new_uid)) {
			task_lock(current);
			current->susfs_task_state |=
				TASK_STRUCT_NON_ROOT_USER_APP_PROC;
			task_unlock(current);
		}
#endif // #ifdef CONFIG_KSU_SUSFS
    }

#ifdef CONFIG_KSU_SUSFS
    // Route exactly where native ksu_handle_umount() would have acted
    // (same entry gate as feature/kernel_umount.c:148-152), so enabling
    // SUSFS cannot weaken KSUN's per-app umount semantics.
    if (likely((is_appuid(new_uid) || new_uid == WEBVIEW_ZYGOTE_UID ||
                is_isolated_process(new_uid)) &&
               (ksu_uid_should_umount(new_uid) ||
                is_isolated_process(new_uid)))) {
        goto do_umount;
    }
#ifndef CONFIG_KSU_SUSFS_SUS_MOUNT
    // Without SUS_MOUNT there is no early isolated routing; keep native path
    ksu_handle_umount(old_uid, new_uid);
#endif // #ifndef CONFIG_KSU_SUSFS_SUS_MOUNT
#else
    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);
#endif // #ifdef CONFIG_KSU_SUSFS

    return 0;

#ifdef CONFIG_KSU_SUSFS
do_umount:
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	susfs_try_umount_all(new_uid);
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	// KSUN-native mount_list (ksud-managed) umount is preserved;
	// ksu_handle_umount() re-validates all preconditions internally.
	ksu_handle_umount(old_uid, new_uid);
	return 0;
#endif // #ifdef CONFIG_KSU_SUSFS
}

void __init ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
	pr_info("ksu_core_exit\n");
	ksu_kernel_umount_exit();
}