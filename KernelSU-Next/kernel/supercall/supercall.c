#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem
#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "compat/kernel_compat.h"

#include "sulog/event.h"

uint32_t ksuver_override = 0;

#define KSU_DRIVER_PERMISSION_SU_SESSION (1UL << 0)

struct ksu_driver_context {
    unsigned long permissions;
};

struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    kfree(filp->private_data);
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(filp, cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

static int ksu_install_fd_with_permissions(unsigned int fd_flags, unsigned long permissions)
{
    struct ksu_driver_context *context;
    struct file *filp;
    const char *name;
    int fd;

    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context)
        return -ENOMEM;

    context->permissions = permissions;
    name = permissions & KSU_DRIVER_PERMISSION_SU_SESSION ? "[ksu_driver_su]" : "[ksu_driver]";

    fd = get_unused_fd_flags(fd_flags);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        kfree(context);
        return fd;
    }

    filp = anon_inode_getfile(name, &anon_ksu_fops, context, O_RDWR);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        kfree(context);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

int ksu_install_fd(void)
{
    return ksu_install_fd_with_permissions(O_CLOEXEC, 0);
}

int ksu_install_su_fd(void)
{
    // This descriptor must be installed after the exec into ksud.
    return ksu_install_fd_with_permissions(O_CLOEXEC, KSU_DRIVER_PERMISSION_SU_SESSION);
}

bool ksu_is_su_session_fd(const struct file *filp)
{
    const struct ksu_driver_context *context = filp->private_data;

    return context && (context->permissions & KSU_DRIVER_PERMISSION_SU_SESSION);
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
        ksu_close_fd(fd);
    }

    kfree(tw);
}

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

#ifdef CONFIG_KSU_DEBUG
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1,
		magic2);
#endif

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		struct ksu_install_fd_tw *tw;

		tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
		if (!tw)
			return 0;

		tw->outp = (int __user *)*arg;
		tw->cb.func = ksu_install_fd_tw_func;

		if (task_work_add(current, &tw->cb, TWA_RESUME)) {
			kfree(tw);
			pr_warn("install fd add task_work failed\n");
		}
		return 0;
	}

	// extensions 
	u64 reply = (u64)*arg;

	if (magic2 == CHANGE_MANAGER_UID) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}
	
	if (magic2 == GET_SULOG_DUMP_V2) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		int ret = ksu_sulog_handle_compat_dump((void __user *)*arg);
		if (ret)
			return 0;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {
		// only root is allowed for this command 
		if (current_uid().val != 0)
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// basically void * void __user * void __user *arg
		void ***ppptr = (uintptr_t)arg;

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		pr_info("sys_reboot: ppptr: 0x%lx \n", ppptr);

		// arg here is ***, dereference to pull out **
		if (copy_from_user(&u_pptr, (void __user *)*ppptr, sizeof(u_pptr)))
			return 0;

		pr_info("sys_reboot: u_pptr: 0x%lx \n", u_pptr);

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		pr_info("sys_reboot: u_ptr: 0x%lx \n", u_ptr);

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
			strscpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strscpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#else
			strlcpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strlcpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#endif
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		strscpy(u->release, release_buf, sizeof(u->release));
		strscpy(u->version, version_buf, sizeof(u->version));
#else
		strlcpy(u->release, release_buf, sizeof(u->release));
		strlcpy(u->version, version_buf, sizeof(u->version));
#endif
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
			return 0;
	}

	return 0;
}

#ifdef KSU_KPROBES_HOOK
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;

	return ksu_handle_sys_reboot(magic1, magic2, cmd, (void __user **)&arg4);
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};
#endif

void __init ksu_supercalls_init(void)
{
	int i;

	ksu_supercall_dump_commands();

#ifdef KSU_KPROBES_HOOK
	int rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
	} else {
		pr_info("reboot kprobe registered successfully\n");
	}
#endif
}

void __exit ksu_supercalls_exit(void){
	struct mount_entry *entry, *tmp;

#ifdef KSU_KPROBES_HOOK
	unregister_kprobe(&reboot_kp);
#endif

	ksu_supercall_cleanup_state();
}

/*
 * SUSFS command channel (simonpunk/susfs4ksu v1.5.5 10_enable content,
 * re-homed for KernelSU-Next v3.4.0-legacy which has no prctl supercall:
 * this is the manual hook from kernel/sys.c SYSCALL_DEFINE5(prctl)).
 * Wire ABI preserved byte-for-byte for the ksu_susfs tool of the same
 * repo: prctl(0xDEADBEEF, CMD_SUSFS_*, &info, NULL, &error).
 */
#define KSU_SUSFS_PRCTL_OPTION 0xDEADBEEF

#ifdef CONFIG_KSU_SUSFS
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
// defined in fs/namespace.c by 50_add_susfs_in_kernel-4.14.patch
extern void susfs_run_try_umount_for_current_mnt_ns(void);
#endif

int ksu_handle_susfs_prctl(int option, unsigned long arg2,
			   unsigned long arg3, unsigned long arg4,
			   unsigned long arg5)
{
	if (option != KSU_SUSFS_PRCTL_OPTION) {
		return 0; // not ours: pass through to the kernel prctl
	}
	// consume the magic option entirely (upstream KSU 0.7-era behavior)
	if (current_uid().val != 0) {
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	if (arg2 == CMD_SUSFS_ADD_SUS_PATH) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     sizeof(struct st_susfs_sus_path))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_add_sus_path((struct st_susfs_sus_path __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (arg2 == CMD_SUSFS_ADD_SUS_MOUNT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     sizeof(struct st_susfs_sus_mount))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_add_sus_mount((struct st_susfs_sus_mount __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
	if (arg2 == CMD_SUSFS_UPDATE_SUS_KSTAT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
	if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	if (arg2 == CMD_SUSFS_ADD_TRY_UMOUNT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     sizeof(struct st_susfs_try_umount))) {
			pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_add_try_umount((struct st_susfs_try_umount __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
	if (arg2 == CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS) {
		int error = 0;
		susfs_run_try_umount_for_current_mnt_ns();
		pr_info("susfs: CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS -> ret: %d\n", error);
		return 1;
	}
#endif //#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	if (arg2 == CMD_SUSFS_SET_UNAME) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     sizeof(struct st_susfs_uname))) {
			pr_err("susfs: CMD_SUSFS_SET_UNAME -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SET_UNAME -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_set_uname((struct st_susfs_uname __user *)arg3);
		pr_info("susfs: CMD_SUSFS_SET_UNAME -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	if (arg2 == CMD_SUSFS_ENABLE_LOG) {
		int error = 0;
		if (arg3 != 0 && arg3 != 1) {
			pr_err("susfs: CMD_SUSFS_ENABLE_LOG -> arg3 can only be 0 or 1\n");
			return 1;
		}
		susfs_set_log(arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
#endif //#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	if (arg2 == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE)) {
			pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_set_cmdline_or_bootconfig((char __user *)arg3);
		pr_info("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	if (arg2 == CMD_SUSFS_ADD_OPEN_REDIRECT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3,
				     sizeof(struct st_susfs_open_redirect))) {
			pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> arg5 is not accessible\n");
			return 1;
		}
		error = susfs_add_open_redirect((struct st_susfs_open_redirect __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
#endif //#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	if (arg2 == CMD_SUSFS_SHOW_VERSION) {
		int error = 0;
		int len_of_susfs_version = strlen(SUSFS_VERSION);
		char *susfs_version = SUSFS_VERSION;
		if (!ksu_access_ok((void __user *)arg3, len_of_susfs_version + 1)) {
			pr_err("susfs: CMD_SUSFS_SHOW_VERSION -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_VERSION -> arg5 is not accessible\n");
			return 1;
		}
		error = copy_to_user((void __user *)arg3, (void *)susfs_version,
				       len_of_susfs_version + 1);
		pr_info("susfs: CMD_SUSFS_SHOW_VERSION -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
	if (arg2 == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
		int error = 0;
		u64 enabled_features = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(u64))) {
			pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg5 is not accessible\n");
			return 1;
		}
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		enabled_features |= (1 << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		enabled_features |= (1 << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
		enabled_features |= (1 << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
		enabled_features |= (1 << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		enabled_features |= (1 << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
		enabled_features |= (1 << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		enabled_features |= (1 << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
		enabled_features |= (1 << 7);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		enabled_features |= (1 << 8);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		enabled_features |= (1 << 9);
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
		enabled_features |= (1 << 10);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		enabled_features |= (1 << 11);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		enabled_features |= (1 << 12);
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
		enabled_features |= (1 << 14);
#endif
		error = copy_to_user((void __user *)arg3, (void *)&enabled_features,
				     sizeof(enabled_features));
		pr_info("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
	if (arg2 == CMD_SUSFS_SHOW_VARIANT) {
		int error = 0;
		int len_of_variant = strlen(SUSFS_VARIANT);
		char *susfs_variant = SUSFS_VARIANT;
		if (!ksu_access_ok((void __user *)arg3, len_of_variant + 1)) {
			pr_err("susfs: CMD_SUSFS_SHOW_VARIANT -> arg3 is not accessible\n");
			return 1;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_VARIANT -> arg5 is not accessible\n");
			return 1;
		}
		error = copy_to_user((void __user *)arg3, (void *)susfs_variant,
				     len_of_variant + 1);
		pr_info("susfs: CMD_SUSFS_SHOW_VARIANT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 1;
	}
	// CMD_SUSFS_SUS_SU / _IS_SUS_SU_READY / _SHOW_SUS_SU_WORKING_MODE are
	// intentionally not ported: SUS_SU is unsupported on non-GKI since
	// SUSFS v1.5.5 (kprobe-hook-only) and the plan forbids enabling it.
	return 1; // magic option consumed
}
#else /* !CONFIG_KSU_SUSFS */
int ksu_handle_susfs_prctl(int option, unsigned long arg2,
			   unsigned long arg3, unsigned long arg4,
			   unsigned long arg5)
{
	return 0;
}
#endif /* CONFIG_KSU_SUSFS */
