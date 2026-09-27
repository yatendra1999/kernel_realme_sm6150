#ifndef __KSU_H_KERNEL_UMOUNT
#define __KSU_H_KERNEL_UMOUNT

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rwsem.h>

void ksu_kernel_umount_init(void);
void ksu_kernel_umount_exit(void);

// Handler function to be called from setresuid hook
int ksu_handle_umount(uid_t old_uid, uid_t new_uid);

#ifdef CONFIG_KSU_SUSFS
// SUSFS glue: module flag-file evaluation at POST_FS_DATA + zygote-spawned
// system-process umount toggle (see feature/kernel_umount.c)
void susfs_on_post_fs_data(void);
bool susfs_umount_for_zygote_system_process_enabled(void);
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
// Exposed for SUSFS (simonpunk v1.5.5 10_enable ABI)
void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid);
void susfs_try_umount_all(uid_t uid);
#endif

// for the umount list
struct mount_entry {
    char *umountable;
    unsigned int flags;
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;

#endif
