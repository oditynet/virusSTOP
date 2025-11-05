#define pr_fmt(fmt) "bitx: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/namei.h>
#include <linux/delay.h>

MODULE_DESCRIPTION("BitX exec hook for user.bitX checking");
MODULE_AUTHOR("oditynet");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long retval;
	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name) { return kallsyms_lookup_name(name); }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#define ftrace_regs pt_regs
static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs) { return fregs; }
#endif

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;
	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);
	if (!hook->address) {
		pr_err("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}
	*((unsigned long*) hook->original) = hook->address;
	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
}

static int fh_install_hook(struct ftrace_hook *hook)
{
	int err;
	err = fh_resolve_hook_address(hook);
	if (err) return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_err("ftrace_set_filter_ip failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_err("register_ftrace_function failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}
	return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
	unregister_ftrace_function(&hook->ops);
	ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

static int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;
	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err) goto error;
	}
	return 0;
error:
	while (i != 0) fh_remove_hook(&hooks[--i]);
	return err;
}

static void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;
	for (i = 0; i < count; i++) fh_remove_hook(&hooks[i]);
}

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#pragma GCC optimize("-fno-optimize-sibling-calls")

static int check_bitx(const char *filename)
{
	struct path path;
	char bitx_value[2] = {0};
	int error, ret = -1;

	error = kern_path(filename, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_info("No path for: %s, err: %d\n", filename, error);
		return -1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
	error = vfs_getxattr(&nop_mnt_idmap, path.dentry, "user.bitX", bitx_value, sizeof(bitx_value));
#else
	error = vfs_getxattr(path.dentry, "user.bitX", bitx_value, sizeof(bitx_value));
#endif

	if (error > 0) {
		pr_info("File %s has user.bitX = %c\n", filename, bitx_value[0]);
		if (bitx_value[0] == '0') ret = 0;
		else if (bitx_value[0] == '1') ret = 1;
	} else if (error == -ENODATA) {
		pr_info("File %s has no user.bitX\n", filename);
		ret = -1;
	} else {
		pr_info("Error reading bitX for %s: %d\n", filename, error);
	}

	path_put(&path);
	return ret;
}

static int get_script_args(const char __user *__user *argv, char **kargv, int max)
{
	int i = 0;
	const char __user *uptr;
	char *karg;

	while (i < max) {
		if (get_user(uptr, &argv[i])) break;
		if (!uptr) break;

		karg = kmalloc(256, GFP_KERNEL);
		if (!karg) break;

		if (strncpy_from_user(karg, uptr, 256) < 0) {
			kfree(karg);
			break;
		}
		kargv[i] = karg;
		i++;
	}
	return i;
}

static void free_args(char **kargv, int count)
{
	int i;
	for (i = 0; i < count && kargv[i]; i++) kfree(kargv[i]);
}

static int is_interpreter(const char *name)
{
	return strstr(name, "python") || strstr(name, "bash") || strstr(name, "sh") || strstr(name, "perl");
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_execve)(struct pt_regs *regs);

static asmlinkage long bitx_execve(struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->di;
	const char __user *__user *argv = (const char __user *__user *)regs->si;
	char *kname = NULL;
	char *kargs[32] = {0};
	int argc, i, bitx, block = 0;

	kname = kmalloc(256, GFP_KERNEL);
	if (!kname) goto out;

	if (strncpy_from_user(kname, filename, 256) < 0) goto out;

	if (!is_interpreter(kname)) goto out;

	pr_info("Interpreter detected: %s\n", kname);

	argc = get_script_args(argv, kargs, 32);

	// Проверяем ВСЕ аргументы как потенциальные файлы скриптов
	for (i = 0; i < argc && kargs[i]; i++) {
		// Любой аргумент может быть файлом скрипта (не проверяем расширения)
		if (kargs[i][0] == '/') {  // Только абсолютные пути
			bitx = check_bitx(kargs[i]);
			pr_info("Checking file: %s, bitX=%d\n", kargs[i], bitx);
			if (bitx == 0 || bitx == -1) {
				pr_warn("BLOCKED: %s bitX=%d\n", kargs[i], bitx);
				block = 1;
				break;
			}
		}
	}

	if (block) {
		kfree(kname);
		free_args(kargs, argc);
		return -EACCES;
	}

out:
	if (kname) kfree(kname);
	free_args(kargs, 32);
	return real_execve(regs);
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original) \
	{ .name = SYSCALL_NAME(_name), .function = (_function), .original = (_original) }

static struct ftrace_hook hooks[] = {
	HOOK("sys_execve", bitx_execve, &real_execve),
};

static void safe_remove_hooks(void)
{
    int i;
    
    pr_info("Safely removing hooks...\n");
    
    // Отключаем все хуки
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        if (hooks[i].address) {
            unregister_ftrace_function(&hooks[i].ops);
            ftrace_set_filter_ip(&hooks[i].ops, hooks[i].address, 1, 0);
        }
    }
    
    // Ждем завершения всех системных вызовов
    synchronize_rcu();
    msleep(200);
    
    pr_info("Hooks safely removed\n");
}

static int __init bitx_init(void)
{
    int err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) return err;
    pr_info("bitx module loaded\n");
    return 0;
}

static void __exit bitx_exit(void)
{
    pr_info("Beginning bitx module unload\n");
    safe_remove_hooks();
    pr_info("bitx module unloaded successfully\n");
}

module_init(bitx_init);
module_exit(bitx_exit);
