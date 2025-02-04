# TempRoot-Huawei

Temporary root for Huawei hardened kernel via CVE-2019-2215

This code is written for P20 Pro (CLT-AL00), and kernel offset is taken from firmware with build fingerprint: 'HUAWEI/CLT-AL00/HWCLT:8.1.0/HUAWEICLT-AL00/176(C00):user/release-keys'

## Background

Like Samsung's KNOX, Huawei added many mechanisms to prevent exploit from hackers and improve 'security'.

- enabled DEBUG_SPINLOCK which adds additional check on spainlock
- The kernel stack pointer in task struct has been obfuscated using a random offset `kti_offset` (like KASLR)
- get_fs() returns either `KERNEL_DS` or `USER_DS`, changing `current_thread_info()->addr_limit` will not work
- uid/gid/capabilities in cred struct has been protected by hypervisor (EL2), process will be immediately killed during access check if they become root without using `commit_creds()`
- CONFIG_SECURITY_SELINUX_DEVELOP is not set, SeLinux cannot put into global permissive state
- many critical variables are readonly after init or protected by hypervisor, including `ss_initialized` `policydb->permissive_map` `security_hook_heads`

These mechanisms make it hard to exploit old Huawei devices even if they are vulnerable to CVE-2019-2215.

## Usage

First, compile and run `patch_system.c`, this will nullify selinux by messing selinux mapping and calling `avc_ss_reset()`.

Next, compile and run `poc.c` to get root shell.

(Optional) Compile su daemon and start it by poc to allow other apps using root (see scripts/termux-boot).

## Notes

The su daemon is taken and modified from https://github.com/corellium/sud