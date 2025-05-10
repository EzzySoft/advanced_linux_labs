#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "int_stack.h"

static const char *dev = "/dev/int_stack";

static void usb_missing(void)
{
	fprintf(stderr, "ERROR: USB key not inserted\n");
	exit(1);
}

static void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static int open_safe(int flags)
{
	int fd = open(dev, flags);
	if (fd < 0) {
		if (errno == ENOENT)
			usb_missing();
		die("open");
	}
	return fd;
}

static void cmd_set_size(int size)
{
	int fd = open_safe(O_RDWR);
	if (ioctl(fd, INT_STACK_SET_SIZE, &size) < 0)
		die("ioctl");
	close(fd);
}

static void cmd_push(int val)
{
	int fd = open_safe(O_RDWR);
	if (write(fd, &val, sizeof(int)) < 0) {
		if (errno == ERANGE) {
			fprintf(stderr, "ERROR: stack is full\n");
			exit(-ERANGE);
		}
		die("write");
	}
	close(fd);
}

static void cmd_pop(void)
{
	int fd = open_safe(O_RDONLY);
	int val;
	ssize_t n = read(fd, &val, sizeof(int));
	if (n == 0)
		printf("NULL\n");
	else if (n > 0)
		printf("%d\n", val);
	else
		die("read");
	close(fd);
}

static void usage(const char *prg)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s set-size <N>\n"
		"  %s push <val>\n"
		"  %s pop\n"
		"  %s unwind\n", prg, prg, prg, prg);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	if (argc < 2) usage(argv[0]);

	if (!strcmp(argv[1], "set-size") && argc == 3) {
		int n = atoi(argv[2]);
		if (n <= 0) { fprintf(stderr,"ERROR: size should be > 0\n"); return 1; }
		cmd_set_size(n);
	} else if (!strcmp(argv[1], "push") && argc == 3) {
		cmd_push(atoi(argv[2]));
	} else if (!strcmp(argv[1], "pop") && argc == 2) {
		cmd_pop();
	} else if (!strcmp(argv[1], "unwind") && argc == 2) {
		while (1) {
			int fd = open_safe(O_RDONLY);
			int v; ssize_t n = read(fd, &v, sizeof(int));
			close(fd);
			if (n == 0) break;
			printf("%d\n", v);
		}
	} else {
		usage(argv[0]);
	}
	return 0;
}
