/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2015 Benjamin Fleischer
 */

#include "fuse_lowlevel.h"
#include "fuse_kernel.h"
#include "fuse_i.h"

#ifdef __APPLE__
#include "fuse_darwin_private.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>

dispatch_queue_t recvQ;
dispatch_queue_t sendQ;

static int _fuse_kern_chan_receive(struct fuse_chan **chp, char *buf,
				  size_t size)
{
	struct fuse_chan *ch = *chp;
	int err;
	ssize_t res;
	struct fuse_session *se = fuse_chan_session(ch);
	int state = 0;
	assert(se != NULL);
	int total = 0;

	while (state < 2) {
		// read header
		int len = 0;
		if (state == 0) {
			len = sizeof(struct fuse_in_header);
		} else {
			struct fuse_in_header *hdr = (struct fuse_in_header *)buf;
			len = hdr->len - sizeof(struct fuse_in_header);
		}
		if (!len)
			break;
again:
		res = recv(fuse_chan_fd(ch), buf + total, len, 0);
		if (res > 0 && res < len) {
			total += res;
			len -= res;
			goto again;
		}
		if (res == len) {
			state++;
			total += res;
		}
			
		err = errno;

		if (fuse_session_exited(se)) {
			return 0;
		}
		if (res == -1) {
			/* ENOENT means the operation was interrupted, it's safe
			to restart */
			if (err == ENOENT)
				continue;

			if (err == ENODEV) {
				fuse_session_exit(se);
				return 0;
			}
			/* Errors occurring during normal operation: EINTR (read
			interrupted), EAGAIN (nonblocking I/O), ENODEV (filesystem
			umounted) */
			if (err != EINTR && err != EAGAIN)
				perror("fuse: reading error");
			return -err;
		}
		if (res < len) {
			fprintf(stderr, "short read on fuse device\n");
			return -EIO;
		}
	}

	return total;
}

static int fuse_kern_chan_receive(struct fuse_chan **chp, char *buf, size_t size)
{
	// since we use a regular socket, need to make sure all requests are serialized
	__block int res;
	dispatch_sync(recvQ, ^{
		res = _fuse_kern_chan_receive(chp, buf,size);
	});
	return res;
}

static int _fuse_kern_chan_send(struct fuse_chan *ch, const struct iovec iov[],
			       size_t count)
{
	if (iov) {
		ssize_t res = writev(fuse_chan_fd(ch), iov, count);
		int err = errno;

		if (res == -1) {
			struct fuse_session *se = fuse_chan_session(ch);

			assert(se != NULL);

			/* ENOENT means the operation was interrupted */
			if (!fuse_session_exited(se) && err != ENOENT)
				perror("fuse: writing error");
			return -err;
		}
	}
	return 0;
}

static int fuse_kern_chan_send(struct fuse_chan *ch, const struct iovec iov[],
			       size_t count)
{
	// since we use a regular socket, need to make sure all requests are serialized
	__block int res;

	dispatch_sync(sendQ, ^{
		res = _fuse_kern_chan_send(ch, iov, count);
	});
	return res;
}

static void fuse_kern_chan_destroy(struct fuse_chan *ch)
{
	int fd = fuse_chan_fd(ch);

	if (fd != -1) {
#ifdef __APPLE__
		(void)ioctl(fd, FUSEDEVIOCSETDAEMONDEAD, &fd);
#endif
		close(fd);
    }
}

#ifdef __APPLE__
#define MIN_BUFSIZE ((FUSE_DEFAULT_USERKERNEL_BUFSIZE) + 0x1000)
#else
#define MIN_BUFSIZE 0x21000
#endif

struct fuse_chan *fuse_kern_chan_new(int fd)
{
	struct fuse_chan_ops op = {
		.receive = fuse_kern_chan_receive,
		.send = fuse_kern_chan_send,
		.destroy = fuse_kern_chan_destroy,
	};
	size_t bufsize = sysconf(_SC_PAGESIZE) + 0x1000;
	bufsize = bufsize < MIN_BUFSIZE ? MIN_BUFSIZE : bufsize;

	recvQ = dispatch_queue_create("recvQ", DISPATCH_QUEUE_SERIAL);
	sendQ = dispatch_queue_create("sendQ", DISPATCH_QUEUE_SERIAL);

	return fuse_chan_new(&op, fd, bufsize, NULL);
}
