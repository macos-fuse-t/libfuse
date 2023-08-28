/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2020 Benjamin Fleischer
 *
 * Derived from mount_bsd.c from the FUSE distribution.
 *
 *  FUSE: Filesystem in Userspace
 *  Copyright (C) 2005-2006 Csaba Henk <csaba.henk@creo.hu>
 *
 *  This program can be distributed under the terms of the GNU LGPLv2.
 *  See the file COPYING.LIB.
 */

#include "fuse_i.h"
#include "fuse_opt.h"
#include "fuse_darwin_private.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <paths.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <DiskArbitration/DiskArbitration.h>

static int quiet_mode = 0;
static int debug_mode = 0;

static pid_t cpid = -1;
static pthread_t mount_wait_thread = 0;

enum {
	KEY_ALLOW_ROOT,
	KEY_AUTO_CACHE,
	KEY_DIO,
	KEY_HELP,
	KEY_IGNORED,
	KEY_KERN,
	KEY_QUIET,
	KEY_RO,
	KEY_VERSION,
	KEY_DEBUG,
	KEY_NONAMEDATTR,
	KEY_NOATTRCACHE,
	KEY_NOBROWSE,
	KEY_NOATIME,
	KEY_NOMTIME,
	KEY_NFC,
};

struct mount_opts {
	int allow_other;
	int allow_root;
	int ishelp;
	char *kernel_opts;
	char *modules;
	char *volicon;
	char *volname;
	char *listen_addr;
	int read_only;
	int nonamedattr;
	int noattrcache;
	int rwsize;
	int nobrowse;
	int nfc;
	int noatime;
	int nomtime;
	char *location;
};

static const struct fuse_opt fuse_mount_opts[] = {
	{ "allow_other", offsetof(struct mount_opts, allow_other), 1 },
	{ "allow_root", offsetof(struct mount_opts, allow_root), 1 },
	{ "modules=%s", offsetof(struct mount_opts, modules), 0 },
	{ "volname=%s", offsetof(struct mount_opts, volname), 0 },
	{ "location=%s", offsetof(struct mount_opts, location), 0 },
	FUSE_OPT_KEY("allow_root",	      KEY_ALLOW_ROOT),
	FUSE_OPT_KEY("auto_cache",	      KEY_AUTO_CACHE),
	FUSE_OPT_KEY("-r",		      KEY_RO),
	FUSE_OPT_KEY("-h",		      KEY_HELP),
	FUSE_OPT_KEY("--help",		      KEY_HELP),
	FUSE_OPT_KEY("-V",		      KEY_VERSION),
	FUSE_OPT_KEY("--version",	      KEY_VERSION),
	/* standard FreeBSD mount options */
	FUSE_OPT_KEY("dev",		      KEY_KERN),
	FUSE_OPT_KEY("async",		      KEY_KERN),
	FUSE_OPT_KEY("atime",		      KEY_KERN),
	FUSE_OPT_KEY("dev",		      KEY_KERN),
	FUSE_OPT_KEY("exec",		      KEY_KERN),
	FUSE_OPT_KEY("suid",		      KEY_KERN),
	FUSE_OPT_KEY("symfollow",	      KEY_KERN),
	FUSE_OPT_KEY("rdonly",		      KEY_KERN),
	FUSE_OPT_KEY("sync",		      KEY_KERN),
	FUSE_OPT_KEY("union",		      KEY_KERN),
	FUSE_OPT_KEY("userquota",	      KEY_KERN),
	FUSE_OPT_KEY("groupquota",	      KEY_KERN),
	FUSE_OPT_KEY("clusterr",	      KEY_KERN),
	FUSE_OPT_KEY("clusterw",	      KEY_KERN),
	FUSE_OPT_KEY("suiddir",		      KEY_KERN),
	FUSE_OPT_KEY("snapshot",	      KEY_KERN),
	FUSE_OPT_KEY("multilabel",	      KEY_KERN),
	FUSE_OPT_KEY("acls",		      KEY_KERN),
	FUSE_OPT_KEY("force",		      KEY_KERN),
	FUSE_OPT_KEY("update",		      KEY_KERN),
	FUSE_OPT_KEY("ro",		      KEY_RO),
	FUSE_OPT_KEY("rw",		      KEY_KERN),
	FUSE_OPT_KEY("auto",		      KEY_KERN),
	/* options supported under both Linux and FBSD */
	FUSE_OPT_KEY("allow_other",	      KEY_KERN),
	FUSE_OPT_KEY("default_permissions",   KEY_KERN),
	/* FBSD FUSE specific mount options */
	FUSE_OPT_KEY("private",		      KEY_KERN),
	FUSE_OPT_KEY("neglect_shares",	      KEY_KERN),
	FUSE_OPT_KEY("push_symlinks_in",      KEY_KERN),
	/* stock FBSD mountopt parsing routine lets anything be negated... */
	FUSE_OPT_KEY("nodev",		      KEY_KERN),
	FUSE_OPT_KEY("noasync",		      KEY_KERN),
	FUSE_OPT_KEY("noatime",		      KEY_KERN),
	FUSE_OPT_KEY("nodev",		      KEY_KERN),
	FUSE_OPT_KEY("noexec",		      KEY_KERN),
	FUSE_OPT_KEY("nosuid",		      KEY_KERN),
	FUSE_OPT_KEY("nosymfollow",	      KEY_KERN),
	FUSE_OPT_KEY("nordonly",	      KEY_KERN),
	FUSE_OPT_KEY("nosync",		      KEY_KERN),
	FUSE_OPT_KEY("nounion",		      KEY_KERN),
	FUSE_OPT_KEY("nouserquota",	      KEY_KERN),
	FUSE_OPT_KEY("nogroupquota",	      KEY_KERN),
	FUSE_OPT_KEY("noclusterr",	      KEY_KERN),
	FUSE_OPT_KEY("noclusterw",	      KEY_KERN),
	FUSE_OPT_KEY("nosuiddir",	      KEY_KERN),
	FUSE_OPT_KEY("nosnapshot",	      KEY_KERN),
	FUSE_OPT_KEY("nomultilabel",	      KEY_KERN),
	FUSE_OPT_KEY("noacls",		      KEY_KERN),
	FUSE_OPT_KEY("noforce",		      KEY_KERN),
	FUSE_OPT_KEY("noupdate",	      KEY_KERN),
	FUSE_OPT_KEY("noro",		      KEY_KERN),
	FUSE_OPT_KEY("norw",		      KEY_KERN),
	FUSE_OPT_KEY("noauto",		      KEY_KERN),
	FUSE_OPT_KEY("noallow_other",	      KEY_KERN),
	FUSE_OPT_KEY("nodefault_permissions", KEY_KERN),
	FUSE_OPT_KEY("noprivate",	      KEY_KERN),
	FUSE_OPT_KEY("noneglect_shares",      KEY_KERN),
	FUSE_OPT_KEY("nopush_symlinks_in",    KEY_KERN),
	/* macOS options */
	FUSE_OPT_KEY("allow_recursion",	      KEY_KERN),
	FUSE_OPT_KEY("allow_root",	      KEY_KERN), /* need to pass this on */
	FUSE_OPT_KEY("auto_xattr",	      KEY_KERN),
	FUSE_OPT_KEY("automounted",	      KEY_IGNORED),
	FUSE_OPT_KEY("blocksize=",	      KEY_KERN),
	FUSE_OPT_KEY("daemon_timeout=",	      KEY_KERN),
	FUSE_OPT_KEY("default_permissions",   KEY_KERN),
	FUSE_OPT_KEY("defer_permissions",     KEY_KERN),
	FUSE_OPT_KEY("direct_io",	      KEY_DIO),
	FUSE_OPT_KEY("excl_create",	      KEY_KERN),
	FUSE_OPT_KEY("extended_security",     KEY_KERN),
	FUSE_OPT_KEY("fsid=",		      KEY_KERN),
	FUSE_OPT_KEY("fsname=",		      KEY_KERN),
	FUSE_OPT_KEY("fssubtype=",	      KEY_KERN),
	FUSE_OPT_KEY("fstypename=",	      KEY_KERN),
	FUSE_OPT_KEY("init_timeout=",	      KEY_KERN),
	FUSE_OPT_KEY("iosize=",		      KEY_KERN),
	FUSE_OPT_KEY("jail_symlinks",	      KEY_KERN),
	FUSE_OPT_KEY("kill_on_unmount",	      KEY_KERN),
	FUSE_OPT_KEY("local",		      KEY_KERN),
	FUSE_OPT_KEY("native_xattr",	      KEY_KERN),
	FUSE_OPT_KEY("negative_vncache",      KEY_KERN),
	FUSE_OPT_KEY("noalerts",	      KEY_KERN),
	FUSE_OPT_KEY("noappledouble",	      KEY_KERN),
	FUSE_OPT_KEY("noapplexattr",	      KEY_KERN),
	FUSE_OPT_KEY("noattrcache",	      KEY_NOATTRCACHE),
	FUSE_OPT_KEY("noautonotify",	      KEY_KERN),
	FUSE_OPT_KEY("nobrowse",	      KEY_NOBROWSE),
	FUSE_OPT_KEY("nolocalcaches",	      KEY_KERN),
	FUSE_OPT_KEY("noping_diskarb",	      KEY_IGNORED),
	FUSE_OPT_KEY("noreadahead",	      KEY_KERN),
	FUSE_OPT_KEY("nosynconclose",	      KEY_KERN),
	FUSE_OPT_KEY("nosyncwrites",	      KEY_KERN),
	FUSE_OPT_KEY("noubc",		      KEY_KERN),
	FUSE_OPT_KEY("novncache",	      KEY_KERN),
	FUSE_OPT_KEY("ping_diskarb",	      KEY_IGNORED),
	FUSE_OPT_KEY("quiet",		      KEY_QUIET),
	FUSE_OPT_KEY("slow_statfs",	      KEY_KERN),
	FUSE_OPT_KEY("sparse",		      KEY_KERN),
	FUSE_OPT_KEY("subtype=",	      KEY_IGNORED),
	{ "volicon=%s", offsetof(struct mount_opts, volicon), 0 },
	FUSE_OPT_KEY("debug",		      KEY_DEBUG),
	FUSE_OPT_KEY("-d",		     	  KEY_DEBUG),
	{ "listen_addr=%s", offsetof(struct mount_opts, listen_addr), 0 },
	FUSE_OPT_KEY("nonamedattr",	      KEY_NONAMEDATTR),
	FUSE_OPT_KEY("nfc",	      		KEY_NFC),
	{ "rwsize=%d", offsetof(struct mount_opts, rwsize), 0 },
	FUSE_OPT_KEY("noatime",	      	KEY_NOATIME),
	FUSE_OPT_KEY("nomtime",	      	KEY_NOMTIME),
	FUSE_OPT_END
};

static void
mount_run(const char *mount_args)
{
}

static void
mount_help(void)
{
	mount_run("--help");
	fputc('\n', stderr);
}

static void
mount_version(void)
{
	mount_run("--version");
}

static int
fuse_mount_opt_proc(void *data, const char *arg, int key,
		    struct fuse_args *outargs)
{
	struct mount_opts *mo = data;

	switch (key) {

		case KEY_AUTO_CACHE:
			if (fuse_opt_add_opt(&mo->kernel_opts, "auto_cache") == -1 ||
			    fuse_opt_add_arg(outargs, "-oauto_cache") == -1)
				return -1;
			return 0;

		case KEY_ALLOW_ROOT:
			if (fuse_opt_add_opt(&mo->kernel_opts, "allow_other") == -1 ||
			    fuse_opt_add_arg(outargs, "-oallow_root") == -1)
				return -1;
			return 0;

		case KEY_RO:
			arg = "ro";
			mo->read_only = 1;
			/* fall through */

		case KEY_KERN:
			return fuse_opt_add_opt(&mo->kernel_opts, arg);

		case KEY_DIO:
			if (fuse_opt_add_opt(&mo->kernel_opts, "direct_io") == -1 ||
			    (fuse_opt_add_arg(outargs, "-odirect_io") == -1))
				return -1;
			return 0;

		case KEY_IGNORED:
			return 0;

		case KEY_QUIET:
			quiet_mode = 1;
			return 0;
		case KEY_DEBUG:
			debug_mode = 1;
			break;
		case KEY_HELP:
			mount_help();
			mo->ishelp = 1;
			break;

		case KEY_VERSION:
			mount_version();
			mo->ishelp = 1;
			break;
		case KEY_NONAMEDATTR:
			mo->nonamedattr = 1;
			return 0;
		case KEY_NOATTRCACHE:
			mo->noattrcache = 1;
			return 0;
		case KEY_NOBROWSE:
			mo->nobrowse = 1;
			return 0;
		case KEY_NFC:
			mo->nfc = 1;
			return 0;
		case KEY_NOATIME:
			mo->noatime = 1;
			return 0;
		case KEY_NOMTIME:
			mo->nomtime = 1;
			return 0;
	}
	return 1;
}


void fuse_kern_unmount(const char *mountpoint, int fd)
{
	if (fd > 0) {
		char unmount_cmd[] = "unmount";
		send(fd, unmount_cmd, strlen(unmount_cmd), 0);
		close(fd);
	}

    /* Terminate the server process */
    if (cpid != -1) {
        kill(cpid, SIGTERM);

        int status = 0;
        waitpid(cpid, &status, 0);
    }

    /* Join our mount thread */
    if (mount_wait_thread) {
        pthread_join(mount_wait_thread, NULL);
    }

}

void
fuse_unmount_compat22(const char *mountpoint)
{
	(void)unmount(mountpoint, 0);
}

/* return value:
 * >= 0	 => fd
 * -1	 => error
 */
static int receive_fd(int sock_fd)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[1];
	size_t rv;
	char ccmsg[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	int fd;

	iov.iov_base = buf;
	iov.iov_len = 1;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	while (((rv = recvmsg(sock_fd, &msg, 0)) == -1) && errno == EINTR);
	if (rv == -1) {
		perror("recvmsg");
		return -1;
	}
	if (!rv) {
		/* EOF */
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "got control message of unknown type %d\n",
			cmsg->cmsg_type);
		return -1;
	}

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return fd;
}

struct fuse_mount_core_wait_arg {
	int fd;
	void (*callback)(void *context, int res, int fd);
	void *context;
};

static void *
fuse_mount_core_wait(void *arg)
{
	int fd;
	void (*callback)(void *context, int res, int mod_fd);
	void *context;
	char mount_cmd[] = "mount";

	int32_t status = -1;
	ssize_t rv = 0;

	{
		struct fuse_mount_core_wait_arg *a =
			(struct fuse_mount_core_wait_arg *)arg;
		fd = a->fd;
		callback = a->callback;
		context = a->context;
	}

	rv = send(fd, mount_cmd, strlen(mount_cmd), 0);
	if (rv != strlen(mount_cmd)) {
		perror("send mount command");
		goto out;
	}

	while (((rv = recv(fd, &status, sizeof(status), 0)) == -1) &&
	       errno == EINTR);
	if (rv == -1) {
		perror("receive mount status");
		goto out;
	}
	if (!rv) {
		/* EOF */
		goto out;
	}

	if (callback)
		callback(context, status, fd);

out:
	free(arg);
	return NULL;
}

static int
fuse_mount_core(const char *mountpoint, struct mount_opts *mopts,
		void (*callback)(void *, int, int), void *context)
{
	int fd;
	int result;
	char *dev;
	char *mount_prog_path;
	int fds[2];
	int mon_fds[2];
	pid_t pid;
	int status;
	char *srv_path;
	int sndsize = 4*1024*1024;

	if (!mountpoint) {
		fprintf(stderr, "missing or invalid mount point\n");
		return -1;
	}

	signal(SIGCHLD, SIG_DFL); /* So that we can wait4() below. */

	srv_path = getenv("FUSE_NFSSRV_PATH");
	if (!srv_path)
		srv_path = FUSE_NFSSRV_PROG;
	mount_prog_path = fuse_resource_path(srv_path);
	if (!mount_prog_path) {
		fprintf(stderr, "fuse: mount program missing\n");
		return -1;
	}

	result = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (result == -1) {
		fprintf(stderr, "fuse: socketpair() failed");
		return -1;
	}

	setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &sndsize, sizeof(sndsize));
	setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sndsize, sizeof(sndsize));
	setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &sndsize, sizeof(sndsize));
	setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &sndsize, sizeof(sndsize));


	result = socketpair(AF_UNIX, SOCK_STREAM, 0, mon_fds);
	if (result == -1) {
		fprintf(stderr, "fuse: socketpair() failed");
		return -1;
	}
		
	cpid = fork();

	if (cpid == -1) {
		perror("fuse: fork failed");
		close(fds[0]);
		close(fds[1]);
		close(mon_fds[0]);
		close(mon_fds[1]);
		_exit(1);
	}

	if (cpid == 0) {
		char daemon_path[PROC_PIDPATHINFO_MAXSIZE];
		char commfd[10];
		char rwsize_str[64];

		const char *argv[32];
		int a = 0;

		close(fds[1]);
		close(mon_fds[1]);

		if (proc_pidpath(getpid(), daemon_path, PROC_PIDPATHINFO_MAXSIZE)) {
			setenv("_FUSE_DAEMON_PATH", daemon_path, 1);
		}

		snprintf(commfd, sizeof(commfd), "%i", fds[0]);
		setenv("_FUSE_COMMFD", commfd, 1);
		snprintf(commfd, sizeof(commfd), "%i", mon_fds[0]);
		setenv("_FUSE_MONFD", commfd, 1);
		setenv("_FUSE_COMMVERS", "2", 1);

		argv[a++] = mount_prog_path;
		if (mopts->listen_addr) {
			argv[a++] = "-l";
			argv[a++] = mopts->listen_addr;
		}
		if (debug_mode) {
			argv[a++] = "-d";
		}
		if (mopts->volname) {
			argv[a++] = "--volname";
			argv[a++] = mopts->volname;
		}
		if (mopts->read_only) {
			argv[a++] = "-r";
		}
		if (mopts->nonamedattr) {
			argv[a++] = "--namedattr=false";
		}
		if (mopts->noattrcache) {
			argv[a++] = "--attrcache=false";
		}
		if (mopts->rwsize) {
			sprintf(rwsize_str, "--rwsize=%d", mopts->rwsize);
			argv[a++] = rwsize_str;
		}
		if (mopts->nobrowse) {
			argv[a++] = "--dontbrowse=true";
		}
		if (mopts->nfc) {
			argv[a++] = "--nfc=true";
		}
		if (mopts->noatime) {
			argv[a++] = "--noatime=true";
		}
		if (mopts->nomtime) {
			argv[a++] = "--nomtime=true";
		}
		if (mopts->location) {
			argv[a++] = "--location";
			argv[a++] = mopts->location;
		}

		argv[a++] = mountpoint;
		argv[a++] = NULL;

		// daemonize the server
        setsid();
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);

		execv(mount_prog_path, (char **)argv);
		perror("fuse: failed to exec mount program");
		_exit(1);
	}

	free(mount_prog_path);

	close(fds[0]);
	close(mon_fds[0]);
	fd = fds[1];

	if (getenv("FUSE_NO_MOUNT")) {
		goto out;
	}

	struct fuse_mount_core_wait_arg *arg =
		calloc(1, sizeof(struct fuse_mount_core_wait_arg));
	arg->fd = mon_fds[1];
	arg->callback = callback;
	arg->context = context;

	int res = pthread_create(&mount_wait_thread, NULL,
				 &fuse_mount_core_wait, (void *)arg);
	if (res) {
		perror("fuse: failed to wait for mount status");
		goto mount_err_out;
	}

	goto out;

mount_err_out:
	close(fd);
	close(mon_fds[1]);
	fd = -1;

out:
	return fd;
}

int
fuse_kern_mount(const char *mountpoint, struct fuse_args *args,
		void (*callback)(void *, int, int), void *context)
{
	struct mount_opts mo;
	int res = -1;

	memset(&mo, 0, sizeof(mo));

	/* to notify mount_macfuse it's called from lib */
	setenv("_FUSE_CALL_BY_LIB", "1", 1);

	if (args &&
		fuse_opt_parse(args, &mo, fuse_mount_opts, fuse_mount_opt_proc) == -1) {
		return -1;
	}

	if (mo.allow_other && mo.allow_root) {
		fprintf(stderr,
			"fuse: allow_other and allow_root are mutually exclusive\n");
		goto out;
	}

	if (mo.ishelp) {
		res = 0;
		goto out;
	}

	if (mo.volicon) {
		size_t modules_len;
		char *modules;
		char *modules_ptr;

		char iconpath_arg[MAXPATHLEN + 12];

		if (mo.modules) {
			modules_len = strlen(mo.modules);
		} else {
			modules_len = 0;
		}

		modules = (char *)malloc(modules_len + sizeof(":volicon"));
		if (!modules) {
			fprintf(stderr, "fuse: failed to allocate modules string\n");
			goto out;
		}

		/* build new modules string */
		modules_ptr = modules;
		if (modules_len) {
			modules_ptr = stpcpy(modules_ptr, mo.modules);
			*modules_ptr = ':';
			modules_ptr++;
		}
		modules_ptr = stpcpy(modules_ptr, "volicon");
		*modules_ptr = '\0';

		/* replace old modules string */
		if (mo.modules) {
			free(mo.modules);
		}
		mo.modules = modules;

		/* add iconpath argument */
		if (snprintf(iconpath_arg, sizeof(iconpath_arg),
			     "-oiconpath=%s", mo.volicon) <= 0) {
			fprintf(stderr, "fuse: failed to create iconpath argument\n");
			goto out;
		}
		if (fuse_opt_add_arg(args, iconpath_arg) == -1) {
			fprintf(stderr, "fuse: failed to add iconpath argument\n");
			goto out;
		}
	}

	if (mo.modules) {
		int err;

		size_t modules_arg_len = sizeof("-omodules=") + strlen(mo.modules);
		char *modules_arg = (char *)malloc(modules_arg_len);

		/* add modules argument */
		err = snprintf(modules_arg, modules_arg_len, "-omodules=%s",
			       mo.modules);
		if (err <= 0) {
			fprintf(stderr, "fuse: failed to create modules argument\n");
			free(modules_arg);
			goto out;
		}
		err = fuse_opt_add_arg(args, modules_arg);
		free(modules_arg);
		if (err == -1) {
			fprintf(stderr, "fuse: failed to add modules argument\n");
			goto out;
		}
	}

	res = fuse_mount_core(mountpoint, &mo, callback, context);

out:
	free(mo.kernel_opts);
	if (mo.modules) {
		free(mo.modules);
	}
	if (mo.volicon) {
		free(mo.volicon);
	}

	return res;
}
