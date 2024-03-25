// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <ftw.h>
#include "cgroup.h"

static bool
file_exists(const char *path)
{
  struct stat sb;

  if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
    return true;
  } else {
    return false;
  }
}

#define get_cgroup_path(buf, path)                                                        \
do {                                                                                      \
  if (file_exists(CGROUP_MOUNT_PATH)) {                                                   \
    snprintf(buf, sizeof(buf), "%s%s%s", CGROUP_MOUNT_PATH, CGROUP_WORK_DIR, path);       \
  } else {                                                                                \
    snprintf(buf, sizeof(buf), "%s%s%s", CGROUP_MOUNT_PATH_NEW, CGROUP_WORK_DIR, path);   \
  }                                                                                       \
} while(0)

static int nftwfunc(const char *filename, const struct stat *statptr,
		    int fileflags, struct FTW *pfwt)
{
	if ((fileflags & FTW_D) && rmdir(filename))
		cgroup_log("Removing cgroup: %s", filename);
	return 0;
}

static int cgroup_join_from_top(char *cgroup_path)
{
	char cgroup_procs_path[PATH_MAX + 1];
	pid_t pid = getpid();
	int fd, rc = 0;

	snprintf(cgroup_procs_path, sizeof(cgroup_procs_path),
		 "%s/cgroup.procs", cgroup_path);

	fd = open(cgroup_procs_path, O_WRONLY);
	if (fd < 0) {
		cgroup_log("Opening Cgroup Procs: %s", cgroup_procs_path);
		return 1;
	}

	if (dprintf(fd, "%d\n", pid) < 0) {
		cgroup_log("Joining Cgroup");
		rc = 1;
	}

	close(fd);
	return rc;
}

/**
 * cgroup_join() - Join a cgroup
 * @path: The cgroup path, relative to the workdir, to join
 *
 * This function expects a cgroup to already be created, relative to the cgroup
 * work dir, and it joins it. For example, passing "/my-cgroup" as the path
 * would actually put the calling process into the cgroup
 * "/cgroup-test-work-dir/my-cgroup"
 *
 * On success, it returns 0, otherwise on failure it returns 1.
 */
int cgroup_join(const char *path)
{
	char cgroup_path[PATH_MAX + 1];

	get_cgroup_path(cgroup_path, path);
	return cgroup_join_from_top(cgroup_path);
}

/**
 * cgroup_clean() - Cleanup Cgroup Testing Environment
 *
 * This is an idempotent function to delete all temporary cgroups that
 * have been created during the test, including the cgroup testing work
 * directory.
 *
 * At call time, it moves the calling process to the root cgroup, and then
 * runs the deletion process. It is idempotent, and should not fail, unless
 * a process is lingering.
 *
 * On failure, it will print an error to stderr, and try to continue.
 */
void cgroup_clean(void)
{
	char topdir[PATH_MAX + 1];

	get_cgroup_path(topdir, "");
	cgroup_join_from_top(CGROUP_MOUNT_PATH);
	nftw(topdir, nftwfunc, MAX_FD_LIMIT, FTW_DEPTH | FTW_MOUNT);
}

/**
 * cgroup_create_get() - Create a cgroup, relative to workdir, and get the FD
 * @path: The cgroup path, relative to the workdir, to join
 *
 * This function creates a cgroup under the top level workdir and returns the
 * file descriptor. It is idempotent.
 *
 * On success, it returns the file descriptor. On failure it returns -1.
 * If there is a failure, it prints the error to stderr.
 */
int cgroup_create_get(const char *path)
{
	char cgroup_path[PATH_MAX + 1];
	int fd;

	get_cgroup_path(cgroup_path, path);
	if (mkdir(cgroup_path, 0777) && errno != EEXIST) {
		cgroup_log("mkdiring cgroup %s .. %s", path, cgroup_path);
		return -1;
	}

	fd = open(cgroup_path, O_RDONLY);
	if (fd < 0) {
		cgroup_log("Opening Cgroup");
		return -1;
	}

	return fd;
}

/**
 * get_cgroup_id() - Get cgroup id for a particular cgroup path
 * @path: The cgroup path, relative to the workdir, to join
 *
 * On success, it returns the cgroup id. On failure it returns 0,
 * which is an invalid cgroup id.
 * If there is a failure, it prints the error to stderr.
 */
uint64_t get_cgroup_id(const char *path)
{
	int dirfd, err, flags, mount_id, fhsize;
	union {
		unsigned long long cgid;
		unsigned char raw_bytes[8];
	} id;
	char topdir[PATH_MAX + 1];
	struct file_handle *fhp, *fhp2;
	unsigned long long ret = 0;

	get_cgroup_path(topdir, path);

	dirfd = AT_FDCWD;
	flags = 0;
	fhsize = sizeof(*fhp);
	fhp = calloc(1, fhsize);
	if (!fhp) {
		cgroup_log("calloc");
		return 0;
	}
	err = name_to_handle_at(dirfd, topdir, fhp, &mount_id, flags);
	if (err >= 0 || fhp->handle_bytes != 8) {
		cgroup_log("name_to_handle_at");
		goto free_mem;
	}

	fhsize = sizeof(struct file_handle) + fhp->handle_bytes;
	fhp2 = realloc(fhp, fhsize);
	if (!fhp2) {
		cgroup_log("realloc");
		goto free_mem;
	}
	err = name_to_handle_at(dirfd, topdir, fhp2, &mount_id, flags);
	fhp = fhp2;
	if (err < 0) {
		cgroup_log("name_to_handle_at");
		goto free_mem;
	}

	memcpy(id.raw_bytes, fhp->f_handle, 8);
	ret = id.cgid;

free_mem:
	free(fhp);
	return ret;
}

int cgroup_control_enable(char *cgroup_path)
{
	char path[PATH_MAX + 1];
	char buf[PATH_MAX];
	char *c, *c2;
	int fd, cfd;
	ssize_t len;

	snprintf(path, sizeof(path), "%s/cgroup.controllers", cgroup_path);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("Opening cgroup.controllers: %s\n", path);
		return 1;
	}

	len = read(fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		close(fd);
		cgroup_log("Reading cgroup.controllers: %s", path);
		return 1;
	}
	buf[len] = 0;
	close(fd);

	/* Are we on cgroup v1 ? */
	if (len == 0)
		return 0;

	snprintf(path, sizeof(path), "%s/cgroup.subtree_control", cgroup_path);
	cfd = open(path, O_RDWR);
	if (cfd < 0) {
		cgroup_log("Opening cgroup.subtree_control: %s", path);
		return 1;
	}

	for (c = strtok_r(buf, " ", &c2); c; c = strtok_r(NULL, " ", &c2)) {
		if (dprintf(cfd, "+%s\n", c) <= 0) {
			cgroup_log("Enabling controller %s: %s", c, path);
			close(cfd);
			return 1;
		}
	}
	close(cfd);
	return 0;
}

/**
 * cgroup_mkenv() - Setup the cgroup environment
 *
 * After calling this function, cgroup_clean should be called
 * once testing is complete.
 *
 * This function will print an error to stderr and return 1 if it is unable
 * to setup the cgroup environment. If setup is successful, 0 is returned.
 */
int cgroup_mkenv(void)
{
	char topdir[PATH_MAX - 24];

	get_cgroup_path(topdir, "");

	if (unshare(CLONE_NEWNS)) {
		cgroup_log("unshare");
		return 1;
	}

	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		cgroup_log("mount fakeroot");
		return 1;
	}

	if (mount("none", CGROUP_MOUNT_PATH, "cgroup2", 0, NULL) && errno != EBUSY) {
		cgroup_log("cgroup2 mount");
		return 1;
	}

	/* Cleanup existing failed runs, now that the environment is setup */
	cgroup_clean();

	if (mkdir(topdir, 0777) && errno != EEXIST) {
		cgroup_log("cgroup topdir");
		return 1;
	}

	if (cgroup_control_enable(topdir))
		return 1;

	return 0;
}
