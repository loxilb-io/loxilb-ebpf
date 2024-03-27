// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#ifndef __CGROUP_H__
#define __CGROUP_H__

#include <errno.h>
#include <string.h>

#define MAX_FD_LIMIT            16
#define CGROUP_MOUNT_PATH       "/opt/loxilb/cgroup"
#define CGROUP_MOUNT_PATH_NEW   "/sys/fs/cgroup/"
#define CGROUP_WORK_DIR         ""
#define CGROUP_PATH             ""

#define pr_errno() (errno == 0 ? "none" : strerror(errno))
#define cgroup_log(LOG, ...) fprintf(stderr, "(%s:%d: errno: %s) " LOG "\n", \
	__FILE__, __LINE__, pr_errno(), ##__VA_ARGS__)

int cgroup_create_get(const char *path);
int cgroup_join(const char *path);
uint64_t get_cgroup_id(const char *path);
int cgroup_mkenv(void);
void cgroup_clean(void);

#endif
