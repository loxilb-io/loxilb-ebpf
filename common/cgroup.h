// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#ifndef __CGROUP_H__
#define __CGROUP_H__

#include <errno.h>
#include <string.h>

#define MAX_FD_LIMIT        16
#define CGROUP_MOUNT_PATH   "/sys/fs/cgroup/unified/"
#define CGROUP_WORK_DIR     ""
#define CGROUP_PATH         ""

#define get_cgroup_path(buf, path) \
  snprintf(buf, sizeof(buf), "%s%s%s", CGROUP_MOUNT_PATH, CGROUP_WORK_DIR, path)

#define pr_errno() (errno == 0 ? "none" : strerror(errno))
#define cgroup_log(LOG, ...) fprintf(stderr, "(%s:%d: errno: %s) " LOG "\n", \
	__FILE__, __LINE__, pr_errno(), ##__VA_ARGS__)

int cgroup_create_get(const char *path);
int cgroup_join(const char *path);
uint64_t get_cgroup_id(const char *path);
int cgroup_mkenv(void);
void cgroup_clean(void);

#endif
