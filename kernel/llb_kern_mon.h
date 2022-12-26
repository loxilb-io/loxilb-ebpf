// SPDX-License-Identifier: BSD-3-Clause
// This file is based on https://github.com/CrowdStrike/bpfmon-example
// And modified to work with loxilb by loxilb authors
#ifndef __LLB_KERN_MON_H__
#define __LLB_KERN_MON_H__

#define MAX_KEY_SIZE 64
#define MAX_VALUE_SIZE 176
#define BPF_NAME_LEN 16U

enum map_updater{
    UPDATER_KERNEL,
    UPDATER_USERMODE,
    UPDATER_SYSCALL_GET,
    UPDATER_SYSCALL_UPDATE,
    DELETE_KERNEL,
}map_updater;

typedef struct map_update_data {
    unsigned int map_id;
    char name[BPF_NAME_LEN];
    enum map_updater updater;
    unsigned int pid;
    unsigned int key_size;
    unsigned int value_size;
    char key[MAX_KEY_SIZE];
    char value[MAX_VALUE_SIZE];
} map_update_data;

#endif /* __LLB_KERN_MON_H__ */
