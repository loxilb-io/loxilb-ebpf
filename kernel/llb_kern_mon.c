// SPDX-License-Identifier: BSD-3-Clause
// This file is based on https://github.com/CrowdStrike/bpfmon-example
// And modified to work with loxilb by loxilb authors
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"
#include "llb_kern_mon.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, unsigned int);
    __uint(max_entries, 1024);
} map_events SEC(".maps");

#define MEM_READ(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

static void __always_inline
log_map_update(struct pt_regs *ctx, struct bpf_map* updated_map,
               char *pKey, char *pValue, enum map_updater update_type)
{ 
  // Get basic info about the map
  uint32_t map_id = MEM_READ(updated_map->id);
  uint32_t key_size = MEM_READ(updated_map->key_size);
  uint32_t value_size = MEM_READ(updated_map->value_size);
 

  // Read the key and value into byte arrays
  // memset the whole struct to ensure verifier is happy
  struct map_update_data out_data;
  __builtin_memset(&out_data, 0, sizeof(out_data));

  // Set basic data
  out_data.key_size = key_size;
  out_data.value_size = value_size;
  out_data.map_id = map_id;
  out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
  out_data.updater = update_type;

  // Parse the map name
  bpf_probe_read_str(out_data.name, BPF_NAME_LEN, updated_map->name);
  
  // Parse the Key
  if (key_size <= MAX_KEY_SIZE) {
    bpf_probe_read(out_data.key, key_size, pKey);
  } else {
    bpf_probe_read(out_data.key, MAX_KEY_SIZE, pKey);
  }
  // Parse the Value
  if (pValue) {
    if (value_size <= MAX_VALUE_SIZE) {
      bpf_probe_read(out_data.value, value_size, pValue);
    } else {
      bpf_probe_read(out_data.key, MAX_VALUE_SIZE, pKey);
    }
  }

  // Write data to be processed in userspace
  bpf_perf_event_output(ctx, &map_events, BPF_F_CURRENT_CPU,
                        &out_data, sizeof(out_data));
}

SEC("kprobe/bpf_map_update_value.isra.0")
int bpf_prog_user_mapupdate(struct pt_regs *ctx)
{
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  // 'struct fd f' is PARAM2
  char *pKey = (char*)PT_REGS_PARM3(ctx);
  char *pValue = (char*)PT_REGS_PARM4(ctx);

  log_map_update(ctx, updated_map, pKey, pValue, UPDATER_USERMODE);

  return 0;
}

SEC("kprobe/htab_map_update_elem")
int bpf_prog_kern_hmapupdate(struct pt_regs *ctx)
{
  // Parse functions params
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  char *pKey = (char*)PT_REGS_PARM2(ctx);
  char *pValue = (char*)PT_REGS_PARM3(ctx);

  log_map_update(ctx, updated_map, pKey, pValue, UPDATER_KERNEL);
  return 0;
}

SEC("kprobe/htab_map_delete_elem")
int bpf_prog_kern_hmapdelete(struct pt_regs *ctx)
{
  // Parse functions params
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  char *pKey = (char*)PT_REGS_PARM2(ctx);
  char *pValue = NULL;

  log_map_update(ctx, updated_map, pKey, pValue, DELETE_KERNEL);
  return 0;
}

#ifdef HAVE_DP_EXT_MON 

SEC("kprobe/array_map_update_elem")
int bpf_prog_kern_mapupdate(struct pt_regs *ctx)
{
  // Parse functions params
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  char *pKey = (char*)PT_REGS_PARM2(ctx);
  char *pValue = (char*)PT_REGS_PARM3(ctx);

  log_map_update(ctx, updated_map, pKey, pValue, UPDATER_KERNEL);
  return 0;
}

// The bpf syscall has 3 arguments:
//  1. cmd:   The command/action to take (get a map handle, load a program, etc.)
//  2. uattr: A union of structs that hold the arguments for the action
//  3. size:  The size of the union
struct syscall_bpf_args {
    unsigned long long unused;
    long syscall_nr;
    int cmd;
    // bpf_attr contains the arguments to pass to the
    // various bpf commands
    union bpf_attr* uattr;
    unsigned int size;
};
SEC("tp/syscalls/sys_enter_bpf")
int bpf_prog_syscall(struct syscall_bpf_args *args) {
    if (args->cmd == BPF_MAP_GET_FD_BY_ID) {
        // Get The Map ID
        unsigned int map_id = 0;
        bpf_probe_read(&map_id, sizeof(map_id), &args->uattr->map_id);

        // memset the whole struct to ensure verifier is happy
        struct map_update_data out_data;
        __builtin_memset(&out_data, 0, sizeof(out_data));
        
        out_data.map_id = map_id;
        out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
        out_data.updater = UPDATER_SYSCALL_GET;
        // We don't know any key or value size, as we are just getting a handle
        out_data.key_size = 0;
        out_data.value_size = 0;

        // Write data to perf event
        bpf_perf_event_output(args, &map_events, BPF_F_CURRENT_CPU, &out_data, sizeof(out_data));
    }
    else if (args->cmd == BPF_MAP_UPDATE_ELEM) {
        int map_fd = 0;
        bpf_probe_read(&map_fd, sizeof(map_fd), &args->uattr->map_fd);
        
        // memset the whole struct to ensure verifier is happy
        struct map_update_data out_data;
        __builtin_memset(&out_data, 0, sizeof(out_data));

        out_data.map_id = map_fd;
        out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
        out_data.updater = UPDATER_SYSCALL_UPDATE;
        // We don't know any key or value size, as we are just getting a handle
        out_data.key_size = 0;
        out_data.value_size = 0;
        
        // Write data to perf event
        bpf_perf_event_output(args, &map_events, BPF_F_CURRENT_CPU, &out_data, sizeof(out_data));
    }
    return 0;
}
#endif
