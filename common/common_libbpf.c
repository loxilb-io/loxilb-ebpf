/* Common wrapper function for libbpf */
#include <string.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/if_link.h>
#include <linux/err.h>
#include <linux/pkt_cls.h>
#include <bpf/libbpf.h>

#include "bpf.h"
#include "log.h"
#include "common_libbpf.h"

static int
setup_tail_calls(struct bpf_object *obj, struct libbpf_cfg *cfg)
{
  int key, jmp_table_fd;
  struct bpf_program *prog;
  const char *section;
  char pinpbuf[PINPATH_MAX_LEN];

  int len = snprintf(pinpbuf, PINPATH_MAX_LEN, "%s/%s", cfg->pin_dir, "pgm_tbl");
  if (len < 0 || len >= PINPATH_MAX_LEN) {
    log_error("failed to find jump tables %s", pinpbuf);
    return -1;
  }

  jmp_table_fd = bpf_object__find_map_fd_by_name(obj, "pgm_tbl");
  if (jmp_table_fd < 0) {
    jmp_table_fd = bpf_obj_get(pinpbuf);

    if (jmp_table_fd < 0) {
      log_error("finding a map in obj file %s failed", pinpbuf);
      return -1;
    }
  }

  bpf_object__for_each_program(prog, obj) {
    int fd = bpf_program__fd(prog);

    section = bpf_program__section_name(prog);
    if (strcmp(section, "tc_packet_hook7") == 0) {
      key = 7;
    } else if (strcmp(section, "tc_packet_hook6") == 0) {
      key = 6;
    } else if (strcmp(section, "tc_packet_hook5") == 0) {
      key = 5;
    } else if (strcmp(section, "tc_packet_hook4") == 0) {
      key = 4;
    } else if (strcmp(section, "tc_packet_hook3") == 0) {
      key = 3;
    } else if (strcmp(section, "tc_packet_hook2") == 0) {
      key = 2;
    } else if (strcmp(section, "tc_packet_hook1") == 0) {
      key = 1;
    } else  if (strcmp(section, "tc_packet_hook0") == 0) {
      key = 0;
    } else key = -1;

    if (key >= 0)
      bpf_map_update_elem(jmp_table_fd, &key, &fd, BPF_ANY);
  }

  return 0;
}

int
libbpf_tc_detach(struct libbpf_cfg *cfg, int egr)
{
  DECLARE_LIBBPF_OPTS(bpf_tc_hook,
                      hook,
                      .ifindex = cfg->ifindex,
                      .parent = 0,
                      .attach_point = egr ? BPF_TC_EGRESS : BPF_TC_INGRESS);
  DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
                      .handle = 1,
                      .priority = 1,
                      .prog_fd = -1,
                      .flags = 0,
                      .prog_id = 0);


  bpf_tc_hook_create(&hook);
  bpf_tc_detach(&hook, &opts);

  hook.attach_point = BPF_TC_EGRESS|BPF_TC_INGRESS;
  int rc = bpf_tc_hook_destroy(&hook);
  if (rc < 0) {
    log_error("tc: bpf hook destroy failed for %s:%d", cfg->ifname, egr);
  } else {
    log_debug("tc: bpf destroy OK for %s:%d", cfg->ifname, egr);
  }
  return 0;
}

void *
libbpf_tc_attach(struct libbpf_cfg *cfg, int egr)
{
  int len, pmfd;
  char pinpbuf[PINPATH_MAX_LEN];
  struct bpf_object *bpf_obj;
  struct bpf_program *bpf_pgm = NULL;
  struct bpf_program *p;
  struct bpf_map *map;
  DECLARE_LIBBPF_OPTS(bpf_tc_hook,
                      hook,
                      .ifindex = cfg->ifindex,
                      .parent = 0,
                      .attach_point = egr ? BPF_TC_EGRESS : BPF_TC_INGRESS);
  DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
                      .handle = 1,
                      .priority = 1,
                      .prog_fd = -1,
                      .flags = BPF_TC_F_REPLACE);

  log_info("tc: bpf attach start for %s:%d", cfg->ifname, egr);

  if (!egr) {
    if (bpf_tc_hook_create(&hook)) {
      log_error("tc: hook create failed");
      return NULL;
    }
  }

  bpf_obj = bpf_object__open(cfg->filename);

  bpf_object__for_each_map(map, bpf_obj) {
    len = snprintf(pinpbuf, PINPATH_MAX_LEN, "%s/%s", cfg->pin_dir, bpf_map__name(map));
    if (len < 0 || len >= PINPATH_MAX_LEN) {
      log_error("tc: pinpath buffer error");
      goto cleanup;
    }

    pmfd = bpf_obj_get(pinpbuf);
    if (pmfd < 0) {
      log_error("tc: no obj for pinpath %s ", pinpbuf);
      goto cleanup;
    }

    if (bpf_map__reuse_fd(map, pmfd)) {
      log_error("tc: map %s reus failed", bpf_map__name(map));
      goto cleanup;
    }
  }

  bpf_object__for_each_program(p, bpf_obj) {
    if ((strcmp(bpf_program__section_name(p), "tc_packet_hook1") == 0 ||
        strcmp(bpf_program__section_name(p), "tc_packet_hook2") == 0 ||
        strcmp(bpf_program__section_name(p), "tc_packet_hook3") == 0 ||
        strcmp(bpf_program__section_name(p), "tc_packet_hook4") == 0 ||
        strcmp(bpf_program__section_name(p), "tc_packet_hook5") == 0 ||
        strcmp(bpf_program__section_name(p), "tc_packet_hook6") == 0 ||
        strcmp(bpf_program__section_name(p), "tc_packet_hook7") == 0) &&
        strcmp(bpf_program__section_name(p), cfg->progsec)) {

      log_debug("tc: autoload sec %s prog %s",
           bpf_program__section_name(p),  bpf_program__name(p));

      if (bpf_program__set_autoload(p, true))
        goto cleanup;
    }

    bpf_program__set_type(p, BPF_PROG_TYPE_SCHED_CLS);

    if (strcmp(bpf_program__section_name(p), cfg->progsec) == 0) {
      if (bpf_pgm == NULL) {
        bpf_pgm = p;
      }
    }
  }

  if (bpf_pgm == NULL) {
    log_error("tc: pgm %s find failed", cfg->progsec);
    goto cleanup;
  }

  if (bpf_object__load(bpf_obj)) {
    log_error("tc: obj load failed");
    return NULL;
  }

  if (setup_tail_calls(bpf_obj, cfg)) {
    log_error("tc: setup tail calls failed");
    return NULL;
  }

  opts.prog_fd = bpf_program__fd(bpf_pgm);
  if (opts.prog_fd <= -1) {
    log_error("tc: pgm %s has  no fd", cfg->progsec);
    goto cleanup;
  }

  int rc = bpf_tc_attach(&hook, &opts);
  if (rc < 0) {
    log_error("tc: bpf attach failed for %s (%d)", cfg->ifname, cfg->tc_egr_bpf);
    goto cleanup;
  }

  log_info("tc: bpf attach OK for %s ", cfg->ifname);
  return bpf_obj;

cleanup:
  bpf_object__close(bpf_obj);
  return NULL;
}

int
xdp_link_attach(int ifindex, __u32 bpf_flags, int prog_fd)
{
  int err;

  err = bpf_xdp_attach(ifindex, prog_fd, bpf_flags, NULL);
  if (err < 0) {
    log_error("bpfhelper: ifindex(%d) link set xdp fd failed : %s", ifindex, strerror(-err));
    return -1;
  }

  return 0;
}

int
xdp_link_detach(int ifindex, __u32 bpf_flags, __u32 epgid)
{
  __u32 cpgid;
  int err;

  err = bpf_xdp_query_id(ifindex, bpf_flags, &cpgid);
  if (err) {
    log_error("bpfhelper: get link xdp id failed : %s", strerror(-err));
    return -1;
  }

  if (!cpgid) {
    return 0;
  }

  if (epgid && cpgid != epgid) {
    log_error("bpfhelper: expected epgid %d != cpgid %d", epgid, cpgid);
    return -1;
  }

  if ((err = bpf_xdp_detach(ifindex, bpf_flags, NULL)) < 0) {
    log_error("bpfhelper: link set xdp failed : %s", strerror(-err));
    return -1;
  }

  log_debug("bpfhelper: removed XDP pgid %d from ifindex:%d", cpgid, ifindex);
  return 0;
}

static struct bpf_object *
open_bpf_object(const char *file, int ifindex)
{
  int err;
  struct bpf_object *obj;
  struct bpf_map *map;
  struct bpf_program *prog, *any_prog = NULL;

  obj = bpf_object__open(file);
  if (IS_ERR_OR_NULL(obj)) {
    err = -PTR_ERR(obj);
    log_error("bpfhelper: opening file(%s) failed: %s", file, strerror(-err));
    return NULL;
  }

  bpf_object__for_each_program(prog, obj) {
    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
    bpf_program__set_ifindex(prog, ifindex);
    if (!any_prog)
      any_prog = prog;
  }

  bpf_object__for_each_map(map, obj) {
    bpf_map__set_ifindex(map, ifindex);
  }

  if (!any_prog) {
    log_error("bpfhelper: file %s contains no programs", file);
    return NULL;
  }

  return obj;
}

static int
reuse_maps_from_pinned_path(struct bpf_object *obj, const char *path)
{
  struct bpf_map *map;

  if (!obj)
    return -ENOENT;

  if (!path)
    return -EINVAL;

  bpf_object__for_each_map(map, obj) {
    int len, err;
    int pinned_map_fd;
    char buf[PINPATH_MAX_LEN];

    len = snprintf(buf, PINPATH_MAX_LEN, "%s/%s", path, bpf_map__name(map));
    if (len < 0 || len >= PINPATH_MAX_LEN) {
      return -EINVAL;
    }

    pinned_map_fd = bpf_obj_get(buf);
    if (pinned_map_fd < 0)
      return pinned_map_fd;

    err = bpf_map__reuse_fd(map, pinned_map_fd);
    if (err)
      return err;
  }

  return 0;
}

struct bpf_object *
load_bpf_object_file_common(const char *file, int ifindex, int reuse_maps, const char *pin_dir)
{
  int err;
  struct bpf_object *obj;

  obj = open_bpf_object(file, ifindex);
  if (!obj) {
    log_error("bpfhelper: failed to open object %s", file);
    return NULL;
  }

  if (reuse_maps) {
    err = reuse_maps_from_pinned_path(obj, pin_dir);
    if (err) {
      log_error("bpfhelper: failed to reuse maps for object %s, pin %s", file, pin_dir);
      return NULL;
    }
  }

  err = bpf_object__load(obj);
  if (err) {
    log_error("bpfhelper: loading BPF-OBJ file(%s) : %s", file, strerror(-err));
    return NULL;
  }

  return obj;
}

struct bpf_object *
libbpf_xdp_attach(struct libbpf_cfg *cfg)
{
  struct bpf_program *bpf_prog = NULL;
  struct bpf_program *p = NULL;
  struct bpf_object *bpf_obj;
  int prog_fd = -1;
  int err;

  bpf_obj = load_bpf_object_file_common(cfg->filename, 0, cfg->reuse_maps, cfg->pin_dir);
  if (!bpf_obj) {
    log_error("bpfhelper: loading file: %s failed", cfg->filename);
    return NULL;
  }

  if (cfg->progsec[0]) {
    bpf_object__for_each_program(p, bpf_obj) {
      if ((strcmp(bpf_program__section_name(p), cfg->progsec) == 0)) {
        bpf_prog = p;
        break;
      }
    }
  } else {
    bpf_prog = bpf_object__next_program(bpf_obj, NULL);
  }

  if (!bpf_prog) {
    log_error("bpfhelper: couldn't find a program in ELF section %s", cfg->progsec);
    return NULL;
  }

  strncpy(cfg->progsec, bpf_program__section_name(bpf_prog), sizeof(cfg->progsec));

  prog_fd = bpf_program__fd(bpf_prog);
  if (prog_fd <= 0) {
    log_error("bpfhelper: bpf_program__fd failed");
    return NULL;
  }

  err = xdp_link_attach(cfg->ifindex, cfg->bpf_flags, prog_fd);
  if (err) {
    log_error("bpfhelper: link_attach failed");
    return NULL;
  }

  return bpf_obj;
}
