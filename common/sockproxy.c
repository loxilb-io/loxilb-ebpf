/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <fcntl.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <netdb.h>
#include <poll.h>
#include <bpf.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include "log.h"
#include "sockproxy.h"
#include "common_pdi.h"
#include "llb_dpapi.h"

#define SP_MAX_ACCEPT_QSZ 2048
#define SP_MAX_POLLFD_QSZ 8192
#define SP_MAX_NEWFD_QSZ 1024
#define SP_MAX_FDPAIR_SZ 65535
#define SP_ACCEPT_TIMEO_MS 500
#define SP_FD_TIMEO_MS 500

struct proxy_map_ent {
  struct proxy_ent key;
  struct proxy_val val;
  struct proxy_map_ent *next;
};

struct proxy_struct {
  pthread_rwlock_t lock;
  pthread_t proxy_thr;
  struct proxy_map_ent *head;
  int (*sockmap_cb)(struct llb_sockmap_key *key, int fd, int doadd);
};

#define PROXY_LOCK()    pthread_rwlock_wrlock(&proxy_struct->lock)
#define PROXY_RDLOCK()  pthread_rwlock_rdlock(&proxy_struct->lock)
#define PROXY_UNLOCK()  pthread_rwlock_unlock(&proxy_struct->lock)

struct proxy_struct *proxy_struct;

static int
proxy_skmap_key_from_fd(int fd, struct llb_sockmap_key *skmap_key)
{
  struct sockaddr_in sin_addr;
  socklen_t sin_len;

  sin_len = sizeof(struct sockaddr);
  if (getsockname(fd, (struct sockaddr*)&sin_addr, &sin_len)) {
    return -1;
  }
  skmap_key->sip = sin_addr.sin_addr.s_addr;
  skmap_key->sport = sin_addr.sin_port << 16;

  if (getpeername(fd, (struct sockaddr*)&sin_addr, &sin_len)) {
    return -1;
  }
  skmap_key->dip = sin_addr.sin_addr.s_addr;
  skmap_key->dport = sin_addr.sin_port << 16;

  return 0;
}

static int
proxy_sock_setup(int fd, uint32_t server, uint16_t port)
{
  struct sockaddr_in addr;
  int rc;
  int on = 1;
  int flags;

  rc = setsockopt(fd, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(on));
  if (rc < 0) {
    close(fd);
    return -1;
  }

  flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    flags = 0;
  }

  rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (rc == -1) {
    assert(0);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = port;
  addr.sin_addr.s_addr = server;
  rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (rc < 0) {
    perror("");
    close(fd);
    return -1; 
  }

  rc = listen(fd, 32);
  if (rc < 0) {
    perror("");
    close(fd);
    return -1;
  }

  log_info("sock-proxy setup done");
  return 0;
}

static void *
proxy_looper(void *arg)
{
  struct llb_sockmap_key key = { 0 };
  struct llb_sockmap_key rkey = { 0 };
  int listen_sd = -1, new_sd = -1;
  int ep_cfd = -1;
  int n_new = 0;
  int accept_to;
  int rc, timeo;
  int n_afds = 0, curr_sz = 0, i, j;
  int n_fds = 0;
  struct pollfd afds[SP_MAX_ACCEPT_QSZ];
  struct pollfd fds[SP_MAX_POLLFD_QSZ];
  int new_afds[SP_MAX_NEWFD_QSZ];
  int fd_pairs[SP_MAX_FDPAIR_SZ];
  struct sockaddr_in epaddr;
  struct proxy_map_ent *node;
  uint32_t epip;
  uint16_t epport;

  accept_to = SP_ACCEPT_TIMEO_MS;
  timeo = SP_FD_TIMEO_MS;

  memset(fd_pairs, 0 , sizeof(fd_pairs));
  memset(afds, 0 , sizeof(afds));
  memset(fds, 0 , sizeof(fds));

  while (1) {
    n_new = 0;
    memset(new_afds, 0, sizeof(new_afds));

    PROXY_LOCK();
    node = proxy_struct->head;
    while (node) {
      if (node->val.main_fd <= 0) {
        listen_sd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_sd > 0) {
          proxy_sock_setup(listen_sd, node->key.xip, node->key.xport);
          if (n_new < SP_MAX_NEWFD_QSZ-1) {
            new_afds[n_new++] = listen_sd;
            node->val.main_fd = listen_sd;
          } else {
            break;
          }
        }
      }
      node = node->next;
    }
    PROXY_UNLOCK();

    for (i = 0; i < n_new; i++) {
      if (n_afds >= SP_MAX_ACCEPT_QSZ-1) {
        log_error("No space in accept poll_fd");
        break;
      }
      afds[n_afds].fd = new_afds[i];
      afds[n_afds].events = POLLIN|POLLRDHUP;
      log_debug("n_afd %d fd %d", afds[n_afds].fd, n_afds);
      n_afds++;
    }

    rc = poll(afds, n_afds, accept_to);
    if (rc < 0) {
      perror("");
      assert(0);
      continue;
    }

    curr_sz = n_afds;
    for (i = 0; i < curr_sz; i++) {
      if (afds[i].revents == POLLIN) {
        new_sd = accept(listen_sd, NULL, NULL);
        if (new_sd < 0) {
          if (errno != EWOULDBLOCK) {
            log_error("accept failed");
          }
          continue;
        }
        if (proxy_skmap_key_from_fd(new_sd, &key)) {
          log_error("cant get skmap key from fd");
          close(new_sd);
          continue;
        }

        log_debug("accept() from %s:%u --> %s:%u",
               inet_ntoa(*(struct in_addr *)(&key.sip)), key.sport >> 16,
               inet_ntoa(*(struct in_addr *)&key.dip), key.dport >> 16);

        if (sockproxy_find_endpoint(key.sip, key.sport >> 16, &epip, &epport)) {
          log_error("No EP for %s:%u --> %s:%u",
                 inet_ntoa(*(struct in_addr *)(&key.sip)), key.sport >> 16,
                 inet_ntoa(*(struct in_addr *)&key.dip), key.dport >> 16);
          close(new_sd);
          continue;
        }
        log_debug("EP for %s:%u --> %s:%u ## %s:%u",
               inet_ntoa(*(struct in_addr *)(&key.sip)), key.sport >> 16,
               inet_ntoa(*(struct in_addr *)&key.dip), key.dport >> 16,
               inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));

        memset(&epaddr, 0, sizeof(epaddr));
        epaddr.sin_family = AF_INET;
        epaddr.sin_port = epport;
        epaddr.sin_addr.s_addr = epip;

        ep_cfd = socket(AF_INET, SOCK_STREAM, 0);
        if (ep_cfd < 0) {
          close(new_sd);
          continue;
        }

        if (connect(ep_cfd, (struct sockaddr*)&epaddr, sizeof(epaddr)) != 0) {
          log_error("connect failed %s:%u", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
          close(new_sd);
          continue;
        }

        if (proxy_skmap_key_from_fd(ep_cfd, &rkey)) {
          log_error("cant get skmap key from ep_cfd");
          close(new_sd);
          close(ep_cfd);
          continue;
        }

        log_debug("connect() %s:%u --> %s:%u",
               inet_ntoa(*(struct in_addr *)(&rkey.sip)), rkey.sport >> 16,
               inet_ntoa(*(struct in_addr *)&rkey.dip), rkey.dport >> 16);

        proxy_struct->sockmap_cb(&rkey, new_sd, 1);
        proxy_struct->sockmap_cb(&key, ep_cfd, 1);

        fd_pairs[new_sd] = ep_cfd;
        fds[n_fds].fd = new_sd;
        fds[n_fds].events = POLLRDHUP;
        n_fds++;
      } else if (afds[i].revents & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL)) {
        close(afds[i].fd);
        afds[i].fd = -1;
      }
    }

    rc = poll(fds, n_fds, timeo);
    if (rc < 0) {
      continue;
    }

    curr_sz = n_fds;
    for (i = 0; i < curr_sz; i++) {
      if (fds[i].revents & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL)) {
        log_debug("HUP for sock %d", fds[i].fd);
        if (fds[i].fd > 0 && fds[i].fd < SP_MAX_FDPAIR_SZ && fd_pairs[fds[i].fd] > 0) {
          close(fd_pairs[fds[i].fd]);
          fd_pairs[fds[i].fd] = -1;
        }
        close(fds[i].fd);
        fds[i].fd = -1;
      }
    }

    for (i = 0; i < n_fds; i++) {
      if (fds[i].fd == -1) {
        for(j = i; j < n_fds; j++) {
          fds[j].fd = fds[j+1].fd;
        }
        i--;
        n_fds--;
      }
    }


    for (i = 0; i < n_afds; i++) {
      if (afds[i].fd == -1) {
        for(j = i; j < n_afds; j++) {
          afds[j].fd = afds[j+1].fd;
        }
        i--;
        n_afds--;
      }
    }
    //log_debug("nfds %d nafds %d", n_fds, n_afds);
  }
}

static bool
cmp_proxy_ent(struct proxy_ent *e1, struct proxy_ent *e2)
{
  if (e1->xip == e2->xip &&
      e1->xport == e2->xport) {
    return true;
  }
  return false;
}

static bool
cmp_proxy_val(struct proxy_val *v1, struct proxy_val *v2)
{
  int i;
  for (i = 0; i < MAX_PROXY_EP; i++) {
    if (!cmp_proxy_ent(&v1->eps[i], &v2->eps[i])) {
      return false;
    }
  }
  return true;
}

int
sockproxy_find_endpoint(uint32_t xip, uint16_t xport, uint32_t *epip, uint16_t *epport)
{
  int sel = 0;
  struct proxy_ent ent = { 0 };
  struct proxy_map_ent *node = proxy_struct->head;
   
  ent.xip = xip;
  ent.xport = xport;

  PROXY_LOCK();

  while (node) {

    if (cmp_proxy_ent(&node->key, &ent)) {
      if (!node->val.n_eps) {
        PROXY_UNLOCK();
        return -1;
      }
      sel = node->val.ep_sel % node->val.n_eps;
      if (sel >= MAX_PROXY_EP) break;
      *epip = node->val.eps[sel].xip; 
      *epport = node->val.eps[sel].xport; 
      //printf("epid 0x%x: 0x%u\n", node->val.eps[sel].xip, node->val.eps[sel].xport);
      PROXY_UNLOCK();
      return 0;
    }
    node = node->next;
  }

  PROXY_UNLOCK();
  return -1;
}

static int
sockproxy_delete_entry__(struct proxy_ent *ent)
{
  struct proxy_map_ent *prev = NULL;
  struct proxy_map_ent *node;

  node = proxy_struct->head;

  while (node) {

    if (cmp_proxy_ent(&node->key, ent)) {
      break;
    }
    prev = node;
    node = node->next;
  }

  if (node) {
    if (prev) {
      prev->next = node->next;
    } else {
      proxy_struct->head = node->next;
    }

    if (node->val.main_fd > 0) {
      close(node->val.main_fd);
    }
    free(node);
  } else {
    return -EINVAL;
  }

  log_info("sockproxy : %s:%u deleted", inet_ntoa(*(struct in_addr *)&ent->xip), ntohs(ent->xport));

  return 0;
}

int
sockproxy_add_entry(struct proxy_ent *new_ent, struct proxy_val *val)
{
  struct proxy_map_ent *node;
  struct proxy_map_ent *ent = proxy_struct->head;

  PROXY_LOCK();

  while (ent) {

    if (cmp_proxy_ent(&ent->key, new_ent) &&  cmp_proxy_val(&ent->val, val)) {
      PROXY_UNLOCK();
      log_info("sockproxy : %s:%u exists", inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
      return -EEXIST;
    }
    ent = ent->next;
  }

  node = calloc(sizeof(*node), 1);
  if (node == NULL) {
    PROXY_UNLOCK();
    return -ENOMEM;
  }

  memcpy(&node->key, new_ent, sizeof(*ent));

  val->main_fd = -1;
  memcpy(&node->val, val, sizeof(*val));

  node->next = proxy_struct->head;
  proxy_struct->head = node;

  PROXY_UNLOCK();

  log_info("sockproxy : %s:%u added", inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
  
  return 0;
}

int
sockproxy_delete_entry(struct proxy_ent *ent)
{
  int ret = 0;
  PROXY_LOCK();
  ret = sockproxy_delete_entry__(ent);
  PROXY_UNLOCK();

  return ret;
}

void
sockproxy_dump_entry(void)
{
  struct proxy_map_ent *node = proxy_struct->head;
  int i = 0;

  log_info("sockproxy dump:");

  while (node) {
    log_info("entry (%d) %s:%u ", i, inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
    node = node->next;
    i++;
  }
}

int
sockproxy_selftests()
{
  struct proxy_ent key = { 0 };
  struct proxy_val val = { 0 };
  struct proxy_ent key2 = { 0 };
  int n = 0;

  key.xip = inet_addr("172.17.0.2");
  key.xport = htons(22222);

  val.eps[0].xip = inet_addr("127.0.0.1");
  val.eps[0].xport = htons(33333);
  val.n_eps = 1;
  sockproxy_add_entry(&key, &val);

  key2.xip = inet_addr("127.0.0.2");
  key2.xport = htons(22222);
  sockproxy_add_entry(&key2, &val);
  sockproxy_dump_entry();

  sockproxy_delete_entry(&key2);
  sockproxy_dump_entry();

  while(0) {
    sleep(1);
    n++;
    if (n > 10) {
      sockproxy_delete_entry(&key);
    }
  }

  return 0;
}

int
sockproxy_main(sockmap_cb_t sockmap_cb)
{
  proxy_struct = calloc(sizeof(struct proxy_struct), 1);
  if (proxy_struct == NULL) {
    assert(0);
  }
  proxy_struct->sockmap_cb = sockmap_cb;
  pthread_create(&proxy_struct->proxy_thr, NULL, proxy_looper, NULL);

  return 0;
}
