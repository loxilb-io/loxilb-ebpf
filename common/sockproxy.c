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
#include <linux/tls.h>
#include <linux/tcp.h>
#include "log.h"
#include "common_pdi.h"
#include "llb_dpapi.h"
#include "notify.h"
#include "sockproxy.h"
#include "ngap_helper.h"

#define SP_MAX_ACCEPT_QSZ 2048
#define SP_MAX_POLLFD_QSZ 8192
#define SP_MAX_NEWFD_QSZ 1024
#define SP_MAX_FDPAIR_SZ 65535
#define SP_ACCEPT_TIMEO_MS 500
#define SP_FD_TIMEO_MS 500
#define SP_MSG_BUSY_THRESHOLD 1
#define SP_SOCK_MSG_LEN 8192
#define PROXY_NUM_BURST_RX 1024

typedef struct proxy_map_ent {
  struct proxy_ent key;
  struct proxy_val val;
  struct proxy_map_ent *next;
} proxy_map_ent_t;

typedef struct proxy_struct {
  pthread_rwlock_t lock;
  pthread_t pthr;
  proxy_map_ent_t *head;
  sockmap_cb_t sockmap_cb;
  void *ns;
} proxy_struct_t;

#define PROXY_LOCK()    pthread_rwlock_wrlock(&proxy_struct->lock)
#define PROXY_RDLOCK()  pthread_rwlock_rdlock(&proxy_struct->lock)
#define PROXY_UNLOCK()  pthread_rwlock_unlock(&proxy_struct->lock)

static proxy_struct_t *proxy_struct;

static bool
cmp_proxy_ent(proxy_ent_t *e1, proxy_ent_t *e2)
{
  if (e1->xip == e2->xip &&
      e1->xport == e2->xport &&
      e1->protocol == e2->protocol) {
    return true;
  }
  return false;
}

static bool
cmp_proxy_val(proxy_val_t *v1, proxy_val_t *v2)
{
  int i;
  for (i = 0; i < MAX_PROXY_EP; i++) {
    if (!cmp_proxy_ent(&v1->eps[i], &v2->eps[i])) {
      return false;
    }
  }
  return true;
}

static int
proxy_add_xmitcache(proxy_fd_ent_t *ent, uint8_t *cache, size_t len)
{
  struct proxy_cache *new;
  struct proxy_cache *curr = ent->cache_head;
  struct proxy_cache **prev = &ent->cache_head;

  new  = calloc(1, sizeof(struct proxy_cache)+len);
  assert(new);
  new->cache = new->data;
  memcpy(new->cache, cache, len);
  new->off = 0;;
  new->len = len;

  while (curr) {
    prev = &curr->next;
    curr = curr->next;
  }

  if (prev) {
    *prev = new;
  }

  return 0;
}

static void
proxy_destroy_xmitcache(proxy_fd_ent_t *ent)
{
  struct proxy_cache *curr = ent->cache_head;
  struct proxy_cache *next;

  while (curr) {
    next = curr->next;
    free(curr);
    curr = next;
  }
  ent->cache_head = NULL;
}

static void __attribute__((unused))
proxy_list_xmitcache(proxy_fd_ent_t *ent)
{
  int i = 0;
  struct proxy_cache *curr = ent->cache_head;

  while (curr) {
    log_info("%d:curr %p\n", i, curr);
    curr = curr->next;
    i++;
  }
}

static int
proxy_xmit_cache(proxy_fd_ent_t *ent)
{
  struct proxy_cache *curr = ent->cache_head;
  struct proxy_cache *tmp = NULL;
  int n = 0;

  while (curr) {
    n = send(ent->fd, (uint8_t *)(curr->cache) + curr->off, curr->len, MSG_DONTWAIT|MSG_NOSIGNAL);
    if (n != curr->len) {
      if (n >= 0) {
        /* errno == EAGAIN || errno == EWOULDBLOCK */
        curr->off += n;
        curr->len -= n;
        continue;
      } else /*if (n < 0)*/ {
        //log_debug("Failed to send cache");
        return -1;
      }
    }

    tmp = curr;

    curr = curr->next;
    ent->cache_head = curr;

    if (tmp)
      free(tmp);

  }
  ent->cache_head = NULL;
  return 0;
}

static int
proxy_try_epxmit(proxy_fd_ent_t *ent, void *msg, size_t len, int sel)
{
  int n;

  n = proxy_xmit_cache(ent);
  if (n < 0) {
    proxy_add_xmitcache(ent, msg, len);
    return 0;
  }

  n = send(ent->rfd[sel], msg, len, MSG_DONTWAIT|MSG_NOSIGNAL);
  if (n != len) {
    if (n >= 0) {
      //log_debug("Partial send %d", n);
      proxy_add_xmitcache(ent, (uint8_t *)(msg) + n, len - n);
      return 0;
    } else /*if (n < 0)*/ {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        proxy_add_xmitcache(ent, msg, len);
        return 0;
      }
      //log_debug("Failed to send");
      return -1;
    }
  }

  return 0;
}

static int
proxy_skmap_key_from_fd(int fd, struct llb_sockmap_key *skmap_key, int *protocol)
{
  struct sockaddr_in sin_addr;
  socklen_t sin_len;
  socklen_t optsize = sizeof(int);

  if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, protocol, &optsize)) {
    return -1;
  }

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

#ifdef HAVE_SOCKMAP_KTLS
static int
proxy_sock_init_ktls(int fd)
{
  int so_buf = 6553500;
  int err;
  struct tls12_crypto_info_aes_gcm_128 tls_tx = { 0 };
  struct tls12_crypto_info_aes_gcm_128 tls_rx = { 0 };

  tls_tx.info.version = TLS_1_2_VERSION;
  tls_tx.info.cipher_type = TLS_CIPHER_AES_GCM_128;

  tls_rx.info.version = TLS_1_2_VERSION;
  tls_rx.info.cipher_type = TLS_CIPHER_AES_GCM_128;

  err = setsockopt(fd, 6, TCP_ULP, "tls", sizeof("tls"));
  if (err) {
    log_error("setsockopt: TCP_ULP failed error %d\n", err);
    return -EINVAL;
  }

  err = setsockopt(fd, SOL_TLS, TLS_TX, (void *)&tls_tx, sizeof(tls_tx));
  if (err) {
    log_error("setsockopt: TLS_TX failed error %d\n", err);
    return -EINVAL;
  }

  err = setsockopt(fd, SOL_TLS, TLS_RX, (void *)&tls_rx, sizeof(tls_rx));
  if (err) {
    log_error("setsockopt: TLS_RX failed error %d\n", err);
    return -EINVAL;
  }

  err = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &so_buf, sizeof(so_buf));
  if (err) {
    log_error("setsockopt: SO_SNDBUF failed error %d\n", err);
    return -EINVAL;
  }

  err = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &so_buf, sizeof(so_buf));
  if (err) {
    log_error("setsockopt: SO_RCVBUF failed error %d\n", err);
    return -EINVAL;
  }

  return 0;
}
#endif

static void
proxy_sock_setnb(int fd)
{
  int rc, flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    flags = 0;
  }

  rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (rc == -1) {
    assert(0);
  }
}

static int
proxy_server_setup(int fd, uint32_t server, uint16_t port, uint8_t protocol)
{
  struct sockaddr_in addr;
  int rc, on = 1, flags;

#if 0
  struct sctp_initmsg im;
  if (protocol == IPPROTO_SCTP) {
    memset(&im, 0, sizeof(im));
    im.sinit_num_ostreams = 1;
    im.sinit_max_instreams = 1;
    im.sinit_max_attempts = 4;
    rc = setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &im, sizeof(im));
    if (rc < 0) {
      close(fd);
      return -1;
    }
  }
#endif

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
    perror("bind");
    close(fd);
    return -1; 
  }

  rc = listen(fd, 32);
  if (rc < 0) {
    perror("listen");
    close(fd);
    return -1;
  }

  log_info("sock-proxy setup done");
  return 0;
}

static int
proxy_setup_ep_connect(uint32_t epip, uint16_t epport, uint8_t protocol)
{
  int fd, rc;
  struct sockaddr_in epaddr;
  fd_set wrdy, errors;
  struct timeval tv = { .tv_sec  = 0,
                        .tv_usec = 500000
                      };

  memset(&epaddr, 0, sizeof(epaddr));
  epaddr.sin_family = AF_INET;
  epaddr.sin_port = epport;
  epaddr.sin_addr.s_addr = epip;

  fd = socket(AF_INET, SOCK_STREAM, protocol);
  if (fd < 0) {
    return -1;
  }

  proxy_sock_setnb(fd);

  if (connect(fd, (struct sockaddr*)&epaddr, sizeof(epaddr)) < 0) {
    if (errno != EINPROGRESS) {
      log_error("connect failed %s:%u", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      close(fd);
      return -1;
    }

    FD_ZERO(&wrdy);
    FD_SET(fd, &wrdy);

    FD_ZERO(&errors);
    FD_SET(fd, &errors);

    rc = select(fd + 1, NULL, &wrdy, &errors, &tv);
    if (rc <= 0) {
      log_error("connect select %s:%u(%s)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport), strerror(errno));
      close(fd);
      return -1;
    }

    if (rc == 0) {
      log_error("connect %s:%u(timedout)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      close(fd);
      return -1;
    }

    if (FD_ISSET(fd, &errors)) {
      log_error("connect %s:%u(errors)", inet_ntoa(*(struct in_addr *)(&epip)), ntohs(epport));
      close(fd);
      return -1;
    }

    return fd;
  }

  return fd;
}

static int
proxy_setup_ep(uint32_t xip, uint16_t xport, uint8_t protocol,
               int *fds, int *fdsz, int *seltype)
{
  int sel = 0;
  uint32_t epip;
  uint16_t epport;
  uint8_t epprotocol;
  proxy_ent_t ent = { 0 };
  proxy_map_ent_t *node = proxy_struct->head;

  ent.xip = xip;
  ent.xport = xport;
  ent.protocol = protocol;

  PROXY_LOCK();

  while (node) {

    if (cmp_proxy_ent(&node->key, &ent)) {
      if (!node->val.n_eps || node->val.n_eps >= MAX_PROXY_EP) {
        PROXY_UNLOCK();
        return -1;
      }

      if (node->val.proxy_mode == PROXY_MODE_DFL) {
        sel = node->val.ep_sel % node->val.n_eps;
        if (sel >= MAX_PROXY_EP) break;
        epip = node->val.eps[sel].xip;
        epport = node->val.eps[sel].xport;
        epprotocol = node->val.eps[sel].protocol;
        node->val.ep_sel++;
        PROXY_UNLOCK();
        fds[0] = proxy_setup_ep_connect(epip, epport, (uint8_t)epprotocol);
        if (fds[0] < 0) {
          return -1;
        }

        *seltype = 0;
        *fdsz = 1;

        return 0;
      } else if (node->val.proxy_mode == PROXY_MODE_ALL) {
        int ep = 0;

        for (ep = 0; ep < node->val.n_eps; ep++) {
          epip = node->val.eps[ep].xip;
          epport = node->val.eps[ep].xport;
          epprotocol = node->val.eps[ep].protocol;
          fds[sel] = proxy_setup_ep_connect(epip, epport, (uint8_t)epprotocol);
          if (fds[sel] > 0) {
            sel++;
          }
        }

        PROXY_UNLOCK();
        if (sel) {
          *fdsz = sel;
          *seltype = node->val.select;
          return 0;
        }
        return -1;
      }
    }
    node = node->next;
  }

  PROXY_UNLOCK();
  return -1;
}

static int
proxy_sock_init(uint32_t IP, uint16_t port, uint8_t protocol)
{
  int listen_sd;

  switch (protocol) {
  case IPPROTO_TCP:
  case IPPROTO_SCTP:
    listen_sd = socket(AF_INET, SOCK_STREAM, protocol);
    break;
  default:
    return -1;
  }

  if (listen_sd > 0) {
    if (!proxy_server_setup(listen_sd, IP, port, protocol)) {
      return listen_sd;
    }
    close(listen_sd); 
  }

  return -1;
}

static void *
proxy_run(void *arg)
{
  notify_run(proxy_struct->ns);
  return NULL;
}

int
proxy_find_ep(uint32_t xip, uint16_t xport, uint8_t protocol, 
              uint32_t *epip, uint16_t *epport, uint8_t *epprotocol)
{
  int sel = 0;
  proxy_ent_t ent = { 0 };
  proxy_map_ent_t *node = proxy_struct->head;
   
  ent.xip = xip;
  ent.xport = xport;
  ent.protocol = protocol;

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
      *epprotocol = node->val.eps[sel].protocol;
      node->val.ep_sel++;
      //log_debug("epid 0x%x: 0x%u\n", node->val.eps[sel].xip, node->val.eps[sel].xport);
      PROXY_UNLOCK();
      return 0;
    }
    node = node->next;
  }

  PROXY_UNLOCK();
  return -1;
}

static int
proxy_delete_entry__(proxy_ent_t *ent)
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
      notify_delete_ent(proxy_struct->ns, node->val.main_fd);
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
proxy_add_entry(proxy_ent_t *new_ent, proxy_val_t *val)
{
  int lsd;
  proxy_map_ent_t *node;
  proxy_map_ent_t *ent = proxy_struct->head;
  proxy_fd_ent_t *fd_ctx;

  PROXY_LOCK();

  while (ent) {
    if (cmp_proxy_ent(&ent->key, new_ent) &&
        cmp_proxy_val(&ent->val, val)) {
      PROXY_UNLOCK();
      log_info("sockproxy : %s:%u exists",
        inet_ntoa(*(struct in_addr *)&ent->key.xip), ntohs(ent->key.xport));
      return -EEXIST;
    }
    ent = ent->next;
  }

  node = calloc(1, sizeof(*node));
  if (node == NULL) {
    PROXY_UNLOCK();
    return -ENOMEM;
  }

  memcpy(&node->key, new_ent, sizeof(*ent));

  val->main_fd = -1;
  memcpy(&node->val, val, sizeof(*val));

  lsd = proxy_sock_init(node->key.xip, node->key.xport, node->key.protocol);
  if (lsd <= 0) {
    log_error("sockproxy : %s:%u sock-init failed",
        inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
    PROXY_UNLOCK();
    return -1; 
  }

  node->val.main_fd = lsd;
  fd_ctx = calloc(1, sizeof(*fd_ctx));
  assert(fd_ctx);

  fd_ctx->stype = PROXY_SOCK_LISTEN;
  fd_ctx->fd = lsd;
  if (notify_add_ent(proxy_struct->ns, lsd, NOTI_TYPE_IN|NOTI_TYPE_HUP, fd_ctx)) {
    log_error("sockproxy : %s:%u notify failed",
        inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
    PROXY_UNLOCK();
    close(lsd);
    return -1; 
  }

  node->next = proxy_struct->head;
  proxy_struct->head = node;

  PROXY_UNLOCK();

  log_info("sockproxy : %s:%u added", inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
  
  return 0;
}

int
proxy_delete_entry(proxy_ent_t *ent)
{
  int ret = 0;
  PROXY_LOCK();
  ret = proxy_delete_entry__(ent);
  PROXY_UNLOCK();

  return ret;
}

void
proxy_dump_entry(void)
{
  proxy_map_ent_t *node = proxy_struct->head;
  int i = 0;

  log_info("sockproxy dump:");

  while (node) {
    log_info("entry (%d) %s:%u ", i, inet_ntoa(*(struct in_addr *)&node->key.xip), ntohs(node->key.xport));
    node = node->next;
    i++;
  }
}

int
proxy_selftests()
{
  proxy_ent_t key = { 0 };
  proxy_val_t val = { 0 };
  proxy_ent_t key2 = { 0 };
  int n = 0;

  key.xip = inet_addr("172.17.0.2");
  key.xport = htons(22222);

  val.eps[0].xip = inet_addr("127.0.0.1");
  val.eps[0].xport = htons(33333);
  val.n_eps = 1;
  proxy_add_entry(&key, &val);

  key2.xip = inet_addr("127.0.0.2");
  key2.xport = htons(22222);
  proxy_add_entry(&key2, &val);
  proxy_dump_entry();

  proxy_delete_entry(&key2);
  proxy_dump_entry();

  while(0) {
    sleep(1);
    n++;
    if (n > 10) {
      proxy_delete_entry(&key);
    }
  }

  return 0;
}

static void
proxy_pdestroy(void *priv)
{
  int i = 0;
  proxy_fd_ent_t *pfe = priv;
  if (pfe) {
    for (i = 0; i < pfe->n_rfd; i++) {
      if (pfe->rfd[i] > 0) {
        log_debug("proxy destroy: rfd %d", pfe->rfd[i]);
        close(pfe->rfd[i]);
        pfe->rfd[i] = -1;
      }
    }
    /* Redundant */
    if (pfe->fd > 0) {
      log_debug("proxy destroy: fd %d", pfe->fd);
      close(pfe->fd);
      pfe->fd = -1;
    }
    proxy_destroy_xmitcache(pfe); 
    free(pfe);
  }
}

static void
proxy_log(const char *str, struct llb_sockmap_key *key)
{
  char ab1[INET6_ADDRSTRLEN];
  char ab2[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET, (struct in_addr *)&key->dip, ab1, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, (struct in_addr *)&key->sip, ab2, INET_ADDRSTRLEN);
  log_debug("%s %s:%u -> %s:%u", str,
            ab1, ntohs((key->dport >> 16)), ab2, ntohs(key->sport >> 16));
}

static void
proxy_destroy_eps(int sfd, int *ep_cfds, int n_eps)
{
  int i = 0;
  for (i = 0; i < n_eps; i++) {
    if (ep_cfds[i] > 0) {
      notify_delete_ent(proxy_struct->ns, ep_cfds[i]);
      close(ep_cfds[i]);
      ep_cfds[i] = -1;
    }
    if (sfd > 0) {
      notify_delete_ent(proxy_struct->ns, sfd);
      close(sfd);
    }
  }
}

static int
proxy_notifer(int fd, notify_type_t type, void *priv)
{
  struct llb_sockmap_key key = { 0 };
  struct llb_sockmap_key rkey = { 0 };
  int ep_cfds[MAX_PROXY_EP] = { 0 };
  uint8_t rcvbuf[SP_SOCK_MSG_LEN];
  int j, n_eps = 0, seltype = 0;
  int epprotocol, protocol;
  proxy_fd_ent_t *pfe = priv;
  proxy_fd_ent_t *npfe1 = NULL;
  proxy_fd_ent_t *npfe2 = NULL;

  //log_debug("Fd = %d type 0x%x", fd, type);
restart:
  while (type) {
    if (type & NOTI_TYPE_IN) {
      type &= ~NOTI_TYPE_IN;
      if (pfe->stype == PROXY_SOCK_LISTEN) {
        int new_sd = accept(fd, NULL, NULL);
        if (new_sd < 0) {
          if (errno != EWOULDBLOCK) {
            log_error("accept failed\n");
          }
          continue;
        }
        proxy_sock_setnb(new_sd);

        if (proxy_skmap_key_from_fd(new_sd, &key, &protocol)) {
          log_error("skmap key from fd failed");
          close(new_sd);
          continue;
        }

        proxy_log("new accept()", &key);

        n_eps = 0;
        memset(ep_cfds, 0, sizeof(ep_cfds));

        if (proxy_setup_ep(key.sip, key.sport >> 16, (uint8_t)(protocol),
                           ep_cfds, &n_eps, &seltype)) {
          proxy_log("no endpoint", &key);
          close(new_sd);
          continue;
        }

        for (j = 0; j < n_eps; j++) {
          int ep_cfd = ep_cfds[j];
          if (ep_cfd < 0) {
            assert(0);
          }

          if (proxy_skmap_key_from_fd(ep_cfd, &rkey, &epprotocol)) {
            log_error("skmap key from ep_cfd failed");
            proxy_destroy_eps(new_sd, ep_cfds, n_eps);
            goto restart;
          }

          proxy_log("connected", &rkey);

          if (protocol == IPPROTO_TCP && epprotocol == IPPROTO_TCP && n_eps == 1) {
            if (proxy_struct->sockmap_cb) {
              proxy_struct->sockmap_cb(&rkey, new_sd, 1);
              proxy_struct->sockmap_cb(&key, ep_cfd, 1);
            }
#ifdef HAVE_SOCKMAP_KTLS
            if (proxy_sock_init_ktls(new_sd)) {
              log_error("tls failed");
              proxy_destroy_eps(new_sd, ep_cfds, n_eps);
              goto restart;
            }
#endif
          }

          if (j == 0) {
            npfe1 = calloc(1, sizeof(*npfe1));
            assert(npfe1);
            npfe1->stype = PROXY_SOCK_ACTIVE;
            npfe1->fd = new_sd;
            npfe1->seltype = seltype;
          }

          npfe2 = calloc(1, sizeof(*npfe2));
          assert(npfe2);
          npfe2->stype = PROXY_SOCK_ACTIVE;
          npfe2->fd = ep_cfd; 
          npfe2->rfd[0] = new_sd; 
          npfe2->seltype = seltype;
          npfe2->odir = 1;
          npfe2->n_rfd++;

          if (notify_add_ent(proxy_struct->ns, ep_cfd,
               NOTI_TYPE_IN|NOTI_TYPE_OUT|NOTI_TYPE_HUP, npfe2))  {
             free(npfe2);
             proxy_destroy_eps(new_sd, ep_cfds, n_eps);
             log_error("failed to add epcfd %d", ep_cfd);
             goto restart;
          }

          npfe1->rfd[npfe1->n_rfd] = ep_cfd;
          npfe1->n_rfd++;

          /* Last endpoint entry */
          if (j == n_eps - 1) {
            if (notify_add_ent(proxy_struct->ns, new_sd,
                NOTI_TYPE_IN|NOTI_TYPE_OUT|NOTI_TYPE_HUP, npfe1))  {
              free(npfe1);
              proxy_destroy_eps(new_sd, ep_cfds, n_eps);
              log_error("failed to add new_sd %d", new_sd);
              goto restart;
            }
          }
        }
      } else if (pfe->stype == PROXY_SOCK_ACTIVE) {
        for (j = 0; j < PROXY_NUM_BURST_RX; j++) {
          int rc = recv(fd, rcvbuf, SP_SOCK_MSG_LEN, MSG_DONTWAIT);
          if (rc < 0) {
            if (errno != EWOULDBLOCK && errno != EAGAIN) {
              log_error("pollin : failed");
              goto restart;
            }
          } else {
            int ep = 0;
            if (pfe->n_rfd > 1) {
              if (pfe->seltype == PROXY_SEL_N2) {
                ep = ngap_proto_epsel_helper(rcvbuf, rc, pfe->n_rfd);
              } else {
                ep = pfe->lsel % pfe->n_rfd;
                pfe->lsel++;
                proxy_try_epxmit(pfe, rcvbuf, rc, ep);
              }
            } else {
              proxy_try_epxmit(pfe, rcvbuf, rc, ep);
            }
          }
        }
      }
    } else if (type & NOTI_TYPE_OUT) {
      type &= ~NOTI_TYPE_OUT;
      if (pfe->stype == PROXY_SOCK_ACTIVE) {
        proxy_xmit_cache(pfe);
      }
    } else {
      /* Unhandled */
      return 0;
    }
  }
  return 0;
}

int
proxy_main(sockmap_cb_t sockmap_cb)
{
  notify_cbs_t cbs = { 0 };
  cbs.notify = proxy_notifer;
  cbs.pdestroy = proxy_pdestroy;

  proxy_struct = calloc(sizeof(proxy_struct_t), 1);
  if (proxy_struct == NULL) {
    assert(0);
  }
  proxy_struct->sockmap_cb = sockmap_cb;
  proxy_struct->ns = notify_ctx_new(&cbs);
  assert(proxy_struct->ns);

  pthread_create(&proxy_struct->pthr, NULL, proxy_run, NULL);

  return 0;
}
