/*
 *  llb-csum-kprobe.c: LoxiLB checksum fixup probe
 *  Copyright (C) 2023  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/checksum.h>
#include <net/sctp/checksum.h>

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
  .symbol_name  = "dev_hard_start_xmit",
};

static int dev_hard_start_xmit_pre(struct kprobe *p, struct pt_regs *regs)
{
  struct sctphdr *sctph;
  struct sk_buff *skb = (struct sk_buff *)regs->di;
  int err;

  if (skb->mark & 0x00000300) {
    __u16 off = skb->mark >> 16;
    if (off == 0 && (skb->protocol == htons(ETH_P_IP) || skb->protocol == htons(ETH_P_IPV6))) {

      if (ip_hdr(skb)->protocol != IPPROTO_SCTP)
        return 0;

      off = skb_transport_offset(skb);
      err = skb_ensure_writable(skb, off + sizeof(struct sctphdr));
      if (unlikely(err))
        return 0;

      sctph = sctp_hdr(skb);
      sctph->checksum = sctp_compute_cksum(skb, off);
      skb->mark &= ~0x00000300;
    } else if (off < skb->len && skb->priority) {
      *(__u32 *)(skb->data + off) = skb->priority;
      skb->priority = 0;
    }
    skb->ip_summed = CHECKSUM_UNNECESSARY;
  }

  return 0;
}

static int __init kprobe_init(void)
{
  int ret;
  kp.pre_handler = dev_hard_start_xmit_pre;

  ret = register_kprobe(&kp);
  if (ret < 0) {
    printk(KERN_INFO "loxilb:kprobe reg failed - %d\n", ret);
    return ret;
  }
  printk(KERN_INFO "loxilb: kprobe at %p\n", kp.addr);
  return 0;
}

static void __exit kprobe_exit(void)
{
  unregister_kprobe(&kp);
  printk(KERN_INFO "loxilb:kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("Dual BSD/GPL");
