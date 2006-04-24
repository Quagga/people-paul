/* md5qd main routine.
 * Copyright (C) 2006 Paul Jakma <paul.jakma@sun.com>
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "sockunion.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "md5.h"
#include "hash.h"
#include "jhash.h"
#include "memory.h"
#include "checksum.h"

#define _LINUX_IF_H
#include <linux/netfilter.h>
#include <libipq.h>

/* md5qd options. */
static struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "user",        required_argument, NULL, 'u'},
  { "group",       required_argument, NULL, 'g'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* md5qd privileges */
zebra_capabilities_t _caps_p [] = 
{
  ZCAP_NET_RAW,
  ZCAP_BIND,
  ZCAP_NET_ADMIN,
};

struct zebra_privs_t md5qd_privs =
{
#if defined(QUAGGA_USER)
  .user = QUAGGA_USER,
#endif
#if defined QUAGGA_GROUP
  .group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = (sizeof (_caps_p) / sizeof (zebra_capabilities_t)),
  .cap_num_i = 0
};

#define MD5QD_DEFAULT_CONFIG "md5qd.conf"
#define MD5QD_VTY_PORT		2609

/* Configuration file and directory. */
char config_default[] = SYSCONFDIR MD5QD_DEFAULT_CONFIG;
char *config_file = NULL;

/* md5qd VTY bind address. */
char *vty_addr = NULL;

/* md5qd VTY connection port. */
int vty_port = MD5QD_VTY_PORT;

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
const char *pid_file = PATH_MD5QD_PID;

#define ROUNDUP(x,y)    ((((x)+(y)-1)/(y))*(y))
#define TCPMD5_OPT_SIZE 18
#define TCPOPT_MD5 	19
#define RECVBUF_SIZE (sizeof (struct ipq_packet_msg) \
                      + IP_MAXPACKET + ROUNDUP(TCPMD5_OPT_SIZE,4))
#define DUMPBYTES(S,D,L) \
  { \
    unsigned int i; \
    uint16_t *p16 = (uint16_t *)(D); \
    zlog_debug ("%s: %s:", __func__, (S)); \
    char buf[8*5 + 1]; \
    for (i = 0; i < (L)/2; i++) \
      { \
        if (i && !(i % 8)) \
          zlog_debug ("  %s", buf); \
        sprintf((buf + (i%8 * 5)), "%04hx ", ntohs(p16[i])); \
      } \
    if ((L)%2) \
      zlog_debug ("  %s %02hhx", buf, *(p16+i)); \
    else \
      zlog_debug ("  %s", buf); \
  }

static struct md5q_master_struct
{
  struct md5q_thread
    {
      struct ipq_handle *h;
      struct thread *t_ipq_read;
    } ipqt[AFI_MAX];
  
  /* seed for hash */
  uint32_t hashseed;
  struct hash *hosts;
  
  /* process packet at a time, regardless of number of handles
   * so one buffer will do obviously
   */
  ipq_packet_msg_t *ipqmsg;
  u_char buf[RECVBUF_SIZE];
} md5q_master;

struct host_config
{
  struct prefix p;
  char *addrstr;
  char *password;
};

static u_char debug;
static u_char debug_packet;

static void md5t_finish (struct md5q_thread *);
static void md5q_finish (void);
static int md5q_ipq_read (struct thread *);
static void md5q_init_libipq (void);
static void md5q_pkt_process (struct md5q_thread *);

static int
md5q_hash_cmp (void *obj1, void *obj2)
{
  struct host_config *hc1 = obj1, *hc2 = obj2;
  
  return (!prefix_cmp (&hc1->p, &hc2->p));
}

static uint32_t
md5q_hash_key (void *obj)
{
  uint32_t key;
  struct host_config *hc = obj;
  
  switch (hc->p.family)
    {
      case AF_INET:
        key = jhash_1word ((uint32_t)(*hc->p.u.val), md5q_master.hashseed);
        break;
      case AF_INET6:
        key = jhash2 ((uint32_t *)(hc->p.u.val), IPV6_MAX_BYTELEN, md5q_master.hashseed);
        break;
      default:
        key = 0;
    }
  return key;
}

static void *
md5q_host_config_alloc (void *data)
{
  struct host_config *hc = data;
  struct host_config *hc_new;
  
  hc_new = XMALLOC (MTYPE_MD5Q_HOST_CONFIG, sizeof (struct host_config));
  
  memcpy (&hc_new->p, &hc->p, sizeof(struct prefix));
  hc_new->password = NULL;
  hc_new->addrstr = NULL;
  
  return hc_new;
}

static void
md5q_host_config_clean (void *data)
{
  struct host_config *hc = data;
  
  XFREE (MTYPE_MD5Q_PASSWORD, hc->password);
  XFREE (MTYPE_MD5Q_ADDRSTR, hc->addrstr);
  XFREE (MTYPE_MD5Q_HOST_CONFIG, hc);
}

struct tcp_md5
{
  u_char kind;
  u_char bytes;
  u_char authdata[16];
  u_char pad[2];
};

struct md5q_tcp_opts
{
  struct tcp_md5 md5;
  uint32_t slots[5];
};

struct md5q_mss_slot
{
  u_char kind;
  u_char bytes;
  uint16_t data;
};

struct md5q_wscale_slot
{
  u_char win[3];
  u_char nop;
};

/* Fill new TCP options with any existing ones, as best we can.
 * taking care of alignment, etc.
 * return number of 4-byte words of options used.
 */
static u_char
md5q_fill_opts (struct md5q_tcp_opts *opts, u_char *from, size_t len)
{
  unsigned int bytes = 0;
  u_char nextfree = 0;
  struct md5q_mss_slot *mslot = NULL;
  struct md5q_wscale_slot *wslot = NULL;
  u_char *tslot = NULL;
  
  memset (opts, 1, sizeof(struct md5q_tcp_opts)); /* fill with NOOP */
  
  /*printf ("sof md5q_tcp_opts: %zd, sof tcp_md5 %zd\n", 
          sizeof(struct md5q_tcp_opts), sizeof(struct tcp_md5));
  printf ("sof md5q_mseg_slot: %zd, sof md5q_mseg %zd\n",
          sizeof(struct md5q_mseg_slot), sizeof(struct md5q_mseg));*/
  
  if (debug_packet)
    DUMPBYTES ("orig options", from, len);
  
  /* impossible, or nothing to do */
  if ( (len == 0) || (len > 40) )
    return 0;
  
  /* Allow only Window-Scale, MSS and Timestamp options. We don't allow
   * SACK through - unlikely to fit.
   *
   * Options are fitted into up to 10 4-byte slots. 5 reserved for MD5, 
   * therefore 5 are left for other options, pre-allocated into:
   *   Tstamp: 		3 slots, 10 bytes with 2 NOPs of leading padding.
   *   MSS:		1 slot.
   *   WScale:		1 slot with NOP.
   */
  while (bytes < len)
    {
      switch (from[bytes])
        {
          case TCPOPT_NOP:
            bytes++;
            break;
          case TCPOPT_EOL:
            return nextfree;
          case TCPOPT_MAXSEG:
            if ( ((len - bytes) < TCPOLEN_MAXSEG)
                || (from[bytes+1] != TCPOLEN_MAXSEG)  )
              return nextfree;
            if (mslot == NULL)
              {
                //printf ("MX: msslot %d\n",nextfree);
                mslot = (struct md5q_mss_slot *)&opts->slots[nextfree];
                nextfree++;
              }
            //printf ("MX: b %d, nf %d\n", bytes, nextfree);
            mslot->kind = TCPOPT_MAXSEG;
            mslot->bytes = TCPOLEN_MAXSEG;
            memcpy (&mslot->data, (from + bytes + 2), 2);
            
            /* reduce MSS by sizeof(5 slots) to compensate for TCP-MD5 */
            mslot->data = htons(ntohs(mslot->data)-20);
            bytes += TCPOLEN_MAXSEG;
            break;
          case TCPOPT_WINDOW:
            if ( ((len - bytes) < TCPOLEN_WINDOW)
                || (from[bytes+1] != TCPOLEN_WINDOW) )
              return nextfree;
            if (wslot == NULL)
              {
                //printf ("W: mslot %d\n", nextfree);
                wslot = (struct md5q_wscale_slot *)&opts->slots[nextfree];
                nextfree++;
              }
            //printf ("W: b %d, nf %d\n", bytes, nextfree);
            memcpy (wslot->win, &from[bytes], TCPOLEN_WINDOW);
            //mslot->win[0] = TCPOPT_WINDOW;
            //mslot->win[1] = TCPOLEN_WINDOW;
            //mslot->win[2] = from[bytes + 2];
            bytes += TCPOLEN_WINDOW;
            break;
          case TCPOPT_TIMESTAMP:
            if ( ((len - bytes) < TCPOLEN_TIMESTAMP)
                || (from[bytes+1] != TCPOLEN_TIMESTAMP) 
                || nextfree > 2)
              {
                zlog_warn ("%s: strange timestamp option", __func__);
                return nextfree;
              }
            if (tslot == NULL)
              {
                //printf ("T: tslot %d\n", nextfree);
                tslot = (u_char *)&opts->slots[nextfree];
                nextfree += 3;
              }
            //printf ("T: b %d, nf %d\n", bytes, nextfree);
            memcpy ((tslot + 2), &from[bytes], TCPOLEN_TIMESTAMP);
            bytes += TCPOLEN_TIMESTAMP;
            break;
          default:
            /* All options, bar EOL and NOP, must follow standard option
             * header format of two octets of kind, length.
             */
            if ((bytes + 1) < len)
              bytes += from[bytes+1];
            else
              return nextfree;
            break;
        }
    }
  return nextfree;
}

static void
md5q_add_md5 (struct md5q_thread *md5qt, struct host_config *hc)
{
  size_t tlen;
  struct nlmsghdr nlh;
  ipq_peer_msg_t pm;
  struct iovec iov[5];
  u_char nvecs = 0;
  struct msghdr msg;
  ipq_packet_msg_t *m = md5q_master.ipqmsg;
  struct ip *iph = (struct ip *) m->payload;
  struct tcphdr *tcph;
  struct md5q_tcp_opts tcpopts;
  unsigned int tcpcksum = 0;
  uint16_t tcpseglen, nseglen, tmp, data_offset;
  size_t data_size, optslots;
  MD5_CTX ctx;
  
  tcph = (struct tcphdr *)(m->payload + (4 * iph->ip_hl));
  
  if (m->data_len < ((4 * iph->ip_hl) + sizeof (struct tcphdr)))
    {
      zlog_err ("%s: packet length %ld shorter than TCP header",
                __func__, m->data_len);
      return;
    }
  
  data_offset = 4 * (iph->ip_hl + tcph->doff);
  data_size = m->data_len - data_offset;
  
  if (data_offset > m->data_len)
    {
      zlog_err ("%s: TCP data offset points past end of data", __func__);
      return;
    }
  
  if (debug_packet)
    DUMPBYTES ("original packet", m->payload, m->data_len);
  
  optslots = md5q_fill_opts (&tcpopts, 
                  &m->payload[(4 * iph->ip_hl) + sizeof(struct tcphdr)],
                  data_offset - ((4 * iph->ip_hl) + sizeof(struct tcphdr)));
  
  if (optslots > 5)
    {
      zlog_err ("%s: md5q_fill_opts filled more than 5 slots, %zd",
                __func__, optslots);
      return;
    }
  
  tcph->doff = (ROUNDUP(sizeof(struct tcp_md5),4) / 4) + optslots;
  tcph->doff += sizeof(struct tcphdr)/4;
  
  tcpopts.md5.kind = TCPOPT_MD5;
  tcpopts.md5.bytes = TCPMD5_OPT_SIZE;
  tcpseglen = (tcph->doff * 4) + data_size;
  
  memset (&nlh, 0, sizeof (nlh));
  nlh.nlmsg_flags = NLM_F_REQUEST;
  nlh.nlmsg_type = IPQM_VERDICT;
  nlh.nlmsg_pid = md5qt->h->local.nl_pid;
  memset (&pm, 0, sizeof (pm));
  pm.msg.verdict.value = NF_ACCEPT;
  pm.msg.verdict.id = m->packet_id;
  pm.msg.verdict.data_len = (4 * iph->ip_hl) + tcpseglen;
  
  iph->ip_sum = 0;
  iph->ip_len = htons((4 * iph->ip_hl) + tcpseglen);
  iph->ip_sum = in_cksum (iph, sizeof (struct ip));
  
  iov[0].iov_base = &nlh;
  iov[0].iov_len = sizeof (nlh);
  tlen = iov[0].iov_len;
  nvecs++;
  
  iov[1].iov_base = &pm;
  iov[1].iov_len = sizeof (pm);
  tlen += iov[1].iov_len;
  nvecs++;
  
  /* ip header and static leading section of tcp header */
  iov[2].iov_base = m->payload;
  iov[2].iov_len = (4 * iph->ip_hl) + sizeof(struct tcphdr);
  tlen += iov[2].iov_len;
  nvecs++;
  
  /* TCP options */
  iov[3].iov_base = &tcpopts;
  iov[3].iov_len = (4*tcph->doff) - sizeof(struct tcphdr);
  tlen += iov[3].iov_len;
  nvecs++;
  
  /* payload */
  if (data_size > 0)
    {
      iov[4].iov_base = (m->payload + data_offset);
      iov[4].iov_len = data_size;
      tlen += iov[4].iov_len;
      nvecs++;
    }
  else
    iov[4].iov_len = 0;
  
  if (debug_packet)
    {
      zlog_debug ("m %ld, v %ld, tseg: %d, data_off %d, dz: %zd, nvec: %d",
                  m->data_len, pm.msg.verdict.data_len, 
                  tcpseglen, data_offset, data_size, nvecs);
      zlog_debug ("iov len: 0: %ld, 1: %ld, 2: %ld, 3: %ld 4: %ld",
                  iov[0].iov_len, iov[1].iov_len, iov[2].iov_len, 
                  iov[3].iov_len, iov[4].iov_len);
      zlog_debug ("pm len: %ld, tlen %zd, iov 2-4 len: %ld",
                  pm.msg.verdict.data_len, tlen,
                  iov[2].iov_len + iov[3].iov_len + iov[4].iov_len);
    }
  
  tcph->check = 0;
  MD5Init(&ctx);
  assert (data_offset <= m->data_len);
  /* TCP pseudo-header */
  MD5Update (&ctx, &iph->ip_src.s_addr, sizeof (in_addr_t));
  MD5Update (&ctx, &iph->ip_dst.s_addr, sizeof (in_addr_t));
  MD5Update (&ctx, &iph->ip_p, 1);
  nseglen = htons (tcpseglen);
  MD5Update (&ctx, &nseglen, sizeof(nseglen));
  /* TCP header, static section, sans options */
  MD5Update (&ctx, tcph, sizeof(struct tcphdr));
  /* Segment data */
  if (data_offset > m->data_len)
    MD5Update (&ctx, iov[4].iov_base, iov[4].iov_len);
  /* password */
  MD5Update (&ctx, hc->password, strlen (hc->password));
  
  MD5Final (tcpopts.md5.authdata, &ctx);
  
  tcpcksum = 0;
  in_cksum_accumulate (&tcpcksum, &iph->ip_src.s_addr, sizeof (in_addr_t));
  in_cksum_accumulate (&tcpcksum, &iph->ip_dst.s_addr, sizeof (in_addr_t));
  tmp = htons(iph->ip_p);
  in_cksum_accumulate (&tcpcksum, &tmp, 2);
  nseglen = htons (tcpseglen);
  in_cksum_accumulate (&tcpcksum, &nseglen, 2);
  in_cksum_accumulate (&tcpcksum, tcph, sizeof(struct tcphdr));
  in_cksum_accumulate (&tcpcksum, iov[3].iov_base, iov[3].iov_len);
  if (data_size > 0)
    in_cksum_accumulate (&tcpcksum, iov[4].iov_base, iov[4].iov_len);
  tcph->check = in_cksum_finish (tcpcksum);
  
  
  if (debug_packet)
    {
      DUMPBYTES ("ip and tcp header", iov[2].iov_base, iov[2].iov_len);
      DUMPBYTES ("tcp header", tcph, sizeof (struct tcphdr));
      DUMPBYTES ("tcp options", iov[3].iov_base, iov[3].iov_len);
      if (iov[4].iov_len)
        DUMPBYTES ("data", iov[4].iov_base, iov[4].iov_len);
    }
  
  msg.msg_name = &md5qt->h->peer;
  msg.msg_namelen = sizeof (md5qt->h->peer);
  msg.msg_iov = iov;
  msg.msg_iovlen = nvecs;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  nlh.nlmsg_len = tlen;
  
  md5qd_privs.change (ZPRIVS_RAISE);
  if (sendmsg(md5qt->h->fd, &msg, 0) < 0)
    {
      md5qd_privs.change (ZPRIVS_LOWER);
      zlog_err ("%s: sendmsg failed, %s", __func__, safe_strerror (errno));
    }
  md5qd_privs.change (ZPRIVS_LOWER);
  
  if (debug)
    zlog_debug ("%s: Added TCP-MD5 data", __func__);
  
  return;
}

static int
md5q_pkt_verify (struct md5q_thread *md5qt, struct host_config *hc)
{
  ipq_packet_msg_t *m = md5q_master.ipqmsg;
  struct ip *iph = (struct ip *) m->payload;
  size_t data_offset, data_size;
  uint16_t tcpseglen, tmp;
  struct tcphdr *tcph = (struct tcphdr *)(m->payload + 4*iph->ip_hl);
  u_char digest[16];
  u_char *authdata;
  MD5_CTX ctx;
  
  if (m->data_len < ((4 * iph->ip_hl) + sizeof (struct tcphdr)))
    {
      zlog_err ("%s: packet length %ld shorter than TCP header",
                __func__, m->data_len);
      return NF_DROP;
    }
  
  data_offset = 4 * (iph->ip_hl + tcph->doff);
  data_size = m->data_len - data_offset;
  tcpseglen = 4 * tcph->doff + data_size;
  
  if (data_offset > m->data_len)
    {
      zlog_err ("%s: TCP data offset points past end of data", __func__);
      return NF_DROP;
    }
  
  if (debug_packet)
    DUMPBYTES ("original packet", m->payload, m->data_len);
  
  /* Find the tcp MD5 authentication data */
  authdata = (m->payload + 4*iph->ip_hl + sizeof(struct tcphdr));
  
  while (authdata < (m->payload + data_offset - TCPMD5_OPT_SIZE))
    {
      if (*authdata == TCPOPT_MD5)
        break;
      authdata++;
    }
  if (authdata >= (m->payload + data_offset - TCPMD5_OPT_SIZE))
    {
      if (debug)
        zlog_debug ("%s: no TCPMD5_opt found", __func__);
      return NF_DROP;
    }
  assert (*authdata == TCPOPT_MD5);
  
  if (*(authdata + 1) != TCPMD5_OPT_SIZE)
    {
      zlog_warn ("%s: tcpmd5 option found but size wrong, %hhx", __func__,
                 *(authdata + 1));
      return NF_DROP;
    }
  else
    authdata += 2; /* skip past tcp option kind and bytelen fields */
  
  tcph->check = 0;
  
  MD5Init(&ctx);
  assert (data_offset <= m->data_len);
  /* TCP pseudo-header */
  MD5Update (&ctx, &iph->ip_src.s_addr, sizeof (in_addr_t));
  MD5Update (&ctx, &iph->ip_dst.s_addr, sizeof (in_addr_t));
  MD5Update (&ctx, &iph->ip_p, 1);
  tmp = htons (tcpseglen);
  MD5Update (&ctx, &tmp, sizeof(tmp));
  /* TCP header, static section, sans options */
  MD5Update (&ctx, tcph, sizeof(struct tcphdr));
  /* Segment data */
  if (data_offset > m->data_len)
    MD5Update (&ctx, (m->payload + data_offset), data_size);
  /* password */
  MD5Update (&ctx, hc->password, strlen (hc->password));
  
  MD5Final (digest, &ctx);
  
  if (debug)
    {
      DUMPBYTES ("digest received", authdata, 16);
      DUMPBYTES ("digest calculated", digest, 16);
    }
  
  /* check digest */
  if (memcmp (digest, authdata, sizeof(digest)) == 0)
    return NF_ACCEPT;
  
  return NF_DROP;
  
}
static void
md5q_pkt_process (struct md5q_thread *md5qt)
{
  ipq_packet_msg_t *m = md5q_master.ipqmsg;
  struct ip *iph = (struct ip *) m->payload;
  struct host_config tmphc, *hc;
  unsigned int verdict = NF_DROP;
  
  if (m->data_len < (size_t) (sizeof (struct ip)))
    {
      zlog_err ("%s: Received data is less than size of IP header",
                __func__);
      return;
    }
  if (m->data_len < (size_t) ntohs(iph->ip_len))
    {
      zlog_err ("%s: Received data is less than claimed in IP header",
                __func__);
      return;
    }
  
  if (debug_packet)
    {
      zlog_info ("%s: processing", __func__);
      zlog_info ("pkt id: %lu, proto: %u", m->packet_id, iph->ip_p);
      zlog_info ("in:  %-20s len: %ld", 
                 m->indev_name, strlen(m->indev_name));
      zlog_info ("out: %-20s len: %ld",
                 m->outdev_name, strlen(m->outdev_name));
    }

  tmphc.p.family = AF_INET;
  tmphc.p.prefixlen = 32;
  
  if (strnlen(m->outdev_name, IFNAMSIZ))
    {
      memcpy (&tmphc.p.u.prefix4, &iph->ip_dst, sizeof (struct in_addr));
      hc = hash_lookup (md5q_master.hosts, &tmphc);
      
      if (hc)
        {
          md5q_add_md5 (md5qt, hc);
          return;
        }
      else
        {
          if (debug)
            zlog_info ("%s: no configuration data for %s, accepting packet",
                       __func__, inet_ntoa(iph->ip_dst));
        }
      verdict = NF_ACCEPT;
    }
  
  if (strnlen (m->indev_name, IFNAMSIZ))
    {
      memcpy (&tmphc.p.u.prefix4, &iph->ip_src, sizeof (struct in_addr));
      
      if ( (hc = hash_lookup (md5q_master.hosts, &tmphc)) == NULL)
        verdict = NF_ACCEPT;
      else
        {
          verdict = md5q_pkt_verify (md5qt, hc);
          if (debug)
            zlog_info ("%s: %s packet from %s", __func__, 
                       (verdict == NF_ACCEPT) ? "accepting" : "rejecting",
                       hc->addrstr);
        }
    }
  
  md5qd_privs.change (ZPRIVS_RAISE);
  ipq_set_verdict(md5qt->h, m->packet_id, verdict, 0, NULL);
  md5qd_privs.change (ZPRIVS_LOWER);  
  return;
}

static int
md5q_ipq_read (struct thread *thread)
{
  int status;
  struct md5q_thread *md5t = THREAD_ARG (thread);
  
  md5t->t_ipq_read = NULL;
  
  md5qd_privs.change (ZPRIVS_RAISE);
  status = ipq_read(md5t->h, md5q_master.buf, RECVBUF_SIZE, 0);
  md5qd_privs.change (ZPRIVS_LOWER);
  
  if (status < 0)
    {
      zlog_err ("%s: ipq_read error, %s", __func__, ipq_errstr());
      md5t_finish (md5t);
      return -1;
    }
  
  switch (ipq_message_type (md5q_master.buf))
    {
      case NLMSG_ERROR:
        zlog_err ("%s: Queue error read, %d, %s", __func__,
                  ipq_get_msgerr (md5q_master.buf), ipq_errstr());
        break;
      
      case IPQM_PACKET:
        {
          struct ip *iph;
          ipq_packet_msg_t *m;
          m = md5q_master.ipqmsg = ipq_get_packet (md5q_master.buf);
          
          if (debug)
            zlog_info ("%s: reading packet", __func__);
          
          iph = (struct ip *) m->payload;
          
          if (m->data_len < sizeof (struct ip))
            {
              zlog_err ("%s: Received data is less than sizeof IP header",
                        __func__);
              break;
            }
          if (iph->ip_v != 4)
            {
              zlog_err ("%s: Can't do IP version, %d", __func__, iph->ip_v);
              break;
            }
        }
        md5q_pkt_process (md5t);
        break;
      
      default:
        zlog_err ("%s: unknown message received", __func__);
        break;
    }
  
  if (md5t->h->fd != -1)
    THREAD_READ_ON (master, md5t->t_ipq_read, md5q_ipq_read, md5t,
                    md5t->h->fd);
  else
    {
      zlog_warn  ("%s: didnt set fd is %d",__func__,md5t->h->fd);
      md5t_finish (md5t);
    }
  
  return 0;
}
 
static void
md5t_finish (struct md5q_thread *md5t)
{
  if (md5t->t_ipq_read)
    THREAD_OFF (md5t->t_ipq_read);
  
  ipq_destroy_handle(md5t->h);
  
  md5t->h = NULL;
}

static void
md5q_finish (void)
{
  int i;
  
  for (i = AFI_IP; i < AFI_MAX; i++)
    md5t_finish (&md5q_master.ipqt[i]);
  
  hash_clean (md5q_master.hosts, md5q_host_config_clean);
}
  
static void
md5q_init_libipq (void)
{
  int i, status;
  
  md5qd_privs.change (ZPRIVS_RAISE);
  
  for (i = AFI_IP; i < AFI_MAX; i++)
    {
      struct md5q_thread *md5qt = &md5q_master.ipqt[i];
      
      md5qt->h = ipq_create_handle (0, afi2family(i));
      
      if (!md5qt->h)
        {
          zlog_err ("%s: Unable to create libipq handle, %s", __func__,
                    ipq_errstr());
          ipq_destroy_handle (md5qt->h);
          continue;
        }
      
      status = ipq_set_mode (md5qt->h, IPQ_COPY_PACKET, RECVBUF_SIZE);
      
      if (status < 0)
        {
          zlog_err ("%s: Unable to set mode, %s", __func__,
                    ipq_errstr());
          ipq_destroy_handle (md5qt->h);
          continue;
        }
      
      THREAD_READ_ON (master, md5qt->t_ipq_read, md5q_ipq_read, md5qt,
                      md5qt->h->fd);
    }
  
  md5qd_privs.change (ZPRIVS_LOWER);
  return;
}

DEFUN (md5q,
       md5q_cmd,
       "md5qd",
       "Start md5qd configuration\n")
{
  vty->node = MD5Q_NODE;
  vty->index = &md5q_master;
  return CMD_SUCCESS;
}

DEFUN (no_md5q,
       no_md5q_cmd,
       "no md5qd",
       NO_STR
       "Remove md5qd configuration\n")
{
  md5q_finish();
  return CMD_SUCCESS;
}

DEFUN (neighbour_mode,
       neighbour_mode_cmd,
       "neighbour WORD mode tcp-md5 LINE",
       NEIGHBOR_ADDR_STR
       "Transport authentication mode\n"
       "RFC2328 TCP-MD5 authentication\n"
       "TCP-MD5 password string\n")
{
  struct host_config tmphc, *hc;
  union sockunion su;
  int ret;
  
  ret = str2sockunion (argv[0], &su);
  if (ret != 0)
    {
      vty_out (vty, "%% Malformed neighbour address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  if (!str2prefix (argv[0], &tmphc.p))
    {
      vty_out (vty, "%% Problem with str2prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  hc = hash_get (md5q_master.hosts, &tmphc, md5q_host_config_alloc);
  
  hc->password = XSTRDUP (MTYPE_MD5Q_PASSWORD, argv[1]);
  hc->addrstr = XSTRDUP (MTYPE_MD5Q_ADDRSTR, argv[0]);
  
  return CMD_SUCCESS;
}

DEFUN (no_neighbour_mode,
       no_neighbour_mode_cmd,
       "no neighbour WORD",
       NO_STR
       NEIGHBOR_ADDR_STR
       "Transport authentication mode\n"
       "RFC2328 TCP-MD5 authentication\n"
       "TCP-MD5 password string\n")
{
  struct host_config tmphc, *hc;
  union sockunion su;
  int ret;
  
  ret = str2sockunion (argv[0], &su);
  if (ret != 0)
    {
      vty_out (vty, "%% Malformed neighbour address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  if (!str2prefix (argv[0], &tmphc.p))
    {
      vty_out (vty, "%% Problem with str2prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  hc = hash_release (md5q_master.hosts, &tmphc);
  
  if (hc == NULL)
    {
      vty_out (vty, "%% No such neighbour configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  md5q_host_config_clean (hc);
  
  return CMD_SUCCESS;
}

DEFUN (show_debug,
       show_debug_cmd,
       "show debug",
       SHOW_STR
       DEBUG_STR)
{
  vty_out (vty, "MD5QD debug %s enabled%s",
           (debug == 1) ? "is" : "not",
           VTY_NEWLINE);
  vty_out (vty, "MD5QD packet debug %s enabled%s",
           (debug_packet == 1) ? "is" : "not",
           VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (debug_md5q,
       debug_md5q_cmd,
       "debug md5q",
       DEBUG_STR
       "TCP-MD5 ip_queue daemon\n")
{
  debug = 1;
  return CMD_SUCCESS;
}
DEFUN (debug_md5q_packet,
       debug_md5q_packet_cmd,
       "debug md5q packet",
       DEBUG_STR
       "TCP-MD5 ip_queue daemon\n"
       "TCP-MD5 packet data\n")
{
  debug_packet = 1;
  return CMD_SUCCESS;
}

DEFUN (no_debug_md5q_packet,
       no_debug_md5q_packet_cmd,
       "no debug md5q packet",
       NO_STR
       DEBUG_STR
       "TCP-MD5 ip_queue\n"
       "TCP-MD5 packet data\n")
{
  debug_packet = 0;
  return CMD_SUCCESS;
}

DEFUN (no_debug_md5q,
       no_debug_md5q_cmd,
       "no debug md5q",
       NO_STR
       DEBUG_STR
       "TCP-MD5 ip_queue\n")
{
  debug = 0;
  debug_packet = 0;
  return CMD_SUCCESS;
}

struct cmd_node md5q_node =
{
  MD5Q_NODE,
  "%s(config-md5q)# ",
  1
};

struct cmd_node debug_node = 
{
  DEBUG_NODE,
  "",
  1, /* VTYSH */
};

static int
config_write_debug (struct vty *vty)
{
  if (debug)
    vty_out (vty, "debug md5qd%s", VTY_NEWLINE);
  if (debug_packet)
    vty_out (vty, "debug md5qd packet%s", VTY_NEWLINE);
  return 1;
}

static void
md5q_write_host_config (struct hash_backet *hb, void *data)
{
  struct vty *vty = data;
  struct host_config *hc = hb->data;
  
  vty_out (vty, " neighbour %s mode tcp-md5 %s%s",
           hc->addrstr, hc->password, VTY_NEWLINE);
}

static int
md5q_write_config (struct vty *vty)
{
  vty_out (vty, "md5qd%s", VTY_NEWLINE);
  hash_iterate (md5q_master.hosts, md5q_write_host_config, vty);
  return (1 + md5q_master.hosts->count);
}

static void
md5q_init (void)
{
  md5q_master.hashseed = time(NULL) & 0xffffffff;
  md5q_master.hosts = hash_create (md5q_hash_key, md5q_hash_cmp);
  md5q_init_libipq ();
  
  install_node (&md5q_node, md5q_write_config);
  install_element (CONFIG_NODE, &md5q_cmd);
  install_element (CONFIG_NODE, &no_md5q_cmd);
  
  install_default (MD5Q_NODE);
  
  install_element (MD5Q_NODE, &neighbour_mode_cmd);
  install_element (MD5Q_NODE, &no_neighbour_mode_cmd);
  
  install_node (&debug_node, config_write_debug);
  install_element (ENABLE_NODE, &show_debug_cmd);
  install_element (CONFIG_NODE, &debug_md5q_cmd);
  install_element (CONFIG_NODE, &debug_md5q_packet_cmd);
  install_element (CONFIG_NODE, &no_debug_md5q_cmd);
  install_element (CONFIG_NODE, &no_debug_md5q_packet_cmd);  
}

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\
TCP-MD5 Netfilter QUEUE daemon.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }

  exit (status);
}

/* SIGHUP handler. */
static void 
sighup (void)
{
  zlog_info ("SIGHUP received");

  /* Reload config file. */
  vty_read_config (config_file, config_default);

  /* Create VTY's socket */
  vty_serv_sock (vty_addr, vty_port, MD5QD_VTYSH_PATH);

  /* Try to return to normal operation. */
}

/* SIGINT handler. */
static void
sigint (void)
{
  zlog_notice ("Terminating on signal");

  exit (0);
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

static struct quagga_signal_t md5qd_signals[] =
{
  { 
    .signal = SIGHUP,
    .handler = &sighup,
  },
  { 
    .signal = SIGUSR1,
    .handler = &sigusr1,
  },
  {
    .signal = SIGINT,
    .handler = &sigint,
  },
  {
    .signal = SIGTERM,
    .handler = &sigint,
  },
};  



/* Main routine of md5qd. */
int
main (int argc, char **argv)
{
  char *p;
  int daemon_mode = 0;
  char *progname;
  struct thread thread;

  /* Set umask before anything for security */
  umask (0027);

  /* Get program name. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);


  /* Command line option parse. */
  while (1) 
    {
      int opt;

      opt = getopt_long (argc, argv, "df:i:hA:P:u:g:rv", longopts, 0);
    
      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'A':
	  vty_addr = optarg;
	  break;
        case 'i':
          pid_file = optarg;
          break;
	case 'P':
          /* Deal with atoi() returning 0 on failure, and md5qd not
             listening on md5qd port... */
          if (strcmp(optarg, "0") == 0) 
            {
              vty_port = 0;
              break;
            } 
          vty_port = atoi (optarg);
          vty_port = (vty_port ? vty_port : MD5QD_VTY_PORT);
	  break;
	case 'u':
	  md5qd_privs.user = optarg;
	  break;
	case 'g':
	  md5qd_privs.group = optarg;
	  break;
	case 'v':
	  print_version (progname);
	  exit (0);
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	}
    }

  /* Prepare master thread. */
  master = thread_master_create ();

  /* Library initialization. */
  zprivs_init (&md5qd_privs);
  signal_init (master, Q_SIGC(md5qd_signals), md5qd_signals);
  cmd_init (1);
  vty_init (master);
  memory_init ();
  /* First of all we need logging init. */
  zlog_default = openzlog (progname, ZLOG_MD5QD,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
  
  /* Init md5q */
  md5q_init ();
  
  /* Sort all installed commands. */
  sort_node ();

  /* Get configuration file. */
  vty_read_config (config_file, config_default);

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon (0, 0);

  /* Pid file create. */
  pid_output (pid_file);

  /* Create VTY's socket */
  vty_serv_sock (vty_addr, vty_port, MD5QD_VTYSH_PATH);

  /* Print banner. */
  zlog_notice ("md5qd %s starting: vty@%d", QUAGGA_VERSION, vty_port);

  /* Execute each thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  return (0);
}
