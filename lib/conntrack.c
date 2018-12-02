/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <string.h>

#include "bitmap.h"
#include "conntrack.h"
#include "conntrack-private.h"
#include "coverage.h"
#include "csum.h"
#include "ct-dpif.h"
#include "dp-packet.h"
#include "flow.h"
#include "netdev.h"
#include "odp-netlink.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "random.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(conntrack);

COVERAGE_DEFINE(conntrack_full);
COVERAGE_DEFINE(conntrack_long_cleanup);

struct conn_lookup_ctx {
    struct conn_key key;
    struct conn *conn;
    uint32_t hash;
    bool reply;
    bool icmp_related;
};

enum ftp_ctl_pkt {
    /* Control packets with address and/or port specifiers. */
    CT_FTP_CTL_INTEREST,
    /* Control packets without address and/or port specifiers. */
    CT_FTP_CTL_OTHER,
    CT_FTP_CTL_INVALID,
};

enum ct_alg_mode {
    CT_FTP_MODE_ACTIVE,
    CT_FTP_MODE_PASSIVE,
    CT_TFTP_MODE,
};

enum ct_alg_ctl_type {
    CT_ALG_CTL_NONE,
    CT_ALG_CTL_FTP,
    CT_ALG_CTL_TFTP,
    /* SIP is not enabled through Openflow and presently only used as
     * an example of an alg that allows a wildcard src ip. */
    CT_ALG_CTL_SIP,
};

struct OVS_LOCKABLE ct_rwlock {
    struct ovs_rwlock lock;
};

/* This lock is used to guard alg_expectations and alg_expectation_refs. */
static struct ct_rwlock resources_lock;
/* Hash table for alg expectations. Expectations are created
 * by control connections to help create data connections. */
static struct hmap alg_expectations OVS_GUARDED_BY(resources_lock);
/* Only needed to be able to cleanup expectations from non-control
 * connection context; otherwise a pointer to the expectation from
 * the control connection would suffice. */
static struct hindex alg_expectation_refs OVS_GUARDED_BY(resources_lock);

struct OVS_LOCKABLE ct_lock {
    struct ovs_mutex lock;
};

static struct ct_lock ct_lock;
static struct cmap cm_conns OVS_GUARDED_BY(ct_lock);
struct ovs_list cm_exp_lists[N_CT_TM] OVS_GUARDED_BY(ct_lock);
/* Salt for hashing a connection key. */
static uint32_t hash_basis;
/* The thread performing periodic cleanup of the connection
 * tracker */
static pthread_t clean_thread;
/* Latch to destroy the 'clean_thread' */
static struct latch clean_thread_exit;
/* Number of connections currently in the connection tracker. */
static atomic_count n_conn;
/* Connections limit. When this limit is reached, no new connection
 * will be accepted. */
static atomic_uint n_conn_limit;

/* Lock acquisition order: If multiple locks are taken, then the order is
 * 'ct_lock', then conn entry lock and then 'resources_lock' and release
 * happens in the reverse order. */

static bool conn_key_extract(struct dp_packet *, ovs_be16 dl_type,
                             struct conn_lookup_ctx *, uint16_t zone);
static uint32_t conn_key_hash(const struct conn_key *, uint32_t basis);
static void conn_key_reverse(struct conn_key *);
static bool valid_new(struct dp_packet *pkt, struct conn_key *);
static struct conn *new_conn(struct dp_packet *pkt, struct conn_key *,
                             long long now);
static enum ct_update_res conn_update(struct dp_packet *pkt,
                                      struct conn *conn,
                                      struct conn_lookup_ctx *ctx,
                                      long long now);
static void delete_conn_cmn(struct conn *);
static void delete_conn(struct conn *);
static void delete_conn_one(struct conn *conn);
static bool conn_expired(struct conn *, long long now);
static void set_mark(struct dp_packet *, struct conn *,
                     uint32_t val, uint32_t mask);
static void set_label(struct dp_packet *, struct conn *,
                      const struct ovs_key_ct_labels *val,
                      const struct ovs_key_ct_labels *mask);
static void *clean_thread_main(void *);

static bool
nat_select_range_tuple(const struct conn *conn, struct conn *nat_conn);

static uint8_t
reverse_icmp_type(uint8_t type);
static uint8_t
reverse_icmp6_type(uint8_t type);
static inline bool
extract_l3_ipv4(struct conn_key *key, const void *data, size_t size,
                const char **new_data, bool validate_checksum);
static inline bool
extract_l3_ipv6(struct conn_key *key, const void *data, size_t size,
                const char **new_data);
static struct alg_exp_node *
expectation_lookup(struct hmap *alg_expectations, const struct conn_key *key,
                   uint32_t basis, bool src_ip_wc);

static int
repl_ftp_v4_addr(struct dp_packet *pkt, ovs_be32 v4_addr_rep,
                 char *ftp_data_v4_start,
                 size_t addr_offset_from_ftp_data_start);

static enum ftp_ctl_pkt
process_ftp_ctl_v4(struct dp_packet *pkt,
                   const struct conn *conn_for_expectation,
                   ovs_be32 *v4_addr_rep,
                   char **ftp_data_v4_start,
                   size_t *addr_offset_from_ftp_data_start);

static enum ftp_ctl_pkt
detect_ftp_ctl_type(const struct conn_lookup_ctx *ctx,
                    struct dp_packet *pkt);

static void
expectation_clean(const struct conn_key *master_key);

static struct ct_l4_proto *l4_protos[] = {
    [IPPROTO_TCP] = &ct_proto_tcp,
    [IPPROTO_UDP] = &ct_proto_other,
    [IPPROTO_ICMP] = &ct_proto_icmp4,
    [IPPROTO_ICMPV6] = &ct_proto_icmp6,
};

static void
handle_ftp_ctl(const struct conn_lookup_ctx *ctx, struct dp_packet *pkt,
               const struct conn *conn_for_expectation,
               long long now, enum ftp_ctl_pkt ftp_ctl, bool nat);

static void
handle_tftp_ctl(const struct conn_lookup_ctx *ctx OVS_UNUSED,
                struct dp_packet *pkt,
                const struct conn *conn_for_expectation,
                long long now OVS_UNUSED,
                enum ftp_ctl_pkt ftp_ctl OVS_UNUSED, bool nat OVS_UNUSED);

typedef void (*alg_helper)(const struct conn_lookup_ctx *ctx,
                           struct dp_packet *pkt,
                           const struct conn *conn_for_expectation,
                           long long now, enum ftp_ctl_pkt ftp_ctl,
                           bool nat);

static alg_helper alg_helpers[] = {
    [CT_ALG_CTL_NONE] = NULL,
    [CT_ALG_CTL_FTP] = handle_ftp_ctl,
    [CT_ALG_CTL_TFTP] = handle_tftp_ctl,
};

long long ct_timeout_val[] = {
#define CT_TIMEOUT(NAME, VAL) [CT_TM_##NAME] = VAL,
    CT_TIMEOUTS
#undef CT_TIMEOUT
};

/* The maximum TCP or UDP port number. */
#define CT_MAX_L4_PORT 65535
/* String buffer used for parsing FTP string messages.
 * This is sized about twice what is needed to leave some
 * margin of error. */
#define LARGEST_FTP_MSG_OF_INTEREST 128
/* FTP port string used in active mode. */
#define FTP_PORT_CMD "PORT"
/* FTP pasv string used in passive mode. */
#define FTP_PASV_REPLY_CODE "227"
/* Maximum decimal digits for port in FTP command.
 * The port is represented as two 3 digit numbers with the
 * high part a multiple of 256. */
#define MAX_FTP_PORT_DGTS 3

/* FTP extension EPRT string used for active mode. */
#define FTP_EPRT_CMD "EPRT"
/* FTP extension EPSV string used for passive mode. */
#define FTP_EPSV_REPLY "EXTENDED PASSIVE"
/* Maximum decimal digits for port in FTP extended command. */
#define MAX_EXT_FTP_PORT_DGTS 5
/* FTP extended command code for IPv6. */
#define FTP_AF_V6 '2'
/* Used to indicate a wildcard L4 source port number for ALGs.
 * This is used for port numbers that we cannot predict in
 * expectations. */
#define ALG_WC_SRC_PORT 0

/* If the total number of connections goes above this value, no new connections
 * are accepted; this is for CT_CONN_TYPE_DEFAULT connections. */
#define DEFAULT_N_CONN_LIMIT 3000000

/* Does a member by member comparison of two conn_keys; this
 * function must be kept in sync with struct conn_key; returns 0
 * if the keys are equal or 1 if the keys are not equal. */
static int
conn_key_cmp(const struct conn_key *key1, const struct conn_key *key2)
{
    if (!memcmp(&key1->src.addr, &key2->src.addr, sizeof key1->src.addr) &&
        !memcmp(&key1->dst.addr, &key2->dst.addr, sizeof key1->dst.addr) &&
        (key1->src.icmp_id == key2->src.icmp_id) &&
        (key1->src.icmp_type == key2->src.icmp_type) &&
        (key1->src.icmp_code == key2->src.icmp_code) &&
        (key1->dst.icmp_id == key2->dst.icmp_id) &&
        (key1->dst.icmp_type == key2->dst.icmp_type) &&
        (key1->dst.icmp_code == key2->dst.icmp_code) &&
        (key1->dl_type == key2->dl_type) &&
        (key1->zone == key2->zone) &&
        (key1->nw_proto == key2->nw_proto)) {

        return 0;
    }
    return 1;
}

static bool
conn_key_lookup(const struct conn_key *key, uint32_t hash, long long now,
                struct conn **conn_out, bool *reply)
{
    struct conn *conn;
    bool found = false;

    CMAP_FOR_EACH_WITH_HASH (conn, cm_node, hash, &cm_conns) {
        if (!conn_key_cmp(&conn->key, key) && !conn_expired(conn, now)) {
            found = true;
            if (reply) {
                *reply = false;
            }
            break;
        }
        if (!conn_key_cmp(&conn->rev_key, key) && !conn_expired(conn, now)) {
            found = true;
            if (reply) {
                *reply = true;
            }
            break;
        }
    }

    if (found && conn_out) {
        *conn_out = conn;
    } else if (conn_out) {
        *conn_out = NULL;
    }
    return found;
}

static void
ct_print_conn_info(const struct conn *c, const char *log_msg,
                   enum vlog_level vll, bool force, bool rl_on)
{
#define CT_VLOG(RL_ON, LEVEL, ...)                                          \
    do {                                                                    \
        if (RL_ON) {                                                        \
            static struct vlog_rate_limit rl_ = VLOG_RATE_LIMIT_INIT(5, 5); \
            vlog_rate_limit(&this_module, LEVEL, &rl_, __VA_ARGS__);        \
        } else {                                                            \
            vlog(&this_module, LEVEL, __VA_ARGS__);                         \
        }                                                                   \
    } while (0)

    if (OVS_UNLIKELY(force || vlog_is_enabled(&this_module, vll))) {
        if (c->key.dl_type == htons(ETH_TYPE_IP)) {
            CT_VLOG(rl_on, vll, "%s: src ip "IP_FMT" dst ip "IP_FMT" rev src "
                    "ip "IP_FMT" rev dst ip "IP_FMT" src/dst ports "
                    "%"PRIu16"/%"PRIu16" rev src/dst ports "
                    "%"PRIu16"/%"PRIu16" zone/rev zone "
                    "%"PRIu16"/%"PRIu16" nw_proto/rev nw_proto "
                    "%"PRIu8"/%"PRIu8, log_msg,
                    IP_ARGS(c->key.src.addr.ipv4_aligned),
                    IP_ARGS(c->key.dst.addr.ipv4_aligned),
                    IP_ARGS(c->rev_key.src.addr.ipv4_aligned),
                    IP_ARGS(c->rev_key.dst.addr.ipv4_aligned),
                    ntohs(c->key.src.port), ntohs(c->key.dst.port),
                    ntohs(c->rev_key.src.port), ntohs(c->rev_key.dst.port),
                    c->key.zone, c->rev_key.zone, c->key.nw_proto,
                    c->rev_key.nw_proto);
        } else {
            char ip6_s[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->key.src.addr.ipv6, ip6_s, sizeof ip6_s);
            char ip6_d[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->key.dst.addr.ipv6, ip6_d, sizeof ip6_d);
            char ip6_rs[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->rev_key.src.addr.ipv6, ip6_rs,
                      sizeof ip6_rs);
            char ip6_rd[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &c->rev_key.dst.addr.ipv6, ip6_rd,
                      sizeof ip6_rd);

            CT_VLOG(rl_on, vll, "%s: src ip %s dst ip %s rev src ip %s"
                    " rev dst ip %s src/dst ports %"PRIu16"/%"PRIu16
                    " rev src/dst ports %"PRIu16"/%"PRIu16" zone/rev zone "
                    "%"PRIu16"/%"PRIu16" nw_proto/rev nw_proto "
                    "%"PRIu8"/%"PRIu8, log_msg, ip6_s, ip6_d, ip6_rs,
                    ip6_rd, ntohs(c->key.src.port), ntohs(c->key.dst.port),
                    ntohs(c->rev_key.src.port), ntohs(c->rev_key.dst.port),
                    c->key.zone, c->rev_key.zone, c->key.nw_proto,
                    c->rev_key.nw_proto);
        }
    }
}

/* Initializes the connection tracker 'ct'.  The caller is responsible for
 * calling 'conntrack_destroy()', when the instance is not needed anymore */
void
conntrack_init(void)
{
    ovs_rwlock_init(&resources_lock.lock);
    ovs_rwlock_wrlock(&resources_lock.lock);
    hmap_init(&alg_expectations);
    hindex_init(&alg_expectation_refs);
    ovs_rwlock_unlock(&resources_lock.lock);

    ovs_mutex_init_adaptive(&ct_lock.lock);
    ovs_mutex_lock(&ct_lock.lock);
    cmap_init(&cm_conns);
    for (unsigned i = 0; i < ARRAY_SIZE(cm_exp_lists); i++) {
        ovs_list_init(&cm_exp_lists[i]);
    }
    ovs_mutex_unlock(&ct_lock.lock);

    hash_basis = random_uint32();
    atomic_count_init(&n_conn, 0);
    atomic_init(&n_conn_limit, DEFAULT_N_CONN_LIMIT);
    latch_init(&clean_thread_exit);
    clean_thread = ovs_thread_create("ct_clean", clean_thread_main, NULL);
}

static void
conn_clean_cmn(struct conn *conn)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    if (conn->ext_alg && conn->ext_alg->alg) {
        expectation_clean(&conn->key);
    }

    uint32_t hash = conn_key_hash(&conn->key, hash_basis);
    cmap_remove(&cm_conns, &conn->cm_node, hash);
    ovs_list_remove(&conn->exp_node);
}

/* Must be called with 'conn' of 'conn_type' CT_CONN_TYPE_DEFAULT.  Also
 * removes the associated nat 'conn' from the lookup datastructures. */
static void
conn_clean(struct conn *conn)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_assert(conn->conn_type == CT_CONN_TYPE_DEFAULT);

    conn_clean_cmn(conn);
    if (conn->ext_nat && conn->ext_nat->nat_conn) {
        uint32_t hash = conn_key_hash(&conn->ext_nat->nat_conn->key,
                                      hash_basis);
        cmap_remove(&cm_conns, &conn->ext_nat->nat_conn->cm_node, hash);
    }
    ovsrcu_postpone(delete_conn, conn);
    atomic_count_dec(&n_conn);
}

/* Needed because of usage in CMAP_FOR_EACH. */
static void
conn_clean_one(struct conn *conn)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    conn_clean_cmn(conn);
    if (conn->conn_type == CT_CONN_TYPE_DEFAULT) {
        atomic_count_dec(&n_conn);
    }
    ovsrcu_postpone(delete_conn_one, conn);
}

/* Destroys the connection tracker 'ct' and frees all the allocated memory. */
void
conntrack_destroy(void)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct conn *conn;
    latch_set(&clean_thread_exit);
    pthread_join(clean_thread, NULL);
    latch_destroy(&clean_thread_exit);

    ovs_mutex_lock(&ct_lock.lock);
    CMAP_FOR_EACH (conn, cm_node, &cm_conns) {
        conn_clean_one(conn);
    }
    cmap_destroy(&cm_conns);
    ovs_mutex_unlock(&ct_lock.lock);
    ovs_mutex_destroy(&ct_lock.lock);

    ovs_rwlock_wrlock(&resources_lock.lock);
    struct alg_exp_node *alg_exp_node;
    HMAP_FOR_EACH_POP (alg_exp_node, node, &alg_expectations) {
        free(alg_exp_node);
    }

    hmap_destroy(&alg_expectations);
    hindex_destroy(&alg_expectation_refs);
    ovs_rwlock_unlock(&resources_lock.lock);
    ovs_rwlock_destroy(&resources_lock.lock);
}


static void
write_ct_md(struct dp_packet *pkt, uint16_t zone, const struct conn *conn,
            const struct conn_key *key, const struct alg_exp_node *alg_exp)
{
    pkt->md.ct_state |= CS_TRACKED;
    pkt->md.ct_zone = zone;
    pkt->md.ct_mark = conn ? conn->mark : 0;
    pkt->md.ct_label = conn ? conn->label : OVS_U128_ZERO;

    /* Use the original direction tuple if we have it. */
    if (conn) {
        if (conn->ext_alg && conn->ext_alg->alg_related) {
            key = &conn->ext_alg->master_key;
        } else {
            key = &conn->key;
        }
    } else if (alg_exp) {
        pkt->md.ct_mark = alg_exp->master_mark;
        pkt->md.ct_label = alg_exp->master_label;
        key = &alg_exp->master_key;
    }

    pkt->md.ct_orig_tuple_ipv6 = false;

    if (key) {
        if (key->dl_type == htons(ETH_TYPE_IP)) {
            pkt->md.ct_orig_tuple.ipv4 = (struct ovs_key_ct_tuple_ipv4) {
                key->src.addr.ipv4_aligned,
                key->dst.addr.ipv4_aligned,
                key->nw_proto != IPPROTO_ICMP
                ? key->src.port : htons(key->src.icmp_type),
                key->nw_proto != IPPROTO_ICMP
                ? key->dst.port : htons(key->src.icmp_code),
                key->nw_proto,
            };
        } else {
            pkt->md.ct_orig_tuple_ipv6 = true;
            pkt->md.ct_orig_tuple.ipv6 = (struct ovs_key_ct_tuple_ipv6) {
                key->src.addr.ipv6_aligned,
                key->dst.addr.ipv6_aligned,
                key->nw_proto != IPPROTO_ICMPV6
                ? key->src.port : htons(key->src.icmp_type),
                key->nw_proto != IPPROTO_ICMPV6
                ? key->dst.port : htons(key->src.icmp_code),
                key->nw_proto,
            };
        }
    } else {
        memset(&pkt->md.ct_orig_tuple, 0, sizeof pkt->md.ct_orig_tuple);
    }
}

static uint8_t
get_ip_proto(const struct dp_packet *pkt)
{
    uint8_t ip_proto;
    struct eth_header *l2 = dp_packet_eth(pkt);
    if (l2->eth_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
        ip_proto = nh6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    } else {
        struct ip_header *l3_hdr = dp_packet_l3(pkt);
        ip_proto = l3_hdr->ip_proto;
    }

    return ip_proto;
}

static bool
is_ftp_ctl(const enum ct_alg_ctl_type ct_alg_ctl)
{
    return ct_alg_ctl == CT_ALG_CTL_FTP;
}

static enum ct_alg_ctl_type
get_alg_ctl_type(const struct dp_packet *pkt, ovs_be16 tp_src, ovs_be16 tp_dst,
                 const char *helper)
{
    /* CT_IPPORT_FTP/TFTP is used because IPPORT_FTP/TFTP in not defined
     * in OSX, at least in in.h. Since these values will never change, remove
     * the external dependency. */
    enum { CT_IPPORT_FTP = 21 };
    enum { CT_IPPORT_TFTP = 69 };
    uint8_t ip_proto = get_ip_proto(pkt);
    struct udp_header *uh = dp_packet_l4(pkt);
    struct tcp_header *th = dp_packet_l4(pkt);
    ovs_be16 ftp_src_port = htons(CT_IPPORT_FTP);
    ovs_be16 ftp_dst_port = htons(CT_IPPORT_FTP);
    ovs_be16 tftp_dst_port = htons(CT_IPPORT_TFTP);

    if (OVS_UNLIKELY(tp_dst)) {
        if (helper && !strncmp(helper, "ftp", strlen("ftp"))) {
            ftp_dst_port = tp_dst;
        } else if (helper && !strncmp(helper, "tftp", strlen("tftp"))) {
            tftp_dst_port = tp_dst;
        }
    } else if (OVS_UNLIKELY(tp_src)) {
        if (helper && !strncmp(helper, "ftp", strlen("ftp"))) {
            ftp_src_port = tp_src;
        }
    }

    if (ip_proto == IPPROTO_UDP && uh->udp_dst == tftp_dst_port) {
        return CT_ALG_CTL_TFTP;
    } else if (ip_proto == IPPROTO_TCP &&
               (th->tcp_src == ftp_src_port || th->tcp_dst == ftp_dst_port)) {
        return CT_ALG_CTL_FTP;
    }
    return CT_ALG_CTL_NONE;
}

static bool
alg_src_ip_wc(enum ct_alg_ctl_type alg_ctl_type)
{
    if (alg_ctl_type == CT_ALG_CTL_SIP) {
        return true;
    }
    return false;
}

static void
handle_alg_ctl(const struct conn_lookup_ctx *ctx, struct dp_packet *pkt,
               enum ct_alg_ctl_type ct_alg_ctl, const struct conn *conn,
               long long now, bool nat)
{
    /* ALG control packet handling with expectation creation. */
    if (OVS_UNLIKELY(alg_helpers[ct_alg_ctl] && conn && conn->ext_alg &&
                     conn->ext_alg->alg)) {
        ovs_mutex_lock(&conn->lock.lock);
        alg_helpers[ct_alg_ctl](ctx, pkt, conn, now, CT_FTP_CTL_INTEREST,
                                nat);
        ovs_mutex_unlock(&conn->lock.lock);
    }
}

static void
pat_packet(struct dp_packet *pkt, const struct conn *conn)
{
    if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, conn->rev_key.dst.port, th->tcp_dst);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, conn->rev_key.dst.port, uh->udp_dst);
        }
    } else if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, th->tcp_src, conn->rev_key.src.port);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, uh->udp_src, conn->rev_key.src.port);
        }
    }
}

static void
nat_packet(struct dp_packet *pkt, const struct conn *conn, bool related)
{
    if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
        pkt->md.ct_state |= CS_SRC_NAT;
        if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *nh = dp_packet_l3(pkt);
            packet_set_ipv4_addr(pkt, &nh->ip_src,
                                 conn->rev_key.dst.addr.ipv4_aligned);
        } else {
            struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 nh6->ip6_src.be32,
                                 &conn->rev_key.dst.addr.ipv6_aligned,
                                 true);
        }
        if (!related) {
            pat_packet(pkt, conn);
        }
    } else if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST) {
        pkt->md.ct_state |= CS_DST_NAT;
        if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *nh = dp_packet_l3(pkt);
            packet_set_ipv4_addr(pkt, &nh->ip_dst,
                                 conn->rev_key.src.addr.ipv4_aligned);
        } else {
            struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 nh6->ip6_dst.be32,
                                 &conn->rev_key.src.addr.ipv6_aligned,
                                 true);
        }
        if (!related) {
            pat_packet(pkt, conn);
        }
    }
}

static void
un_pat_packet(struct dp_packet *pkt, const struct conn *conn)
{
    if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, th->tcp_src, conn->key.src.port);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, uh->udp_src, conn->key.src.port);
        }
    } else if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, conn->key.dst.port, th->tcp_dst);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, conn->key.dst.port, uh->udp_dst);
        }
    }
}

static void
reverse_pat_packet(struct dp_packet *pkt, const struct conn *conn)
{
    if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th_in = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, conn->key.src.port,
                                th_in->tcp_dst);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh_in = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, conn->key.src.port,
                                uh_in->udp_dst);
        }
    } else if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST) {
        if (conn->key.nw_proto == IPPROTO_TCP) {
            struct tcp_header *th_in = dp_packet_l4(pkt);
            packet_set_tcp_port(pkt, th_in->tcp_src,
                                conn->key.dst.port);
        } else if (conn->key.nw_proto == IPPROTO_UDP) {
            struct udp_header *uh_in = dp_packet_l4(pkt);
            packet_set_udp_port(pkt, uh_in->udp_src,
                                conn->key.dst.port);
        }
    }
}

static void
reverse_nat_packet(struct dp_packet *pkt, const struct conn *conn)
{
    char *tail = dp_packet_tail(pkt);
    char pad = dp_packet_l2_pad_size(pkt);
    struct conn_key inner_key;
    const char *inner_l4 = NULL;
    uint16_t orig_l3_ofs = pkt->l3_ofs;
    uint16_t orig_l4_ofs = pkt->l4_ofs;

    if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
        struct ip_header *nh = dp_packet_l3(pkt);
        struct icmp_header *icmp = dp_packet_l4(pkt);
        struct ip_header *inner_l3 = (struct ip_header *) (icmp + 1);
        extract_l3_ipv4(&inner_key, inner_l3, tail - ((char *)inner_l3) - pad,
                        &inner_l4, false);
        pkt->l3_ofs += (char *) inner_l3 - (char *) nh;
        pkt->l4_ofs += inner_l4 - (char *) icmp;

        if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
            packet_set_ipv4_addr(pkt, &inner_l3->ip_src,
                                 conn->key.src.addr.ipv4_aligned);
        } else if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST) {
            packet_set_ipv4_addr(pkt, &inner_l3->ip_dst,
                                 conn->key.dst.addr.ipv4_aligned);
        }

        reverse_pat_packet(pkt, conn);
        icmp->icmp_csum = 0;
        icmp->icmp_csum = csum(icmp, tail - (char *) icmp - pad);
    } else {
        struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
        struct icmp6_error_header *icmp6 = dp_packet_l4(pkt);
        struct ovs_16aligned_ip6_hdr *inner_l3_6 =
            (struct ovs_16aligned_ip6_hdr *) (icmp6 + 1);
        extract_l3_ipv6(&inner_key, inner_l3_6,
                        tail - ((char *)inner_l3_6) - pad,
                        &inner_l4);
        pkt->l3_ofs += (char *) inner_l3_6 - (char *) nh6;
        pkt->l4_ofs += inner_l4 - (char *) icmp6;

        if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 inner_l3_6->ip6_src.be32,
                                 &conn->key.src.addr.ipv6_aligned,
                                 true);
        } else if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST) {
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 inner_l3_6->ip6_dst.be32,
                                 &conn->key.dst.addr.ipv6_aligned,
                                 true);
        }
        reverse_pat_packet(pkt, conn);
        uint32_t icmp6_csum = packet_csum_pseudoheader6(nh6);
        icmp6->icmp6_base.icmp6_cksum = 0;
        icmp6->icmp6_base.icmp6_cksum = csum_finish(
            csum_continue(icmp6_csum, icmp6, tail - (char *) icmp6 - pad));
    }
    pkt->l3_ofs = orig_l3_ofs;
    pkt->l4_ofs = orig_l4_ofs;
}

static void
un_nat_packet(struct dp_packet *pkt, const struct conn *conn,
              bool related)
{
    if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
        pkt->md.ct_state |= CS_DST_NAT;
        if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *nh = dp_packet_l3(pkt);
            packet_set_ipv4_addr(pkt, &nh->ip_dst,
                                 conn->key.src.addr.ipv4_aligned);
        } else {
            struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 nh6->ip6_dst.be32,
                                 &conn->key.src.addr.ipv6_aligned, true);
        }

        if (OVS_UNLIKELY(related)) {
            reverse_nat_packet(pkt, conn);
        } else {
            un_pat_packet(pkt, conn);
        }
    } else if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST) {
        pkt->md.ct_state |= CS_SRC_NAT;
        if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *nh = dp_packet_l3(pkt);
            packet_set_ipv4_addr(pkt, &nh->ip_src,
                                 conn->key.dst.addr.ipv4_aligned);
        } else {
            struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
            packet_set_ipv6_addr(pkt, conn->key.nw_proto,
                                 nh6->ip6_src.be32,
                                 &conn->key.dst.addr.ipv6_aligned, true);
        }

        if (OVS_UNLIKELY(related)) {
            reverse_nat_packet(pkt, conn);
        } else {
            un_pat_packet(pkt, conn);
        }
    }
}

static void
conn_seq_skew_set(const struct conn_key *key, long long now, int seq_skew,
                  bool seq_skew_dir)
{
    struct conn *conn;
    bool reply;
    uint32_t hash = conn_key_hash(key, hash_basis);
    conn_key_lookup(key, hash, now, &conn, &reply);

    if (conn && seq_skew) {
        conn->ext_alg->seq_skew = seq_skew;
        conn->ext_alg->seq_skew_dir = seq_skew_dir;
    }
}

static bool
ct_verify_helper(const char *helper, enum ct_alg_ctl_type ct_alg_ctl)
{
    if (ct_alg_ctl == CT_ALG_CTL_NONE) {
        return true;
    } else if (helper) {
        if ((ct_alg_ctl == CT_ALG_CTL_FTP) &&
             !strncmp(helper, "ftp", strlen("ftp"))) {
            return true;
        } else if ((ct_alg_ctl == CT_ALG_CTL_TFTP) &&
                   !strncmp(helper, "tftp", strlen("tftp"))) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

static struct conn *
conn_not_found(struct dp_packet *pkt, struct conn_lookup_ctx *ctx,
               bool commit, long long now,
               const struct nat_action_info_t *nat_action_info,
               const char *helper, const struct alg_exp_node *alg_exp,
               enum ct_alg_ctl_type ct_alg_ctl)
{
    struct conn *nc = NULL;
    struct conn *nat_conn = NULL;

    if (!valid_new(pkt, &ctx->key)) {
        pkt->md.ct_state = CS_INVALID;
        return nc;
    }

    pkt->md.ct_state = CS_NEW;

    if (alg_exp) {
        pkt->md.ct_state |= CS_RELATED;
    }

    if (commit) {
        unsigned int n_conn_limit_;
        atomic_read_relaxed(&n_conn_limit, &n_conn_limit_);

        if (atomic_count_get(&n_conn) >= n_conn_limit_) {
            COVERAGE_INC(conntrack_full);
            return nc;
        }

        nc = new_conn(pkt, &ctx->key, now);
        ctx->conn = nc;
        nc->rev_key = nc->key;
        conn_key_reverse(&nc->rev_key);

        if (alg_exp || helper || ct_alg_ctl != CT_ALG_CTL_NONE) {
            nc->ext_alg = xzalloc(sizeof *nc->ext_alg);
        }

        if (nat_action_info) {
            nc->ext_nat = xzalloc(sizeof *nc->ext_nat);
        }

        if (nc->ext_alg && ct_verify_helper(helper, ct_alg_ctl)) {
            nc->ext_alg->alg = nullable_xstrdup(helper);
        }

        if (alg_exp) {
            nc->ext_alg->alg_related = true;
            nc->mark = alg_exp->master_mark;
            nc->label = alg_exp->master_label;
            nc->ext_alg->master_key = alg_exp->master_key;
        }

        if (nat_action_info) {
            nc->ext_nat->nat_info = xmemdup(nat_action_info,
                                        sizeof *nc->ext_nat->nat_info);

            nat_conn = xzalloc(sizeof *nat_conn);

            if (alg_exp) {
                if (alg_exp->nat_rpl_dst) {
                    nc->rev_key.dst.addr = alg_exp->alg_nat_repl_addr;
                    nc->ext_nat->nat_info->nat_action = NAT_ACTION_SRC;
                } else {
                    nc->rev_key.src.addr = alg_exp->alg_nat_repl_addr;
                    nc->ext_nat->nat_info->nat_action = NAT_ACTION_DST;
                }
                *nat_conn = *nc;
            } else {
                *nat_conn = *nc;
                bool nat_res = nat_select_range_tuple(nc, nat_conn);

                if (!nat_res) {
                    goto nat_res_exhaustion;
                }

                /* Update nc with nat adjustments. */
                *nc = *nat_conn;
            }
            nc->ext_nat->nat_conn = nat_conn;
            nat_packet(pkt, nc, ctx->icmp_related);

            nat_conn->key = nc->rev_key;
            nat_conn->rev_key = nc->key;
            nat_conn->conn_type = CT_CONN_TYPE_UN_NAT;
            nat_conn->ext_nat = NULL;
            nat_conn->ext_alg = NULL;
            uint32_t nat_hash = conn_key_hash(&nat_conn->key,
                                              hash_basis);
            cmap_insert(&cm_conns, &nat_conn->cm_node, nat_hash);
        }

        ovs_mutex_init_adaptive(&nc->lock.lock);
        nc->conn_type = CT_CONN_TYPE_DEFAULT;
        cmap_insert(&cm_conns, &nc->cm_node, ctx->hash);
        nc->inserted = true;
        atomic_count_inc(&n_conn);
    }

    return nc;

    /* This would be a user error or a DOS attack.  A user error is prevented
     * by allocating enough combinations of NAT addresses when combined with
     * ephemeral ports.  A DOS attack should be protected against with
     * firewall rules or a separate firewall.  Also using zone partitioning
     * can limit DoS impact. */
nat_res_exhaustion:
    free(nat_conn);
    ovs_list_remove(&nc->exp_node);
    delete_conn_cmn(nc);
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    VLOG_WARN_RL(&rl, "Unable to NAT due to tuple space exhaustion - "
                 "if DoS attack, use firewalling and/or zone partitioning.");
    return NULL;
}

static bool
conn_update_state(struct dp_packet *pkt, struct conn_lookup_ctx *ctx,
                  struct conn *conn, long long now)
{
    ovs_assert(conn->conn_type == CT_CONN_TYPE_DEFAULT);

    bool create_new_conn = false;

    if (ctx->icmp_related) {
        pkt->md.ct_state |= CS_RELATED;
        if (ctx->reply) {
            pkt->md.ct_state |= CS_REPLY_DIR;
        }
    } else {
        if (conn->ext_alg && conn->ext_alg->alg_related) {
            pkt->md.ct_state |= CS_RELATED;
        }

        enum ct_update_res res = conn_update(pkt, conn, ctx, now);

        switch (res) {
        case CT_UPDATE_VALID:
            pkt->md.ct_state |= CS_ESTABLISHED;
            pkt->md.ct_state &= ~CS_NEW;
            if (ctx->reply) {
                pkt->md.ct_state |= CS_REPLY_DIR;
            }
            break;
        case CT_UPDATE_INVALID:
            pkt->md.ct_state = CS_INVALID;
            break;
        case CT_UPDATE_NEW:
            ovs_mutex_lock(&ct_lock.lock);
            conn_clean(conn);
            ovs_mutex_unlock(&ct_lock.lock);
            create_new_conn = true;
            break;
        default:
            OVS_NOT_REACHED();
        }
    }
    return create_new_conn;
}

static void
handle_nat(struct dp_packet *pkt, struct conn *conn,
           uint16_t zone, bool reply, bool related)
{
    if (conn->ext_nat && conn->ext_nat->nat_info &&
        (!(pkt->md.ct_state & (CS_SRC_NAT | CS_DST_NAT)) ||
          (pkt->md.ct_state & (CS_SRC_NAT | CS_DST_NAT) &&
           zone != pkt->md.ct_zone))) {

        if (pkt->md.ct_state & (CS_SRC_NAT | CS_DST_NAT)) {
            pkt->md.ct_state &= ~(CS_SRC_NAT | CS_DST_NAT);
        }
        if (reply) {
            un_nat_packet(pkt, conn, related);
        } else {
            nat_packet(pkt, conn, related);
        }
    }
}

static bool
check_orig_tuple(struct dp_packet *pkt, struct conn_lookup_ctx *ctx_in,
                 long long now, struct conn **conn,
                 const struct nat_action_info_t *nat_action_info)
{
    if ((ctx_in->key.dl_type == htons(ETH_TYPE_IP) &&
         !pkt->md.ct_orig_tuple.ipv4.ipv4_proto) ||
        (ctx_in->key.dl_type == htons(ETH_TYPE_IPV6) &&
         !pkt->md.ct_orig_tuple.ipv6.ipv6_proto) ||
        !(pkt->md.ct_state & (CS_SRC_NAT | CS_DST_NAT)) ||
        nat_action_info) {
        return false;
    }

    struct conn_key key;
    memset(&key, 0 , sizeof key);

    if (ctx_in->key.dl_type == htons(ETH_TYPE_IP)) {
        key.src.addr.ipv4_aligned = pkt->md.ct_orig_tuple.ipv4.ipv4_src;
        key.dst.addr.ipv4_aligned = pkt->md.ct_orig_tuple.ipv4.ipv4_dst;

        if (ctx_in->key.nw_proto == IPPROTO_ICMP) {
            key.src.icmp_id = ctx_in->key.src.icmp_id;
            key.dst.icmp_id = ctx_in->key.dst.icmp_id;
            uint16_t src_port = ntohs(pkt->md.ct_orig_tuple.ipv4.src_port);
            key.src.icmp_type = (uint8_t) src_port;
            key.dst.icmp_type = reverse_icmp_type(key.src.icmp_type);
        } else {
            key.src.port = pkt->md.ct_orig_tuple.ipv4.src_port;
            key.dst.port = pkt->md.ct_orig_tuple.ipv4.dst_port;
        }
        key.nw_proto = pkt->md.ct_orig_tuple.ipv4.ipv4_proto;
    } else {
        key.src.addr.ipv6_aligned = pkt->md.ct_orig_tuple.ipv6.ipv6_src;
        key.dst.addr.ipv6_aligned = pkt->md.ct_orig_tuple.ipv6.ipv6_dst;

        if (ctx_in->key.nw_proto == IPPROTO_ICMPV6) {
            key.src.icmp_id = ctx_in->key.src.icmp_id;
            key.dst.icmp_id = ctx_in->key.dst.icmp_id;
            uint16_t src_port = ntohs(pkt->md.ct_orig_tuple.ipv6.src_port);
            key.src.icmp_type = (uint8_t) src_port;
            key.dst.icmp_type = reverse_icmp6_type(key.src.icmp_type);
        } else {
            key.src.port = pkt->md.ct_orig_tuple.ipv6.src_port;
            key.dst.port = pkt->md.ct_orig_tuple.ipv6.dst_port;
        }
        key.nw_proto = pkt->md.ct_orig_tuple.ipv6.ipv6_proto;
    }

    key.dl_type = ctx_in->key.dl_type;
    key.zone = pkt->md.ct_zone;
    uint32_t hash = conn_key_hash(&key, hash_basis);
    bool reply;
    conn_key_lookup(&key, hash, now, conn, &reply);

    return *conn ? true : false;
}

static bool
conn_update_state_alg(struct dp_packet *pkt, struct conn_lookup_ctx *ctx,
                      struct conn *conn,
                      const struct nat_action_info_t *nat_action_info,
                      enum ct_alg_ctl_type ct_alg_ctl, long long now,
                      bool *create_new_conn)
{
    if (is_ftp_ctl(ct_alg_ctl)) {
        /* Keep sequence tracking in sync with the source of the
         * sequence skew. */
        ovs_mutex_lock(&conn->lock.lock);
        if (ctx->reply != conn->ext_alg->seq_skew_dir) {
            handle_ftp_ctl(ctx, pkt, conn, now, CT_FTP_CTL_OTHER,
                           !!nat_action_info);
            /* conn_update_state locks for unrelated fields, so unlock. */
            ovs_mutex_unlock(&conn->lock.lock);
            *create_new_conn = conn_update_state(pkt, ctx, conn, now);
        } else {
            /* conn_update_state locks for unrelated fields, so unlock. */
            ovs_mutex_unlock(&conn->lock.lock);
            *create_new_conn = conn_update_state(pkt, ctx, conn, now);
            ovs_mutex_lock(&conn->lock.lock);
            if (*create_new_conn == false) {
                handle_ftp_ctl(ctx, pkt, conn, now, CT_FTP_CTL_OTHER,
                               !!nat_action_info);
            }
            ovs_mutex_unlock(&conn->lock.lock);
        }
        return true;
    }
    return false;
}

static void
process_one(struct dp_packet *pkt, struct conn_lookup_ctx *ctx, uint16_t zone,
            bool force, bool commit, long long now,
            const uint32_t *setmark,
            const struct ovs_key_ct_labels *setlabel,
            const struct nat_action_info_t *nat_action_info,
            ovs_be16 tp_src, ovs_be16 tp_dst, const char *helper)
{
    bool create_new_conn = false;
    conn_key_lookup(&ctx->key, ctx->hash, now, &ctx->conn, &ctx->reply);
    struct conn *conn = ctx->conn;

    /* Delete found entry if in wrong direction. 'force' implies commit. */
    if (conn && force && ctx->reply) {
        ovs_mutex_lock(&ct_lock.lock);
        conn_clean(conn);
        ovs_mutex_unlock(&ct_lock.lock);
        conn = NULL;
    }

    if (OVS_LIKELY(conn)) {
        if (conn->conn_type == CT_CONN_TYPE_UN_NAT) {
            ctx->reply = true;
            struct conn *rev_conn = conn;  /* Save for debugging. */
            uint32_t hash = conn_key_hash(&conn->rev_key, hash_basis);
            conn_key_lookup(&ctx->key, hash, now, &conn, &ctx->reply);

            if (!conn) {
                pkt->md.ct_state |= CS_TRACKED | CS_INVALID;
                char *log_msg = xasprintf("Missing master conn %p", rev_conn);
                ct_print_conn_info(conn, log_msg, VLL_INFO, true, true);
                free(log_msg);
                return;
            }
        }
    }

    enum ct_alg_ctl_type ct_alg_ctl = get_alg_ctl_type(pkt, tp_src, tp_dst,
                                                       helper);

    if (OVS_LIKELY(conn)) {
        if (OVS_LIKELY(!conn_update_state_alg(pkt, ctx, conn,
                                              nat_action_info,
                                              ct_alg_ctl, now,
                                              &create_new_conn))) {

            create_new_conn = conn_update_state(pkt, ctx, conn, now);
        }
        if (nat_action_info && !create_new_conn) {
            handle_nat(pkt, conn, zone, ctx->reply, ctx->icmp_related);
        }
    } else if (check_orig_tuple(pkt, ctx, now, &conn, nat_action_info)) {
        create_new_conn = conn_update_state(pkt, ctx, conn, now);
    } else {
        if (ctx->icmp_related) {
            /* An icmp related conn should always be found; no new
               connection is created based on an icmp related packet. */
            pkt->md.ct_state = CS_INVALID;
        } else {
            create_new_conn = true;
        }
    }

    const struct alg_exp_node *alg_exp = NULL;
    struct alg_exp_node alg_exp_entry;

    if (OVS_UNLIKELY(create_new_conn)) {
        ovs_rwlock_rdlock(&resources_lock.lock);
        alg_exp = expectation_lookup(&alg_expectations, &ctx->key,
                                     hash_basis,
                                     alg_src_ip_wc(ct_alg_ctl));
        if (alg_exp) {
            alg_exp_entry = *alg_exp;
            alg_exp = &alg_exp_entry;
        }
        ovs_rwlock_unlock(&resources_lock.lock);

        ovs_mutex_lock(&ct_lock.lock);
        conn = conn_not_found(pkt, ctx, commit, now, nat_action_info,
                              helper, alg_exp, ct_alg_ctl);
        ovs_mutex_unlock(&ct_lock.lock);
    }

    write_ct_md(pkt, zone, conn, &ctx->key, alg_exp);

    if (conn && setmark) {
        set_mark(pkt, conn, setmark[0], setmark[1]);
    }

    if (conn && setlabel) {
        set_label(pkt, conn, &setlabel[0], &setlabel[1]);
    }

    handle_alg_ctl(ctx, pkt, ct_alg_ctl, conn, now, !!nat_action_info);

    if (nat_action_info && ct_alg_ctl == CT_ALG_CTL_NONE) {
        pkt->md.conn = conn;
        pkt->md.reply = ctx->reply;
        pkt->md.icmp_related = ctx->icmp_related;
    } else {
        pkt->md.conn = NULL;
    }
}

static inline void
process_one_fast(struct dp_packet *pkt, uint16_t zone,
                 const uint32_t *setmark,
                 const struct ovs_key_ct_labels *setlabel,
                 const struct nat_action_info_t *nat_action_info,
                 struct conn *conn)
{
    if (nat_action_info) {
        handle_nat(pkt, conn, zone, pkt->md.reply, pkt->md.icmp_related);
        pkt->md.conn = NULL;
    }

    pkt->md.ct_zone = zone;
    pkt->md.ct_mark = conn->mark;
    pkt->md.ct_label = conn->label;

    if (setmark) {
        set_mark(pkt, conn, setmark[0], setmark[1]);
    }

    if (setlabel) {
        set_label(pkt, conn, &setlabel[0], &setlabel[1]);
    }
}

/* Sends the packets in '*pkt_batch' through the connection tracker 'ct'.  All
 * the packets must have the same 'dl_type' (IPv4 or IPv6) and should have
 * the l3 and and l4 offset properly set.
 *
 * If 'commit' is true, the packets are allowed to create new entries in the
 * connection tables.  'setmark', if not NULL, should point to a two
 * elements array containing a value and a mask to set the connection mark.
 * 'setlabel' behaves similarly for the connection label.*/
int
conntrack_execute(struct dp_packet_batch *pkt_batch, ovs_be16 dl_type,
                  bool force, bool commit, uint16_t zone,
                  const uint32_t *setmark,
                  const struct ovs_key_ct_labels *setlabel,
                  ovs_be16 tp_src, ovs_be16 tp_dst, const char *helper,
                  const struct nat_action_info_t *nat_action_info,
                  long long now)
{
    struct dp_packet *packet;
    struct conn_lookup_ctx ctx;

    DP_PACKET_BATCH_FOR_EACH (i, packet, pkt_batch) {
        struct conn *conn = packet->md.conn;
        if (OVS_UNLIKELY(packet->md.ct_state == CS_INVALID)) {
            write_ct_md(packet, zone, NULL, NULL, NULL);
                continue;
        } else if (conn && !force && !commit && conn->key.zone == zone) {
            process_one_fast(packet, zone, setmark, setlabel, nat_action_info,
                             packet->md.conn);
            continue;
        } else if (OVS_UNLIKELY(!conn_key_extract(packet, dl_type, &ctx,
                                zone))) {
            packet->md.ct_state = CS_INVALID;
            write_ct_md(packet, zone, NULL, NULL, NULL);
            continue;
        }
        process_one(packet, &ctx, zone, force, commit, now, setmark,
                    setlabel, nat_action_info, tp_src, tp_dst, helper);
    }

    return 0;
}

void
conntrack_clear(struct dp_packet *packet)
{
    /* According to pkt_metadata_init(), ct_state == 0 is enough to make all of
     * the conntrack fields invalid. */
    packet->md.ct_state = 0;
    packet->md.conn = NULL;
}

static void
set_mark(struct dp_packet *pkt, struct conn *conn, uint32_t val, uint32_t mask)
{
    if (conn->ext_alg && conn->ext_alg->alg_related) {
        pkt->md.ct_mark = conn->mark;
    } else {
        pkt->md.ct_mark = val | (pkt->md.ct_mark & ~(mask));
        conn->mark = pkt->md.ct_mark;
    }
}

static void
set_label(struct dp_packet *pkt, struct conn *conn,
          const struct ovs_key_ct_labels *val,
          const struct ovs_key_ct_labels *mask)
{
    if (conn->ext_alg && conn->ext_alg->alg_related) {
        pkt->md.ct_label = conn->label;
    } else {
        ovs_u128 v, m;

        memcpy(&v, val, sizeof v);
        memcpy(&m, mask, sizeof m);

        pkt->md.ct_label.u64.lo = v.u64.lo
                              | (pkt->md.ct_label.u64.lo & ~(m.u64.lo));
        pkt->md.ct_label.u64.hi = v.u64.hi
                              | (pkt->md.ct_label.u64.hi & ~(m.u64.hi));
        conn->label = pkt->md.ct_label;
    }
}


/* Delete the expired connections, up to 'limit'. Returns the earliest
 * expiration time among the remaining connections in all expiration lists.
 * Returns LLONG_MAX if all expiration lists are empty.  The return value
 * might be smaller than 'now',if 'limit' is reached */
static long long
ct_sweep(long long now, size_t limit)
{
    struct conn *conn, *next;
    long long min_expiration = LLONG_MAX;
    size_t count = 0;

    ovs_mutex_lock(&ct_lock.lock);

    for (unsigned i = 0; i < N_CT_TM; i++) {
        LIST_FOR_EACH_SAFE (conn, next, exp_node, &cm_exp_lists[i]) {
            if (conn->conn_type == CT_CONN_TYPE_DEFAULT) {
                ovs_mutex_lock(&conn->lock.lock);
                if (conn->exp_list_id != NO_UPD_EXP_LIST) {
                    ovs_list_remove(&conn->exp_node);
                    ovs_list_push_back(&cm_exp_lists[conn->exp_list_id],
                                       &conn->exp_node);
                    conn->exp_list_id = NO_UPD_EXP_LIST;
                    ovs_mutex_unlock(&conn->lock.lock);
                } else if (!conn_expired(conn, now) || count >= limit) {
                    min_expiration = MIN(min_expiration, conn->expiration);
                    ovs_mutex_unlock(&conn->lock.lock);
                    if (count >= limit) {
                        /* Do not check other lists. */
                        COVERAGE_INC(conntrack_long_cleanup);
                        goto out;
                    }
                    break;
                } else {
                    /* Not looking at conn changable fields. */
                    ovs_mutex_unlock(&conn->lock.lock);
                    if (conn->inserted) {
                        conn_clean(conn);
                    } else {
                        break;
                    }
                }
                count++;
            }
        }
    }

out:
    VLOG_DBG("conntrack cleanup %"PRIuSIZE" entries in %lld msec", count,
             time_msec() - now);
    ovs_mutex_unlock(&ct_lock.lock);
    return min_expiration;
}

/* Cleans up old connection entries from 'ct'.  Returns the time when the
 * next expiration might happen.  The return value might be smaller than
 * 'now', meaning that an internal limit has been reached, and some expired
 * connections have not been deleted. */
static long long
conntrack_clean(long long now)
{
    unsigned int n_conn_limit_;
    atomic_read_relaxed(&n_conn_limit, &n_conn_limit_);

    long long min_exp = ct_sweep(now, n_conn_limit_ / 50);
    long long next_wakeup = MIN(min_exp, now + CT_TM_MIN);
    return next_wakeup;
}

/* Cleanup:
 *
 * We must call conntrack_clean() periodically.  conntrack_clean() return
 * value gives an hint on when the next cleanup must be done (either because
 * there is an actual connection that expires, or because a new connection
 * might be created with the minimum timeout).
 *
 * The logic below has two goals:
 *
 * - We want to reduce the number of wakeups and batch connection cleanup
 *   when the load is not very high.  CT_CLEAN_INTERVAL ensures that if we
 *   are coping with the current cleanup tasks, then we wait at least
 *   5 seconds to do further cleanup.
 *
 * - We don't want to keep the map locked too long, as we might prevent
 *   traffic from flowing.  CT_CLEAN_MIN_INTERVAL ensures that if cleanup is
 *   behind, there is at least some 200ms blocks of time when the map will be
 *   left alone, so the datapath can operate unhindered.
 */
#define CT_CLEAN_INTERVAL 5000 /* 5 seconds */
#define CT_CLEAN_MIN_INTERVAL 200  /* 0.2 seconds */

static void *
clean_thread_main(void *f OVS_UNUSED)
{
    while (!latch_is_set(&clean_thread_exit)) {
        long long next_wake;
        long long now = time_msec();
        next_wake = conntrack_clean(now);

        if (next_wake < now) {
            poll_timer_wait_until(now + CT_CLEAN_MIN_INTERVAL);
        } else {
            poll_timer_wait_until(MAX(next_wake, now + CT_CLEAN_INTERVAL));
        }
        latch_wait(&clean_thread_exit);
        poll_block();
    }

    return NULL;
}

/* 'Data' is a pointer to the beginning of the L3 header and 'new_data' is
 * used to store a pointer to the first byte after the L3 header.  'Size' is
 * the size of the packet beyond the data pointer. */
static inline bool
extract_l3_ipv4(struct conn_key *key, const void *data, size_t size,
                const char **new_data, bool validate_checksum)
{
    if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
        return false;
    }

    const struct ip_header *ip = data;
    size_t ip_len = IP_IHL(ip->ip_ihl_ver) * 4;

    if (OVS_UNLIKELY(ip_len < IP_HEADER_LEN)) {
        return false;
    }

    if (OVS_UNLIKELY(size < ip_len)) {
        return false;
    }

    if (IP_IS_FRAGMENT(ip->ip_frag_off)) {
        return false;
    }

    if (validate_checksum && csum(data, ip_len) != 0) {
        return false;
    }

    if (new_data) {
        *new_data = (char *) data + ip_len;
    }

    key->src.addr.ipv4 = ip->ip_src;
    key->dst.addr.ipv4 = ip->ip_dst;
    key->nw_proto = ip->ip_proto;

    return true;
}

/* 'Data' is a pointer to the beginning of the L3 header and 'new_data' is
 * used to store a pointer to the first byte after the L3 header.  'Size' is
 * the size of the packet beyond the data pointer. */
static inline bool
extract_l3_ipv6(struct conn_key *key, const void *data, size_t size,
                const char **new_data)
{
    const struct ovs_16aligned_ip6_hdr *ip6 = data;

    if (OVS_UNLIKELY(size < sizeof *ip6)) {
        return false;
    }

    data = ip6 + 1;
    size -=  sizeof *ip6;
    uint8_t nw_proto = ip6->ip6_nxt;
    uint8_t nw_frag = 0;

    if (!parse_ipv6_ext_hdrs(&data, &size, &nw_proto, &nw_frag)) {
        return false;
    }

    if (nw_frag) {
        return false;
    }

    if (new_data) {
        *new_data = data;
    }

    key->src.addr.ipv6 = ip6->ip6_src;
    key->dst.addr.ipv6 = ip6->ip6_dst;
    key->nw_proto = nw_proto;

    return true;
}

static inline bool
checksum_valid(const struct conn_key *key, const void *data, size_t size,
               const void *l3)
{
    uint32_t csum = 0;

    if (key->dl_type == htons(ETH_TYPE_IP)) {
        csum = packet_csum_pseudoheader(l3);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)) {
        csum = packet_csum_pseudoheader6(l3);
    } else {
        return false;
    }

    csum = csum_continue(csum, data, size);

    return csum_finish(csum) == 0;
}

static inline bool
check_l4_tcp(const struct conn_key *key, const void *data, size_t size,
             const void *l3, bool validate_checksum)
{
    const struct tcp_header *tcp = data;
    if (size < sizeof *tcp) {
        return false;
    }

    size_t tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;
    if (OVS_UNLIKELY(tcp_len < TCP_HEADER_LEN || tcp_len > size)) {
        return false;
    }

    return validate_checksum ? checksum_valid(key, data, size, l3) : true;
}

static inline bool
check_l4_udp(const struct conn_key *key, const void *data, size_t size,
             const void *l3, bool validate_checksum)
{
    const struct udp_header *udp = data;
    if (size < sizeof *udp) {
        return false;
    }

    size_t udp_len = ntohs(udp->udp_len);
    if (OVS_UNLIKELY(udp_len < UDP_HEADER_LEN || udp_len > size)) {
        return false;
    }

    /* Validation must be skipped if checksum is 0 on IPv4 packets */
    return (udp->udp_csum == 0 && key->dl_type == htons(ETH_TYPE_IP))
           || (validate_checksum ? checksum_valid(key, data, size, l3) : true);
}

static inline bool
check_l4_icmp(const void *data, size_t size, bool validate_checksum)
{
    return validate_checksum ? csum(data, size) == 0 : true;
}

static inline bool
check_l4_icmp6(const struct conn_key *key, const void *data, size_t size,
               const void *l3, bool validate_checksum)
{
    return validate_checksum ? checksum_valid(key, data, size, l3) : true;
}

static inline bool
extract_l4_tcp(struct conn_key *key, const void *data, size_t size)
{
    if (OVS_UNLIKELY(size < TCP_HEADER_LEN)) {
        return false;
    }

    const struct tcp_header *tcp = data;
    key->src.port = tcp->tcp_src;
    key->dst.port = tcp->tcp_dst;

    /* Port 0 is invalid */
    return key->src.port && key->dst.port;
}

static inline bool
extract_l4_udp(struct conn_key *key, const void *data, size_t size)
{
    if (OVS_UNLIKELY(size < UDP_HEADER_LEN)) {
        return false;
    }

    const struct udp_header *udp = data;
    key->src.port = udp->udp_src;
    key->dst.port = udp->udp_dst;

    /* Port 0 is invalid */
    return key->src.port && key->dst.port;
}

static inline bool extract_l4(struct conn_key *key, const void *data,
                              size_t size, bool *related, const void *l3,
                              bool validate_checksum);

static uint8_t
reverse_icmp_type(uint8_t type)
{
    switch (type) {
    case ICMP4_ECHO_REQUEST:
        return ICMP4_ECHO_REPLY;
    case ICMP4_ECHO_REPLY:
        return ICMP4_ECHO_REQUEST;

    case ICMP4_TIMESTAMP:
        return ICMP4_TIMESTAMPREPLY;
    case ICMP4_TIMESTAMPREPLY:
        return ICMP4_TIMESTAMP;

    case ICMP4_INFOREQUEST:
        return ICMP4_INFOREPLY;
    case ICMP4_INFOREPLY:
        return ICMP4_INFOREQUEST;
    default:
        OVS_NOT_REACHED();
    }
}

/* If 'related' is not NULL and the function is processing an ICMP
 * error packet, extract the l3 and l4 fields from the nested header
 * instead and set *related to true.  If 'related' is NULL we're
 * already processing a nested header and no such recursion is
 * possible */
static inline int
extract_l4_icmp(struct conn_key *key, const void *data, size_t size,
                bool *related)
{
    if (OVS_UNLIKELY(size < ICMP_HEADER_LEN)) {
        return false;
    }

    const struct icmp_header *icmp = data;

    switch (icmp->icmp_type) {
    case ICMP4_ECHO_REQUEST:
    case ICMP4_ECHO_REPLY:
    case ICMP4_TIMESTAMP:
    case ICMP4_TIMESTAMPREPLY:
    case ICMP4_INFOREQUEST:
    case ICMP4_INFOREPLY:
        if (icmp->icmp_code != 0) {
            return false;
        }
        /* Separate ICMP connection: identified using id */
        key->src.icmp_id = key->dst.icmp_id = icmp->icmp_fields.echo.id;
        key->src.icmp_type = icmp->icmp_type;
        key->dst.icmp_type = reverse_icmp_type(icmp->icmp_type);
        break;
    case ICMP4_DST_UNREACH:
    case ICMP4_TIME_EXCEEDED:
    case ICMP4_PARAM_PROB:
    case ICMP4_SOURCEQUENCH:
    case ICMP4_REDIRECT: {
        /* ICMP packet part of another connection. We should
         * extract the key from embedded packet header */
        struct conn_key inner_key;
        const char *l3 = (const char *) (icmp + 1);
        const char *tail = (const char *) data + size;
        const char *l4;

        if (!related) {
            return false;
        }

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IP);
        bool ok = extract_l3_ipv4(&inner_key, l3, tail - l3, &l4, false);
        if (!ok) {
            return false;
        }

        if (inner_key.src.addr.ipv4_aligned != key->dst.addr.ipv4_aligned) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL, l3, false);
        if (ok) {
            conn_key_reverse(key);
            *related = true;
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

static uint8_t
reverse_icmp6_type(uint8_t type)
{
    switch (type) {
    case ICMP6_ECHO_REQUEST:
        return ICMP6_ECHO_REPLY;
    case ICMP6_ECHO_REPLY:
        return ICMP6_ECHO_REQUEST;
    default:
        OVS_NOT_REACHED();
    }
}

/* If 'related' is not NULL and the function is processing an ICMP
 * error packet, extract the l3 and l4 fields from the nested header
 * instead and set *related to true.  If 'related' is NULL we're
 * already processing a nested header and no such recursion is
 * possible */
static inline bool
extract_l4_icmp6(struct conn_key *key, const void *data, size_t size,
                 bool *related)
{
    const struct icmp6_header *icmp6 = data;

    /* All the messages that we support need at least 4 bytes after
     * the header */
    if (size < sizeof *icmp6 + 4) {
        return false;
    }

    switch (icmp6->icmp6_type) {
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        if (icmp6->icmp6_code != 0) {
            return false;
        }
        /* Separate ICMP connection: identified using id */
        key->src.icmp_id = key->dst.icmp_id = *(ovs_be16 *) (icmp6 + 1);
        key->src.icmp_type = icmp6->icmp6_type;
        key->dst.icmp_type = reverse_icmp6_type(icmp6->icmp6_type);
        break;
    case ICMP6_DST_UNREACH:
    case ICMP6_PACKET_TOO_BIG:
    case ICMP6_TIME_EXCEEDED:
    case ICMP6_PARAM_PROB: {
        /* ICMP packet part of another connection. We should
         * extract the key from embedded packet header */
        struct conn_key inner_key;
        const char *l3 = (const char *) icmp6 + 8;
        const char *tail = (const char *) data + size;
        const char *l4 = NULL;

        if (!related) {
            return false;
        }

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IPV6);
        bool ok = extract_l3_ipv6(&inner_key, l3, tail - l3, &l4);
        if (!ok) {
            return false;
        }

        /* pf doesn't do this, but it seems a good idea */
        if (!ipv6_addr_equals(&inner_key.src.addr.ipv6_aligned,
                              &key->dst.addr.ipv6_aligned)) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL, l3, false);
        if (ok) {
            conn_key_reverse(key);
            *related = true;
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

/* Extract l4 fields into 'key', which must already contain valid l3
 * members.
 *
 * If 'related' is not NULL and an ICMP error packet is being
 * processed, the function will extract the key from the packet nested
 * in the ICMP payload and set '*related' to true.
 *
 * If 'related' is NULL, it means that we're already parsing a header nested
 * in an ICMP error.  In this case, we skip checksum and length validation. */
static inline bool
extract_l4(struct conn_key *key, const void *data, size_t size, bool *related,
           const void *l3, bool validate_checksum)
{
    if (key->nw_proto == IPPROTO_TCP) {
        return (!related || check_l4_tcp(key, data, size, l3,
                validate_checksum)) && extract_l4_tcp(key, data, size);
    } else if (key->nw_proto == IPPROTO_UDP) {
        return (!related || check_l4_udp(key, data, size, l3,
                validate_checksum)) && extract_l4_udp(key, data, size);
    } else if (key->dl_type == htons(ETH_TYPE_IP)
               && key->nw_proto == IPPROTO_ICMP) {
        return (!related || check_l4_icmp(data, size, validate_checksum))
               && extract_l4_icmp(key, data, size, related);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)
               && key->nw_proto == IPPROTO_ICMPV6) {
        return (!related || check_l4_icmp6(key, data, size, l3,
                validate_checksum)) && extract_l4_icmp6(key, data, size,
                related);
    } else {
        return false;
    }
}

static bool
conn_key_extract(struct dp_packet *pkt, ovs_be16 dl_type,
                 struct conn_lookup_ctx *ctx, uint16_t zone)
{
    const struct eth_header *l2 = dp_packet_eth(pkt);
    const struct ip_header *l3 = dp_packet_l3(pkt);
    const char *l4 = dp_packet_l4(pkt);

    memset(ctx, 0, sizeof *ctx);

    if (!l2 || !l3 || !l4) {
        return false;
    }

    ctx->key.zone = zone;

    /* XXX In this function we parse the packet (again, it has already
     * gone through miniflow_extract()) for two reasons:
     *
     * 1) To extract the l3 addresses and l4 ports.
     *    We already have the l3 and l4 headers' pointers.  Extracting
     *    the l3 addresses and the l4 ports is really cheap, since they
     *    can be found at fixed locations.
     * 2) To extract the l4 type.
     *    Extracting the l4 types, for IPv6 can be quite expensive, because
     *    it's not at a fixed location.
     *
     * Here's a way to avoid (2) with the help of the datapath.
     * The datapath doesn't keep the packet's extracted flow[1], so
     * using that is not an option.  We could use the packet's matching
     * megaflow, but we have to make sure that the l4 type (nw_proto)
     * is unwildcarded.  This means either:
     *
     * a) dpif-netdev unwildcards the l4 type when a new flow is installed
     *    if the actions contains ct().
     *
     * b) ofproto-dpif-xlate unwildcards the l4 type when translating a ct()
     *    action.  This is already done in different actions, but it's
     *    unnecessary for the kernel.
     *
     * ---
     * [1] The reasons for this are that keeping the flow increases
     *     (slightly) the cache footprint and increases computation
     *     time as we move the packet around. Most importantly, the flow
     *     should be updated by the actions and this can be slow, as
     *     we use a sparse representation (miniflow).
     *
     */
    const char *tail = dp_packet_tail(pkt);
    bool ok;
    ctx->key.dl_type = dl_type;

    if (ctx->key.dl_type == htons(ETH_TYPE_IP)) {
        bool hwol_bad_l3_csum = dp_packet_ip_checksum_bad(pkt);
        if (hwol_bad_l3_csum) {
            ok = false;
        } else {
            bool hwol_good_l3_csum = dp_packet_ip_checksum_valid(pkt);
            /* Validate the checksum only when hwol is not supported. */
            ok = extract_l3_ipv4(&ctx->key, l3, tail - (char *) l3, NULL,
                                 !hwol_good_l3_csum);
        }
    } else if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        ok = extract_l3_ipv6(&ctx->key, l3, tail - (char *) l3, NULL);
    } else {
        ok = false;
    }

    if (ok) {
        bool hwol_bad_l4_csum = dp_packet_l4_checksum_bad(pkt);
        if (!hwol_bad_l4_csum) {
            bool  hwol_good_l4_csum = dp_packet_l4_checksum_valid(pkt);
            /* Validate the checksum only when hwol is not supported. */
            if (extract_l4(&ctx->key, l4, tail - l4, &ctx->icmp_related, l3,
                           !hwol_good_l4_csum)) {
                ctx->hash = conn_key_hash(&ctx->key, hash_basis);
                return true;
            }
        }
    }

    return false;
}

static uint32_t
ct_addr_hash_add(uint32_t hash, const struct ct_addr *addr)
{
    BUILD_ASSERT_DECL(sizeof *addr % 4 == 0);
    return hash_add_bytes32(hash, (const uint32_t *) addr, sizeof *addr);
}

static uint32_t
ct_endpoint_hash_add(uint32_t hash, const struct ct_endpoint *ep)
{
    BUILD_ASSERT_DECL(sizeof *ep % 4 == 0);
    return hash_add_bytes32(hash, (const uint32_t *) ep, sizeof *ep);
}

/* Symmetric */
static uint32_t
conn_key_hash(const struct conn_key *key, uint32_t basis)
{
    uint32_t hsrc, hdst, hash;
    hsrc = hdst = basis;
    hsrc = ct_endpoint_hash_add(hsrc, &key->src);
    hdst = ct_endpoint_hash_add(hdst, &key->dst);

    /* Even if source and destination are swapped the hash will be the same. */
    hash = hsrc ^ hdst;

    /* Hash the rest of the key(L3 and L4 types and zone). */
    hash = hash_words((uint32_t *) (&key->dst + 1),
                      (uint32_t *) (key + 1) - (uint32_t *) (&key->dst + 1),
                      hash);

    return hash_finish(hash, 0);
}

static void
conn_key_reverse(struct conn_key *key)
{
    struct ct_endpoint tmp = key->src;
    key->src = key->dst;
    key->dst = tmp;
}

static uint32_t
nat_ipv6_addrs_delta(struct in6_addr *ipv6_aligned_min,
                     struct in6_addr *ipv6_aligned_max)
{
    uint8_t *ipv6_min_hi = &ipv6_aligned_min->s6_addr[0];
    uint8_t *ipv6_min_lo = &ipv6_aligned_min->s6_addr[0] +  sizeof(uint64_t);
    uint8_t *ipv6_max_hi = &ipv6_aligned_max->s6_addr[0];
    uint8_t *ipv6_max_lo = &ipv6_aligned_max->s6_addr[0] + sizeof(uint64_t);

    ovs_be64 addr6_64_min_hi;
    ovs_be64 addr6_64_min_lo;
    memcpy(&addr6_64_min_hi, ipv6_min_hi, sizeof addr6_64_min_hi);
    memcpy(&addr6_64_min_lo, ipv6_min_lo, sizeof addr6_64_min_lo);

    ovs_be64 addr6_64_max_hi;
    ovs_be64 addr6_64_max_lo;
    memcpy(&addr6_64_max_hi, ipv6_max_hi, sizeof addr6_64_max_hi);
    memcpy(&addr6_64_max_lo, ipv6_max_lo, sizeof addr6_64_max_lo);

    uint64_t diff;

    if (addr6_64_min_hi == addr6_64_max_hi &&
        ntohll(addr6_64_min_lo) <= ntohll(addr6_64_max_lo)) {
        diff = ntohll(addr6_64_max_lo) - ntohll(addr6_64_min_lo);
    } else if (ntohll(addr6_64_min_hi) + 1 == ntohll(addr6_64_max_hi) &&
               ntohll(addr6_64_min_lo) > ntohll(addr6_64_max_lo)) {
        diff = UINT64_MAX - (ntohll(addr6_64_min_lo) -
                             ntohll(addr6_64_max_lo) - 1);
    } else {
        /* Limit address delta supported to 32 bits or 4 billion approximately.
         * Possibly, this should be visible to the user through a datapath
         * support check, however the practical impact is probably nil. */
        diff = 0xfffffffe;
    }

    if (diff > 0xfffffffe) {
        diff = 0xfffffffe;
    }
    return diff;
}

/* This function must be used in tandem with nat_ipv6_addrs_delta(), which
 * restricts the input parameters. */
static void
nat_ipv6_addr_increment(struct in6_addr *ipv6_aligned, uint32_t increment)
{
    uint8_t *ipv6_hi = &ipv6_aligned->s6_addr[0];
    uint8_t *ipv6_lo = &ipv6_aligned->s6_addr[0] + sizeof(ovs_be64);
    ovs_be64 addr6_64_hi;
    ovs_be64 addr6_64_lo;
    memcpy(&addr6_64_hi, ipv6_hi, sizeof addr6_64_hi);
    memcpy(&addr6_64_lo, ipv6_lo, sizeof addr6_64_lo);

    if (UINT64_MAX - increment >= ntohll(addr6_64_lo)) {
        addr6_64_lo = htonll(increment + ntohll(addr6_64_lo));
    } else if (addr6_64_hi != OVS_BE64_MAX) {
        addr6_64_hi = htonll(1 + ntohll(addr6_64_hi));
        addr6_64_lo = htonll(increment - (UINT64_MAX -
                                          ntohll(addr6_64_lo) + 1));
    } else {
        OVS_NOT_REACHED();
    }

    memcpy(ipv6_hi, &addr6_64_hi, sizeof addr6_64_hi);
    memcpy(ipv6_lo, &addr6_64_lo, sizeof addr6_64_lo);
}

static uint32_t
nat_range_hash(const struct conn *conn, uint32_t basis)
{
    uint32_t hash = basis;

    hash = ct_addr_hash_add(hash, &conn->ext_nat->nat_info->min_addr);
    hash = ct_addr_hash_add(hash, &conn->ext_nat->nat_info->max_addr);
    hash = hash_add(hash,
                    (conn->ext_nat->nat_info->max_port << 16)
                    | conn->ext_nat->nat_info->min_port);
    hash = ct_endpoint_hash_add(hash, &conn->key.src);
    hash = ct_endpoint_hash_add(hash, &conn->key.dst);
    hash = hash_add(hash, (OVS_FORCE uint32_t) conn->key.dl_type);
    hash = hash_add(hash, conn->key.nw_proto);
    hash = hash_add(hash, conn->key.zone);

    /* The purpose of the second parameter is to distinguish hashes of data of
     * different length; our data always has the same length so there is no
     * value in counting. */
    return hash_finish(hash, 0);
}

static bool
nat_select_range_tuple(const struct conn *conn, struct conn *nat_conn)
{
    enum { MIN_NAT_EPHEMERAL_PORT = 1024,
           MAX_NAT_EPHEMERAL_PORT = 65535 };

    uint16_t min_port;
    uint16_t max_port;
    uint16_t first_port;
    uint32_t hash = nat_range_hash(conn, hash_basis);

    if ((conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) &&
        (!(conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC_PORT))) {
        min_port = ntohs(conn->key.src.port);
        max_port = ntohs(conn->key.src.port);
        first_port = min_port;
    } else if ((conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST) &&
               (!(conn->ext_nat->nat_info->nat_action
                  & NAT_ACTION_DST_PORT))) {
        min_port = ntohs(conn->key.dst.port);
        max_port = ntohs(conn->key.dst.port);
        first_port = min_port;
    } else {
        uint16_t deltap = conn->ext_nat->nat_info->max_port -
            conn->ext_nat->nat_info->min_port;
        uint32_t port_index = hash % (deltap + 1);
        first_port = conn->ext_nat->nat_info->min_port + port_index;
        min_port = conn->ext_nat->nat_info->min_port;
        max_port = conn->ext_nat->nat_info->max_port;
    }

    uint32_t deltaa = 0;
    uint32_t address_index;
    struct ct_addr ct_addr;
    memset(&ct_addr, 0, sizeof ct_addr);
    struct ct_addr max_ct_addr;
    memset(&max_ct_addr, 0, sizeof max_ct_addr);
    max_ct_addr = conn->ext_nat->nat_info->max_addr;

    if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
        deltaa = ntohl(conn->ext_nat->nat_info->max_addr.ipv4_aligned) -
                       ntohl(conn->ext_nat->nat_info->min_addr.ipv4_aligned);
        address_index = hash % (deltaa + 1);
        ct_addr.ipv4_aligned = htonl(
            ntohl(conn->ext_nat->nat_info->min_addr.ipv4_aligned) +
                  address_index);
    } else {
        deltaa = nat_ipv6_addrs_delta(
                     &conn->ext_nat->nat_info->min_addr.ipv6_aligned,
                     &conn->ext_nat->nat_info->max_addr.ipv6_aligned);
        /* deltaa must be within 32 bits for full hash coverage. A 64 or
         * 128 bit hash is unnecessary and hence not used here. Most code
         * is kept common with V4; nat_ipv6_addrs_delta() will do the
         * enforcement via max_ct_addr. */
        max_ct_addr = conn->ext_nat->nat_info->min_addr;
        nat_ipv6_addr_increment(&max_ct_addr.ipv6_aligned, deltaa);
        address_index = hash % (deltaa + 1);
        ct_addr.ipv6_aligned = conn->ext_nat->nat_info->min_addr.ipv6_aligned;
        nat_ipv6_addr_increment(&ct_addr.ipv6_aligned, address_index);
    }

    uint16_t port = first_port;
    bool all_ports_tried = false;
    /* For DNAT, we don't use ephemeral ports. */
    bool ephemeral_ports_tried =
        conn->ext_nat->nat_info->nat_action & NAT_ACTION_DST ? true : false;
    struct ct_addr first_addr = ct_addr;

    while (true) {
        if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
            nat_conn->rev_key.dst.addr = ct_addr;
        } else {
            nat_conn->rev_key.src.addr = ct_addr;
        }

        if ((conn->key.nw_proto == IPPROTO_ICMP) ||
            (conn->key.nw_proto == IPPROTO_ICMPV6)) {
            all_ports_tried = true;
        } else if (conn->ext_nat->nat_info->nat_action & NAT_ACTION_SRC) {
            nat_conn->rev_key.dst.port = htons(port);
        } else {
            nat_conn->rev_key.src.port = htons(port);
        }

        uint32_t conn_hash = conn_key_hash(&nat_conn->rev_key, hash_basis);
        bool found = conn_key_lookup(&nat_conn->rev_key, conn_hash,
                                     time_msec(), NULL, NULL);

        if (!found) {
            return true;
        } else if (!all_ports_tried) {
            if (min_port == max_port) {
                all_ports_tried = true;
            } else if (port == max_port) {
                port = min_port;
            } else {
                port++;
            }
            if (port == first_port) {
                all_ports_tried = true;
            }
        } else {
            if (memcmp(&ct_addr, &max_ct_addr, sizeof ct_addr)) {
                if (conn->key.dl_type == htons(ETH_TYPE_IP)) {
                    ct_addr.ipv4_aligned = htonl(
                        ntohl(ct_addr.ipv4_aligned) + 1);
                } else {
                    nat_ipv6_addr_increment(&ct_addr.ipv6_aligned, 1);
                }
            } else {
                ct_addr = conn->ext_nat->nat_info->min_addr;
            }
            if (!memcmp(&ct_addr, &first_addr, sizeof ct_addr)) {
                if (ephemeral_ports_tried) {
                    break;
                } else {
                    ephemeral_ports_tried = true;
                    ct_addr = conn->ext_nat->nat_info->min_addr;
                    first_addr = ct_addr;
                    min_port = MIN_NAT_EPHEMERAL_PORT;
                    max_port = MAX_NAT_EPHEMERAL_PORT;
                }
            }
            first_port = min_port;
            port = first_port;
            all_ports_tried = false;
        }
    }
    return false;
}

static bool
conn_expired(struct conn *conn, long long now)
{
    if (conn->conn_type == CT_CONN_TYPE_DEFAULT) {
        return now >= conn->expiration;
    }
    return false;
}

static bool
valid_new(struct dp_packet *pkt, struct conn_key *key)
{
    return l4_protos[key->nw_proto]->valid_new(pkt);
}

static struct conn *
new_conn(struct dp_packet *pkt, struct conn_key *key, long long now)
{
    struct conn *newconn = l4_protos[key->nw_proto]->new_conn(pkt, now);
    if (newconn) {
        newconn->key = *key;
    }

    return newconn;
}

static enum ct_update_res
conn_update(struct dp_packet *pkt, struct conn *conn,
            struct conn_lookup_ctx *ctx, long long now)
{
    enum ct_update_res update_res =
        l4_protos[conn->key.nw_proto]->conn_update(conn, pkt, ctx->reply,
                                                   now);
    return update_res;
}

static void
delete_conn_cmn(struct conn *conn)
{
    if (conn->ext_nat) {
        free(conn->ext_nat->nat_info);
    }
    free(conn->ext_nat);

    if (conn->ext_alg) {
        free(conn->ext_alg->alg);
    }
    free(conn->ext_alg);
    free(conn);
}

static void
delete_conn(struct conn *conn)
{
    ovs_assert(conn->conn_type == CT_CONN_TYPE_DEFAULT);
    ovs_mutex_destroy(&conn->lock.lock);

    if (conn->ext_nat) {
        free(conn->ext_nat->nat_conn);
    }
    delete_conn_cmn(conn);
}

/* Only used by conn_clean_one(). */
static void
delete_conn_one(struct conn *conn)
{
    if (conn->conn_type == CT_CONN_TYPE_DEFAULT) {
        ovs_mutex_destroy(&conn->lock.lock);
    }
    delete_conn_cmn(conn);
}

/* Convert a conntrack address 'a' into an IP address 'b' based on 'dl_type'.
 *
 * Note that 'dl_type' should be either "ETH_TYPE_IP" or "ETH_TYPE_IPv6"
 * in network-byte order. */
static void
ct_endpoint_to_ct_dpif_inet_addr(const struct ct_addr *a,
                                 union ct_dpif_inet_addr *b,
                                 ovs_be16 dl_type)
{
    if (dl_type == htons(ETH_TYPE_IP)) {
        b->ip = a->ipv4_aligned;
    } else if (dl_type == htons(ETH_TYPE_IPV6)){
        b->in6 = a->ipv6_aligned;
    }
}

/* Convert an IP address 'a' into a conntrack address 'b' based on 'dl_type'.
 *
 * Note that 'dl_type' should be either "ETH_TYPE_IP" or "ETH_TYPE_IPv6"
 * in network-byte order. */
static void
ct_dpif_inet_addr_to_ct_endpoint(const union ct_dpif_inet_addr *a,
                                 struct ct_addr *b,
                                 ovs_be16 dl_type)
{
    if (dl_type == htons(ETH_TYPE_IP)) {
        b->ipv4_aligned = a->ip;
    } else if (dl_type == htons(ETH_TYPE_IPV6)){
        b->ipv6_aligned = a->in6;
    }
}

static void
conn_key_to_tuple(const struct conn_key *key, struct ct_dpif_tuple *tuple)
{
    if (key->dl_type == htons(ETH_TYPE_IP)) {
        tuple->l3_type = AF_INET;
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)) {
        tuple->l3_type = AF_INET6;
    }
    tuple->ip_proto = key->nw_proto;
    ct_endpoint_to_ct_dpif_inet_addr(&key->src.addr, &tuple->src,
                                     key->dl_type);
    ct_endpoint_to_ct_dpif_inet_addr(&key->dst.addr, &tuple->dst,
                                     key->dl_type);

    if (key->nw_proto == IPPROTO_ICMP || key->nw_proto == IPPROTO_ICMPV6) {
        tuple->icmp_id = key->src.icmp_id;
        tuple->icmp_type = key->src.icmp_type;
        tuple->icmp_code = key->src.icmp_code;
    } else {
        tuple->src_port = key->src.port;
        tuple->dst_port = key->dst.port;
    }
}

static void
tuple_to_conn_key(const struct ct_dpif_tuple *tuple, uint16_t zone,
                  struct conn_key *key)
{
    if (tuple->l3_type == AF_INET) {
        key->dl_type = htons(ETH_TYPE_IP);
    } else if (tuple->l3_type == AF_INET6) {
        key->dl_type = htons(ETH_TYPE_IPV6);
    }
    key->nw_proto = tuple->ip_proto;
    ct_dpif_inet_addr_to_ct_endpoint(&tuple->src, &key->src.addr,
                                     key->dl_type);
    ct_dpif_inet_addr_to_ct_endpoint(&tuple->dst, &key->dst.addr,
                                     key->dl_type);

    if (tuple->ip_proto == IPPROTO_ICMP || tuple->ip_proto == IPPROTO_ICMPV6) {
        key->src.icmp_id = tuple->icmp_id;
        key->src.icmp_type = tuple->icmp_type;
        key->src.icmp_code = tuple->icmp_code;
        key->dst.icmp_id = tuple->icmp_id;
        key->dst.icmp_type = reverse_icmp_type(tuple->icmp_type);
        key->dst.icmp_code = tuple->icmp_code;
    } else {
        key->src.port = tuple->src_port;
        key->dst.port = tuple->dst_port;
    }
    key->zone = zone;
}

static void
conn_to_ct_dpif_entry(const struct conn *conn, struct ct_dpif_entry *entry,
                      long long now, int bkt)
{
    memset(entry, 0, sizeof *entry);
    conn_key_to_tuple(&conn->key, &entry->tuple_orig);
    conn_key_to_tuple(&conn->rev_key, &entry->tuple_reply);

    entry->zone = conn->key.zone;
    entry->mark = conn->mark;

    memcpy(&entry->labels, &conn->label, sizeof entry->labels);
    /* Not implemented yet */
    entry->timestamp.start = 0;
    entry->timestamp.stop = 0;

    long long expiration = conn->expiration - now;
    entry->timeout = (expiration > 0) ? expiration / 1000 : 0;

    struct ct_l4_proto *class = l4_protos[conn->key.nw_proto];
    if (class->conn_get_protoinfo) {
        class->conn_get_protoinfo(conn, &entry->protoinfo);
    }

    entry->bkt = bkt;

    if (conn->ext_alg && conn->ext_alg->alg) {
        /* Caller is responsible for freeing. */
        entry->helper.name = xstrdup(conn->ext_alg->alg);
    } else {
        entry->helper.name = NULL;
    }
}

int
conntrack_dump_start(struct conntrack_dump *dump, const uint16_t *pzone,
                     int *ptot_bkts)
{
    memset(dump, 0, sizeof(*dump));

    if (pzone) {
        dump->zone = *pzone;
        dump->filter_zone = true;
    }

    *ptot_bkts = 1; /* Need to clean up the callers. */
    return 0;
}

int
conntrack_dump_next(struct conntrack_dump *dump, struct ct_dpif_entry *entry)
{
    long long now = time_msec();

    for (;;) {
        struct cmap_node *cm_node = cmap_next_position(&cm_conns,
                                                       &dump->cm_pos);
        if (!cm_node) {
            break;
        }
        struct conn *conn;
        INIT_CONTAINER(conn, cm_node, cm_node);
        if ((!dump->filter_zone || conn->key.zone == dump->zone) &&
             (conn->conn_type != CT_CONN_TYPE_UN_NAT)) {
            conn_to_ct_dpif_entry(conn, entry, now, 0);
            return 0;
        }
    }

    return EOF;
}

int
conntrack_dump_done(struct conntrack_dump *dump OVS_UNUSED)
{
    return 0;
}

int
conntrack_flush(const uint16_t *zone)
{
    struct conn *conn;

    ovs_mutex_lock(&ct_lock.lock);

    CMAP_FOR_EACH (conn, cm_node, &cm_conns) {
        if (!zone || *zone == conn->key.zone) {
            conn_clean_one(conn);
        }
    }

    ovs_mutex_unlock(&ct_lock.lock);

    return 0;
}

int
conntrack_flush_tuple(const struct ct_dpif_tuple *tuple, uint16_t zone)
{
    int error = 0;
    struct conn_lookup_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    tuple_to_conn_key(tuple, zone, &ctx.key);
    ctx.hash = conn_key_hash(&ctx.key, hash_basis);

    ovs_mutex_lock(&ct_lock.lock);
    conn_key_lookup(&ctx.key, ctx.hash, time_msec(), &ctx.conn, &ctx.reply);

    if (ctx.conn && ctx.conn->conn_type == CT_CONN_TYPE_DEFAULT) {
        conn_clean(ctx.conn);
    } else {
        VLOG_WARN("Must flush tuple using the original pre-NATed tuple");
        error = ENOENT;
    }
    ovs_mutex_unlock(&ct_lock.lock);
    return error;
}

int
conntrack_set_maxconns(uint32_t maxconns)
{
    atomic_store_relaxed(&n_conn_limit, maxconns);
    return 0;
}

int
conntrack_get_maxconns(uint32_t *maxconns)
{
    atomic_read_relaxed(&n_conn_limit, maxconns);
    return 0;
}

int
conntrack_get_nconns(uint32_t *nconns)
{
    *nconns = atomic_count_get(&n_conn);
    return 0;
}

/* This function must be called with the resources read lock taken. */
static struct alg_exp_node *
expectation_lookup(struct hmap *alg_expectations_, const struct conn_key *key,
                   uint32_t basis, bool src_ip_wc)
{
    struct conn_key check_key = *key;
    check_key.src.port = ALG_WC_SRC_PORT;

    if (src_ip_wc) {
        memset(&check_key.src.addr, 0, sizeof check_key.src.addr);
    }

    struct alg_exp_node *alg_exp_node;

    HMAP_FOR_EACH_WITH_HASH (alg_exp_node, node,
                             conn_key_hash(&check_key, basis),
                             alg_expectations_) {
        if (!conn_key_cmp(&alg_exp_node->key, &check_key)) {
            return alg_exp_node;
        }
    }
    return NULL;
}

/* This function must be called with the resources write lock taken. */
static void
expectation_remove(struct hmap *alg_expectations_,
                   const struct conn_key *key, uint32_t basis)
{
    struct alg_exp_node *alg_exp_node;

    HMAP_FOR_EACH_WITH_HASH (alg_exp_node, node, conn_key_hash(key, basis),
                             alg_expectations_) {
        if (!conn_key_cmp(&alg_exp_node->key, key)) {
            hmap_remove(alg_expectations_, &alg_exp_node->node);
            break;
        }
    }
}

/* This function must be called with the resources read lock taken. */
static struct alg_exp_node *
expectation_ref_lookup_unique(const struct hindex *alg_expectation_refs_,
                              const struct conn_key *master_key,
                              const struct conn_key *alg_exp_key,
                              uint32_t basis)
{
    struct alg_exp_node *alg_exp_node;

    HINDEX_FOR_EACH_WITH_HASH (alg_exp_node, node_ref,
                               conn_key_hash(master_key, basis),
                               alg_expectation_refs_) {
        if (!conn_key_cmp(&alg_exp_node->master_key, master_key) &&
            !conn_key_cmp(&alg_exp_node->key, alg_exp_key)) {
            return alg_exp_node;
        }
    }
    return NULL;
}

/* This function must be called with the resources write lock taken. */
static void
expectation_ref_create(struct hindex *alg_expectation_refs_,
                       struct alg_exp_node *alg_exp_node,
                       uint32_t basis)
{
    if (!expectation_ref_lookup_unique(alg_expectation_refs_,
                                       &alg_exp_node->master_key,
                                       &alg_exp_node->key, basis)) {
        hindex_insert(alg_expectation_refs_, &alg_exp_node->node_ref,
                      conn_key_hash(&alg_exp_node->master_key, basis));
    }
}

static void
expectation_clean(const struct conn_key *master_key)
{
    ovs_rwlock_wrlock(&resources_lock.lock);

    struct alg_exp_node *node, *next;
    HINDEX_FOR_EACH_WITH_HASH_SAFE (node, next, node_ref,
                                    conn_key_hash(master_key, hash_basis),
                                    &alg_expectation_refs) {
        if (!conn_key_cmp(&node->master_key, master_key)) {
            expectation_remove(&alg_expectations, &node->key, hash_basis);
            hindex_remove(&alg_expectation_refs, &node->node_ref);
            free(node);
        }
    }

    ovs_rwlock_unlock(&resources_lock.lock);
}

static void
expectation_create(ovs_be16 dst_port, const struct conn *master_conn,
                   bool reply, bool src_ip_wc, bool skip_nat)
{
    struct ct_addr src_addr;
    struct ct_addr dst_addr;
    struct ct_addr alg_nat_repl_addr;
    struct alg_exp_node *alg_exp_node = xzalloc(sizeof *alg_exp_node);

    if (reply) {
        src_addr = master_conn->key.src.addr;
        dst_addr = master_conn->key.dst.addr;
        if (skip_nat) {
            alg_nat_repl_addr = dst_addr;
        } else {
            alg_nat_repl_addr = master_conn->rev_key.dst.addr;
        }
        alg_exp_node->nat_rpl_dst = true;
    } else {
        src_addr = master_conn->rev_key.src.addr;
        dst_addr = master_conn->rev_key.dst.addr;
        if (skip_nat) {
            alg_nat_repl_addr = src_addr;
        } else {
            alg_nat_repl_addr = master_conn->key.src.addr;
        }
        alg_exp_node->nat_rpl_dst = false;
    }
    if (src_ip_wc) {
        memset(&src_addr, 0, sizeof src_addr);
    }

    alg_exp_node->key.dl_type = master_conn->key.dl_type;
    alg_exp_node->key.nw_proto = master_conn->key.nw_proto;
    alg_exp_node->key.zone = master_conn->key.zone;
    alg_exp_node->key.src.addr = src_addr;
    alg_exp_node->key.dst.addr = dst_addr;
    alg_exp_node->key.src.port = ALG_WC_SRC_PORT;
    alg_exp_node->key.dst.port = dst_port;
    alg_exp_node->master_mark = master_conn->mark;
    alg_exp_node->master_label = master_conn->label;
    alg_exp_node->master_key = master_conn->key;
    /* Take the write lock here because it is almost 100%
     * likely that the lookup will fail and
     * expectation_create() will be called below. */
    ovs_rwlock_wrlock(&resources_lock.lock);
    struct alg_exp_node *alg_exp = expectation_lookup(
        &alg_expectations, &alg_exp_node->key, hash_basis, src_ip_wc);
    if (alg_exp) {
        free(alg_exp_node);
        ovs_rwlock_unlock(&resources_lock.lock);
        return;
    }

    alg_exp_node->alg_nat_repl_addr = alg_nat_repl_addr;
    hmap_insert(&alg_expectations, &alg_exp_node->node,
                conn_key_hash(&alg_exp_node->key, hash_basis));
    expectation_ref_create(&alg_expectation_refs, alg_exp_node,
                           hash_basis);
    ovs_rwlock_unlock(&resources_lock.lock);
}

static uint8_t
get_v4_byte_be(ovs_be32 v4_addr, uint8_t index)
{
    uint8_t *byte_ptr = (OVS_FORCE uint8_t *) &v4_addr;
    return byte_ptr[index];
}

static void
replace_substring(char *substr, uint8_t substr_size,
                  uint8_t total_size, char *rep_str,
                  uint8_t rep_str_size)
{
    memmove(substr + rep_str_size, substr + substr_size,
            total_size - substr_size);
    memcpy(substr, rep_str, rep_str_size);
}

/* Replace IPV4 address in FTP message with NATed address. */
static int
repl_ftp_v4_addr(struct dp_packet *pkt, ovs_be32 v4_addr_rep,
                 char *ftp_data_start,
                 size_t addr_offset_from_ftp_data_start)
{
    enum { MAX_FTP_V4_NAT_DELTA = 8 };

    /* Do conservative check for pathological MTU usage. */
    uint32_t orig_used_size = dp_packet_size(pkt);
    uint16_t allocated_size = dp_packet_get_allocated(pkt);
    if (orig_used_size + MAX_FTP_V4_NAT_DELTA > allocated_size) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "Unsupported effective MTU %u used with FTP",
                     allocated_size);
        return 0;
    }

    size_t remain_size = tcp_payload_length(pkt) -
                             addr_offset_from_ftp_data_start;
    int overall_delta = 0;
    char *byte_str = ftp_data_start + addr_offset_from_ftp_data_start;

    /* Replace the existing IPv4 address by the new one. */
    for (uint8_t i = 0; i < 4; i++) {
        /* Find the end of the string for this octet. */
        char *next_delim = memchr(byte_str, ',', 4);
        ovs_assert(next_delim);
        int substr_size = next_delim - byte_str;
        remain_size -= substr_size;

        /* Compose the new string for this octet, and replace it. */
        char rep_str[4];
        uint8_t rep_byte = get_v4_byte_be(v4_addr_rep, i);
        int replace_size = sprintf(rep_str, "%d", rep_byte);
        replace_substring(byte_str, substr_size, remain_size,
                          rep_str, replace_size);
        overall_delta += replace_size - substr_size;

        /* Advance past the octet and the following comma. */
        byte_str += replace_size + 1;
    }

    dp_packet_set_size(pkt, orig_used_size + overall_delta);
    return overall_delta;
}

static char *
skip_non_digits(char *str)
{
    while (!isdigit(*str) && *str != 0) {
        str++;
    }
    return str;
}

static char *
terminate_number_str(char *str, uint8_t max_digits)
{
    uint8_t digits_found = 0;
    while (isdigit(*str) && digits_found <= max_digits) {
        str++;
        digits_found++;
    }

    *str = 0;
    return str;
}


static void
get_ftp_ctl_msg(struct dp_packet *pkt, char *ftp_msg)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    char *tcp_hdr = (char *) th;
    uint32_t tcp_payload_len = tcp_payload_length(pkt);
    size_t tcp_payload_of_interest = MIN(tcp_payload_len,
                                         LARGEST_FTP_MSG_OF_INTEREST);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;

    ovs_strlcpy(ftp_msg, tcp_hdr + tcp_hdr_len,
                tcp_payload_of_interest);
}

static enum ftp_ctl_pkt
detect_ftp_ctl_type(const struct conn_lookup_ctx *ctx,
                    struct dp_packet *pkt)
{
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);

    if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        if (strncasecmp(ftp_msg, FTP_EPRT_CMD, strlen(FTP_EPRT_CMD)) &&
            !strcasestr(ftp_msg, FTP_EPSV_REPLY)) {
            return CT_FTP_CTL_OTHER;
        }
    } else {
        if (strncasecmp(ftp_msg, FTP_PORT_CMD, strlen(FTP_PORT_CMD)) &&
            strncasecmp(ftp_msg, FTP_PASV_REPLY_CODE,
                        strlen(FTP_PASV_REPLY_CODE))) {
            return CT_FTP_CTL_OTHER;
        }
    }

    return CT_FTP_CTL_INTEREST;
}

static enum ftp_ctl_pkt
process_ftp_ctl_v4(struct dp_packet *pkt,
                   const struct conn *conn_for_expectation,
                   ovs_be32 *v4_addr_rep,
                   char **ftp_data_v4_start,
                   size_t *addr_offset_from_ftp_data_start)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;
    char *tcp_hdr = (char *) th;
    *ftp_data_v4_start = tcp_hdr + tcp_hdr_len;
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);
    char *ftp = ftp_msg;
    enum ct_alg_mode mode;

    if (!strncasecmp(ftp, FTP_PORT_CMD, strlen(FTP_PORT_CMD))) {
        ftp = ftp_msg + strlen(FTP_PORT_CMD);
        mode = CT_FTP_MODE_ACTIVE;
    } else {
        ftp = ftp_msg + strlen(FTP_PASV_REPLY_CODE);
        mode = CT_FTP_MODE_PASSIVE;
    }

    /* Find first space. */
    ftp = strchr(ftp, ' ');
    if (!ftp) {
        return CT_FTP_CTL_INVALID;
    }

    /* Find the first digit, after space. */
    ftp = skip_non_digits(ftp);
    if (*ftp == 0) {
        return CT_FTP_CTL_INVALID;
    }

    char *ip_addr_start = ftp;
    *addr_offset_from_ftp_data_start = ip_addr_start - ftp_msg;

    uint8_t comma_count = 0;
    while (comma_count < 4 && *ftp) {
        if (*ftp == ',') {
            comma_count++;
            if (comma_count == 4) {
                *ftp = 0;
            } else {
                *ftp = '.';
            }
        }
        ftp++;
    }
    if (comma_count != 4) {
        return CT_FTP_CTL_INVALID;
    }

    struct in_addr ip_addr;
    int rc2 = inet_pton(AF_INET, ip_addr_start, &ip_addr);
    if (rc2 != 1) {
        return CT_FTP_CTL_INVALID;
    }

    char *save_ftp = ftp;
    ftp = terminate_number_str(ftp, MAX_FTP_PORT_DGTS);
    if (!ftp) {
        return CT_FTP_CTL_INVALID;
    }
    int value;
    if (!str_to_int(save_ftp, 10, &value)) {
        return CT_FTP_CTL_INVALID;
    }

    /* This is derived from the L4 port maximum is 65535. */
    if (value > 255) {
        return CT_FTP_CTL_INVALID;
    }

    uint16_t port_hs = value;
    port_hs <<= 8;

    /* Skip over comma. */
    ftp++;
    save_ftp = ftp;
    bool digit_found = false;
    while (isdigit(*ftp)) {
        ftp++;
        digit_found = true;
    }
    if (!digit_found) {
        return CT_FTP_CTL_INVALID;
    }
    *ftp = 0;
    if (!str_to_int(save_ftp, 10, &value)) {
        return CT_FTP_CTL_INVALID;
    }

    if (value > 255) {
        return CT_FTP_CTL_INVALID;
    }

    uint16_t port_lo_hs = value;
    if (65535 - port_hs < port_lo_hs) {
        return CT_FTP_CTL_INVALID;
    }

    port_hs |= port_lo_hs;
    ovs_be16 port = htons(port_hs);
    ovs_be32 conn_ipv4_addr;

    switch (mode) {
    case CT_FTP_MODE_ACTIVE:
        *v4_addr_rep = conn_for_expectation->rev_key.dst.addr.ipv4_aligned;
        conn_ipv4_addr = conn_for_expectation->key.src.addr.ipv4_aligned;
        break;
    case CT_FTP_MODE_PASSIVE:
        *v4_addr_rep = conn_for_expectation->key.dst.addr.ipv4_aligned;
        conn_ipv4_addr = conn_for_expectation->rev_key.src.addr.ipv4_aligned;
        break;
    case CT_TFTP_MODE:
    default:
        OVS_NOT_REACHED();
    }

    ovs_be32 ftp_ipv4_addr;
    ftp_ipv4_addr = ip_addr.s_addr;
    /* Although most servers will block this exploit, there may be some
     * less well managed. */
    if (ftp_ipv4_addr != conn_ipv4_addr && ftp_ipv4_addr != *v4_addr_rep) {
        return CT_FTP_CTL_INVALID;
    }

    expectation_create(port, conn_for_expectation,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
    return CT_FTP_CTL_INTEREST;
}

static char *
skip_ipv6_digits(char *str)
{
    while (isxdigit(*str) || *str == ':' || *str == '.') {
        str++;
    }
    return str;
}

static enum ftp_ctl_pkt
process_ftp_ctl_v6(struct dp_packet *pkt,
                   const struct conn *conn_for_expectation,
                   struct ct_addr *v6_addr_rep,
                   char **ftp_data_start,
                   size_t *addr_offset_from_ftp_data_start,
                   size_t *addr_size, enum ct_alg_mode *mode)
{
    struct tcp_header *th = dp_packet_l4(pkt);
    size_t tcp_hdr_len = TCP_OFFSET(th->tcp_ctl) * 4;
    char *tcp_hdr = (char *) th;
    char ftp_msg[LARGEST_FTP_MSG_OF_INTEREST + 1] = {0};
    get_ftp_ctl_msg(pkt, ftp_msg);
    *ftp_data_start = tcp_hdr + tcp_hdr_len;
    char *ftp = ftp_msg;
    struct in6_addr ip6_addr;

    if (!strncasecmp(ftp, FTP_EPRT_CMD, strlen(FTP_EPRT_CMD))) {
        ftp = ftp_msg + strlen(FTP_EPRT_CMD);
        ftp = skip_non_digits(ftp);
        if (*ftp != FTP_AF_V6 || isdigit(ftp[1])) {
            return CT_FTP_CTL_INVALID;
        }
        /* Jump over delimiter. */
        ftp += 2;

        memset(&ip6_addr, 0, sizeof ip6_addr);
        char *ip_addr_start = ftp;
        *addr_offset_from_ftp_data_start = ip_addr_start - ftp_msg;
        ftp = skip_ipv6_digits(ftp);
        *ftp = 0;
        *addr_size = ftp - ip_addr_start;
        int rc2 = inet_pton(AF_INET6, ip_addr_start, &ip6_addr);
        if (rc2 != 1) {
            return CT_FTP_CTL_INVALID;
        }
        ftp++;
        *mode = CT_FTP_MODE_ACTIVE;
    } else {
        ftp = ftp_msg + strcspn(ftp_msg, "(");
        ftp = skip_non_digits(ftp);
        if (!isdigit(*ftp)) {
            return CT_FTP_CTL_INVALID;
        }

        /* Not used for passive mode. */
        *addr_offset_from_ftp_data_start = 0;
        *addr_size = 0;

        *mode = CT_FTP_MODE_PASSIVE;
    }

    char *save_ftp = ftp;
    ftp = terminate_number_str(ftp, MAX_EXT_FTP_PORT_DGTS);
    if (!ftp) {
        return CT_FTP_CTL_INVALID;
    }

    int value;
    if (!str_to_int(save_ftp, 10, &value)) {
        return CT_FTP_CTL_INVALID;
    }
    if (value > CT_MAX_L4_PORT) {
        return CT_FTP_CTL_INVALID;
    }

    uint16_t port_hs = value;
    ovs_be16 port = htons(port_hs);

    switch (*mode) {
    case CT_FTP_MODE_ACTIVE:
        *v6_addr_rep = conn_for_expectation->rev_key.dst.addr;
        /* Although most servers will block this exploit, there may be some
         * less well managed. */
        if (memcmp(&ip6_addr, &v6_addr_rep->ipv6_aligned, sizeof ip6_addr) &&
            memcmp(&ip6_addr, &conn_for_expectation->key.src.addr.ipv6_aligned,
                   sizeof ip6_addr)) {
            return CT_FTP_CTL_INVALID;
        }
        break;
    case CT_FTP_MODE_PASSIVE:
        *v6_addr_rep = conn_for_expectation->key.dst.addr;
        break;
    case CT_TFTP_MODE:
    default:
        OVS_NOT_REACHED();
    }

    expectation_create(port, conn_for_expectation,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
    return CT_FTP_CTL_INTEREST;
}

static int
repl_ftp_v6_addr(struct dp_packet *pkt, struct ct_addr v6_addr_rep,
                 char *ftp_data_start,
                 size_t addr_offset_from_ftp_data_start,
                 size_t addr_size, enum ct_alg_mode mode)
{
    /* This is slightly bigger than really possible. */
    enum { MAX_FTP_V6_NAT_DELTA = 45 };

    if (mode == CT_FTP_MODE_PASSIVE) {
        return 0;
    }

    /* Do conservative check for pathological MTU usage. */
    uint32_t orig_used_size = dp_packet_size(pkt);
    uint16_t allocated_size = dp_packet_get_allocated(pkt);
    if (orig_used_size + MAX_FTP_V6_NAT_DELTA > allocated_size) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "Unsupported effective MTU %u used with FTP",
                     allocated_size);
        return 0;
    }

    char v6_addr_str[IPV6_SCAN_LEN] = {0};
    ovs_assert(inet_ntop(AF_INET6, &v6_addr_rep.ipv6_aligned, v6_addr_str,
                         IPV6_SCAN_LEN - 1));

    size_t replace_addr_size = strlen(v6_addr_str);

    size_t remain_size = tcp_payload_length(pkt) -
                             addr_offset_from_ftp_data_start;

    char *pkt_addr_str = ftp_data_start + addr_offset_from_ftp_data_start;
    replace_substring(pkt_addr_str, addr_size, remain_size,
                      v6_addr_str, replace_addr_size);

    int overall_delta = (int) replace_addr_size - (int) addr_size;

    dp_packet_set_size(pkt, orig_used_size + overall_delta);
    return overall_delta;
}

static void
handle_ftp_ctl(const struct conn_lookup_ctx *ctx, struct dp_packet *pkt,
               const struct conn *conn_for_expectation,
               long long now, enum ftp_ctl_pkt ftp_ctl, bool nat)
{
    struct ip_header *l3_hdr = dp_packet_l3(pkt);
    ovs_be32 v4_addr_rep = 0;
    struct ct_addr v6_addr_rep;
    size_t addr_offset_from_ftp_data_start;
    size_t addr_size = 0;
    char *ftp_data_start;
    bool do_seq_skew_adj = true;
    enum ct_alg_mode mode = CT_FTP_MODE_ACTIVE;

    if (detect_ftp_ctl_type(ctx, pkt) != ftp_ctl) {
        return;
    }

    if (!nat || !conn_for_expectation->ext_alg->seq_skew) {
        do_seq_skew_adj = false;
    }

    struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(pkt);
    int64_t seq_skew = 0;

    if (ftp_ctl == CT_FTP_CTL_OTHER) {
        seq_skew = conn_for_expectation->ext_alg->seq_skew;
    } else if (ftp_ctl == CT_FTP_CTL_INTEREST) {
        enum ftp_ctl_pkt rc;
        if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
            rc = process_ftp_ctl_v6(pkt, conn_for_expectation, &v6_addr_rep,
                                    &ftp_data_start,
                                    &addr_offset_from_ftp_data_start,
                                    &addr_size, &mode);
        } else {
            rc = process_ftp_ctl_v4(pkt, conn_for_expectation, &v4_addr_rep,
                                    &ftp_data_start,
                                    &addr_offset_from_ftp_data_start);
        }
        if (rc == CT_FTP_CTL_INVALID) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_WARN_RL(&rl, "Invalid FTP control packet format");
            pkt->md.ct_state |= CS_TRACKED | CS_INVALID;
            return;
        } else if (rc == CT_FTP_CTL_INTEREST) {
            uint16_t ip_len;

            if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
                seq_skew = repl_ftp_v6_addr(pkt, v6_addr_rep, ftp_data_start,
                                            addr_offset_from_ftp_data_start,
                                            addr_size, mode);
                if (seq_skew) {
                    ip_len = ntohs(nh6->ip6_ctlun.ip6_un1.ip6_un1_plen);
                    ip_len += seq_skew;
                    nh6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(ip_len);
                    conn_seq_skew_set(&conn_for_expectation->key, now,
                                      seq_skew, ctx->reply);
                }
            } else {
                seq_skew = repl_ftp_v4_addr(pkt, v4_addr_rep, ftp_data_start,
                                            addr_offset_from_ftp_data_start);
                ip_len = ntohs(l3_hdr->ip_tot_len);
                if (seq_skew) {
                    ip_len += seq_skew;
                    l3_hdr->ip_csum = recalc_csum16(l3_hdr->ip_csum,
                                          l3_hdr->ip_tot_len, htons(ip_len));
                    l3_hdr->ip_tot_len = htons(ip_len);
                    conn_seq_skew_set(&conn_for_expectation->key, now,
                                      seq_skew, ctx->reply);
                }
            }
        } else {
            OVS_NOT_REACHED();
        }
    } else {
        OVS_NOT_REACHED();
    }

    struct tcp_header *th = dp_packet_l4(pkt);

    if (do_seq_skew_adj && seq_skew != 0) {
        if (ctx->reply != conn_for_expectation->ext_alg->seq_skew_dir) {

            uint32_t tcp_ack = ntohl(get_16aligned_be32(&th->tcp_ack));

            if ((seq_skew > 0) && (tcp_ack < seq_skew)) {
                /* Should not be possible; will be marked invalid. */
                tcp_ack = 0;
            } else if ((seq_skew < 0) && (UINT32_MAX - tcp_ack < -seq_skew)) {
                tcp_ack = (-seq_skew) - (UINT32_MAX - tcp_ack);
            } else {
                tcp_ack -= seq_skew;
            }
            ovs_be32 new_tcp_ack = htonl(tcp_ack);
            put_16aligned_be32(&th->tcp_ack, new_tcp_ack);
        } else {
            uint32_t tcp_seq = ntohl(get_16aligned_be32(&th->tcp_seq));
            if ((seq_skew > 0) && (UINT32_MAX - tcp_seq < seq_skew)) {
                tcp_seq = seq_skew - (UINT32_MAX - tcp_seq);
            } else if ((seq_skew < 0) && (tcp_seq < -seq_skew)) {
                /* Should not be possible; will be marked invalid. */
                tcp_seq = 0;
            } else {
                tcp_seq += seq_skew;
            }
            ovs_be32 new_tcp_seq = htonl(tcp_seq);
            put_16aligned_be32(&th->tcp_seq, new_tcp_seq);
        }
    }

    th->tcp_csum = 0;
    uint32_t tcp_csum;
    if (ctx->key.dl_type == htons(ETH_TYPE_IPV6)) {
        tcp_csum = packet_csum_pseudoheader6(nh6);
    } else {
        tcp_csum = packet_csum_pseudoheader(l3_hdr);
    }
    const char *tail = dp_packet_tail(pkt);
    uint8_t pad = dp_packet_l2_pad_size(pkt);
    th->tcp_csum = csum_finish(
        csum_continue(tcp_csum, th, tail - (char *) th - pad));
}

static void
handle_tftp_ctl(const struct conn_lookup_ctx *ctx OVS_UNUSED,
                struct dp_packet *pkt,
                const struct conn *conn_for_expectation,
                long long now OVS_UNUSED,
                enum ftp_ctl_pkt ftp_ctl OVS_UNUSED, bool nat OVS_UNUSED)
{
    expectation_create(conn_for_expectation->key.src.port,
                       conn_for_expectation,
                       !!(pkt->md.ct_state & CS_REPLY_DIR), false, false);
}
