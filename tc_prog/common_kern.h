#ifndef __COMMON_KERN_H
#define __COMMON_KERN_H

#include "common_defines.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ref: http://www.azillionmonkeys.com/qed/hash.html
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )

static __always_inline
uint32_t SuperFastHash(const char * data, int len) {
    uint32_t hash = len, tmp;
    int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (; len > 0; len--) {
        hash  += get16bits(data);
        tmp    = (get16bits(data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits(data);
                hash ^= hash << 16;
                hash ^= ((signed char)data[sizeof (uint16_t)]) << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits(data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += (signed char)*data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

static __always_inline
int check_l4_bound(int hdr_type, void* l4hdr, void* data_end) {
    if (hdr_type == IPPROTO_UDP) {
        if (data_end < l4hdr + UDPLEN) return 1;
    } else if (hdr_type == IPPROTO_TCP) {
        if (data_end < l4hdr + TCPLEN) return 1;
    }
    return 0;
}

static __always_inline
int iterate_match_fivetuple(struct fivetuple *fivetuple_, __u8 iternum) {
    void* fields_[] = {&fivetuple_->saddr, &fivetuple_->daddr,
                        &fivetuple_->sport, &fivetuple_->dport,
                        &fivetuple_->protocol};
    int bytesize[] = {4, 4, 2, 2, 1};
    if (iternum < 0 || iternum >= 32) return 1;
    // Use iternum to generate the mask bits
    for (int i = 0; i < 5; i ++) {
        __u8 tmp_num = iternum >> i;
        // If the bit is masked, set the field to 0
        if (tmp_num % 2 == 0) {
            switch (bytesize[i]) {
            case 4: {
                __be32 *ptr = fields_[i];
                *ptr = 0;
                break;
            }
            case 2: {
                __be16 *ptr = fields_[i];
                *ptr = 0;
                break;
            }
            case 1: {
                __u8 *ptr = fields_[i];
                *ptr = 0;
                break;
            }
            default:
                break;
            }
        }
    }
    return 0;
}

static __always_inline
int get_rule_action_(void *rulesmap, const struct fivetuple *fivetuple_, bool isIngress) {
    // struct fivetuple tmp_tuple;
    struct rule tmp_rule;
    tmp_rule.isIngress = isIngress;
    // Must find out a rule for the packet.
    // all 0 as default
    // bpf_printkm("DEBUG: Starting iterate");
    __u8* action = NULL;
    for (int i = 31; i >= 1; i--) {
        tmp_rule.fivetuple_ = *fivetuple_;
        if (iterate_match_fivetuple(&tmp_rule.fivetuple_, i)) return 1;
        // bpf_printkm("saddr: %x", tmp_rule.fivetuple_.saddr);
        // bpf_printkm("daddr: %x", tmp_rule.fivetuple_.daddr);
        // bpf_printkm("sport: %x", tmp_rule.fivetuple_.sport);
        // bpf_printkm("dport: %x", tmp_rule.fivetuple_.dport);
        // bpf_printkm("proto: %x", tmp_rule.fivetuple_.protocol);
        // tmp_rule.fivetuple_ = tmp_tuple;
        action = bpf_map_lookup_elem(rulesmap, &tmp_rule);
        if (action != NULL) {
            if (i != 31) {
                // Add the match result to the rules map.
                tmp_rule.fivetuple_ = *fivetuple_;
                bpf_map_update_elem(rulesmap, &tmp_rule, action, BPF_NOEXIST);
            }
            return *action;
        // } else {
        //     bpf_printkm("Dont match!");
        }
    }
    // bpf_printkm("DEBUG: Finished iterate %d", *action);
    // Add the match result to the rules map.
    tmp_rule.fivetuple_ = *fivetuple_;
    __u8 tmp = 1;
    bpf_map_update_elem(rulesmap, &tmp_rule, &tmp, BPF_NOEXIST);
    // bpf_printkm("saddr: %x", tmp_rule.fivetuple_.saddr);
    // bpf_printkm("daddr: %x", tmp_rule.fivetuple_.daddr);
    // bpf_printkm("sport: %x", tmp_rule.fivetuple_.sport);
    // bpf_printkm("dport: %x", tmp_rule.fivetuple_.dport);
    // bpf_printkm("proto: %x", tmp_rule.fivetuple_.protocol);
    return 1;
}

// dir = 0 egress, dir = 1 ingress, dir = 2 both
// Default pass = 1
static __always_inline
int get_rule_action(struct iphdr * iph, void *data_end,
                        void *rulesmap, int dir) {
    int proto = iph->protocol;

    if ((proto != IPPROTO_TCP && proto != IPPROTO_UDP) ||
        check_l4_bound(proto, iph + 1, data_end)) return 1;

    struct fivetuple send_5tuple = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .protocol = iph->protocol
    };

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
        send_5tuple.sport = tcphdr->source;
        send_5tuple.dport = tcphdr->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udphdr = (struct udphdr *)(iph + 1);
        send_5tuple.sport = udphdr->source;
        send_5tuple.dport = udphdr->dest;
    }

    if (dir == 0 || dir == 2) {
        return get_rule_action_(rulesmap, &send_5tuple, false);
    }
    if (dir == 1 || dir == 2) {
        struct fivetuple rev_5tuple = {
            .saddr = send_5tuple.daddr,
            .daddr = send_5tuple.saddr,
            .sport = send_5tuple.dport,
            .dport = send_5tuple.sport,
            .protocol = send_5tuple.protocol
        };
        return get_rule_action_(rulesmap, &rev_5tuple, true);
    }
    return 1;
}

static __always_inline void initpathinfo(struct pathinfo* ci) {
    __builtin_memset(&(ci->local_mac), 0, ETH_ALEN);
    __builtin_memset(&(ci->remote_mac), 0, ETH_ALEN);
    ci->local_ip = 0;
    ci->remote_ip = 0;
    ci->pod_ifkey = 0;
    ci->remote_ready = 0;
    ci->last_refresh_time = 0;  // in second
    ci->local_partial_key = 0;
    ci->remote_partial_key = 0;
}

unsigned long long load_byte(void *skb,
        unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
        unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
        unsigned long long off) asm("llvm.bpf.load.word");

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))
#define IP_ID_OFF (ETH_HLEN + offsetof(struct iphdr, id))
#define TCP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define UDP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define IS_PSEUDO 0x10
#define IS_SRC 1
#define IS_DST 2

static inline void set_ip_tos(struct __sk_buff *skb, unsigned int off, __u8 tos)
{
    __u8 old_tos = load_byte(skb, off + IP_TOS_OFF);
    __u8 new_tos = tos;
    bpf_l3_csum_replace(
        skb, off + IP_CSUM_OFF, htons(old_tos), htons(new_tos), 2);
    bpf_skb_store_bytes(
        skb, off + IP_TOS_OFF, &new_tos, sizeof(new_tos), 0);
}

static inline void set_new_ip(
    struct __sk_buff *skb, unsigned int off,  __be32 new_ip, int is_src, unsigned char proto, bool do_l4csum) {
    unsigned int field;
    if (is_src == IS_SRC) field = off + IP_SRC_OFF;
    else field = off + IP_DST_OFF;
    __be32 old_ip = htonl(load_word(skb, field));

    if (do_l4csum) {
        if (proto == IPPROTO_TCP) {
            bpf_l4_csum_replace(skb, off + TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
        } else if (proto == IPPROTO_UDP) {
            bpf_l4_csum_replace(skb, off + UDP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
        }
    }
    bpf_l3_csum_replace(skb, off + IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, field, &new_ip, sizeof(new_ip), 0);
}

static inline void set_new_ipid(struct __sk_buff *skb, unsigned int off,  __be16 new_id) {
    __be16 old_id = htons(load_half(skb, off + IP_ID_OFF));
    bpf_l3_csum_replace(skb, off + IP_CSUM_OFF, old_id, new_id, sizeof(new_id));
    bpf_skb_store_bytes(skb, off + IP_ID_OFF, &new_id, sizeof(new_id), 0);
}

static inline bool complete_pathinfo(struct pathinfo* pathinfo_) {
    // Check the key for both side to make sure the pathinfo is complete.
    return (pathinfo_->local_partial_key != 0 &&
            pathinfo_->remote_partial_key != 0);
}

static inline bool path_expired(struct pathinfo* pathinfo_, int exp_time) {
    return (pathinfo_->last_refresh_time + exp_time < bpf_ktime_get_ns() >> 32 );
}

// Check if UDP packet is VXLAN/Geneve and set VXLAN/Geneve hdr ptr
static inline bool is_encap(struct udphdr* udph) {
    return (udph->dest == bpf_htons(6081) ||
            udph->dest == bpf_htons(4789) ||
            udph->dest == bpf_htons(8472));
}

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static __always_inline __u16 ip_checksum_diff(
        __u16 seed,
        struct iphdr *iphdr_new,
        struct iphdr *iphdr_old)
{
    __u32 csum, size = sizeof(struct iphdr);
    csum = bpf_csum_diff((__be32 *)iphdr_old, size, (__be32 *)iphdr_new, size, seed);
    return csum_fold_helper(csum);
}

#endif  // COMMON_KERN_H_
