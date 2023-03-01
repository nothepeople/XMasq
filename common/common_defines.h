#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/statfs.h>  /* statfs */
#include <sys/stat.h>    /* stat(2) + S_IRWXU */
#include <sys/mount.h>   /* mount(2) */

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h> /* TC_H_MAJ + TC_H_MIN */
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <getopt.h>
#include "linux/bpf.h"

#define MACLEN 14
#define IPLEN 20
#define UDPLEN 8
#define TCPLEN 20
#define VXLANLEN 8

#define bpf_printkm(fmt, ...)                                    \
({                                                              \
    char ____fmt[] = fmt;                                   \
    bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

#define MAX_IFINDEX 1024

struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

// Must pad the struct to avoid eBPf verifier
// think the stack boundary is iligal.
// #pragma pack(1)
struct fivetuple {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u32 protocol;
};

struct podip {
    __be32 local_ip;
    __be32 remote_ip;
};

struct pathkey {
    __be32 ip;
    __be16 partial_key;
    uint16_t pad;
};

struct pathinfo {
    unsigned char local_mac[ETH_ALEN];
    unsigned char remote_mac[ETH_ALEN];
    __be32 local_ip;
    __be32 remote_ip;
    uint16_t pod_ifkey;
    uint16_t remote_ready;
    uint32_t last_refresh_time;  // in second
    __be16 local_partial_key;
    __be16 remote_partial_key;
};

struct rule {
    struct fivetuple fivetuple_;
    int isIngress;
};

// Should write podmac to a map forahead becuase pod mac is not carried in VXLAN
struct podinfo {
    int ifkey;
    unsigned char podmac[ETH_ALEN];
};

#define PORT_AVAILABLE 1024

int verbose;

#define EXIT_OK   0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL  1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP  3
#define EXIT_FAIL_MAP  20
#define EXIT_FAIL_MAP_KEY 21
#define EXIT_FAIL_MAP_FILE 22
#define EXIT_FAIL_MAP_FS 23
#define EXIT_FAIL_IP  30
#define EXIT_FAIL_CPU  31
#define EXIT_FAIL_BPF  40
#define EXIT_FAIL_BPF_ELF 41
#define EXIT_FAIL_BPF_RELOCATE 42

#endif
