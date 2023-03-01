#include "common_kern.h"

enum field {
    tos, id, options
};

#define PIN_GLOBAL_NS 2
#define USE_FIELD 0
#define ENABLENP
// #define DEBUG
// #define WARNING

struct bpf_elf_map SEC("maps") podip2podinfo = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__be32),
    .size_value = sizeof(struct podinfo),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 1024,
};

// Masq cache map
struct bpf_elf_map SEC("maps") podip2nodepathinfo = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct podip),
    .size_value = sizeof(struct pathinfo),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 65536,
};

// Restore cache map
struct bpf_elf_map SEC("maps") pathkey2podpathinfo = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct pathkey),
    .size_value = sizeof(struct pathinfo),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 65536,
};

// Define 0 is allow and 1 is deny
struct bpf_elf_map SEC("maps") rulesmap = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct rule),
    .size_value = sizeof(__u8),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 65536,
};

struct bpf_elf_map SEC("maps") devmap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(int),
    .size_value = sizeof(int),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem = 1,
};

SEC("tc_init")
int tc_init_func(struct __sk_buff *skb) {
    int err;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

////////////////// Check if the packet is a VXLAN packet ////////////////////
    if (data_end < data + MACLEN * 2 + IPLEN * 2 + UDPLEN + VXLANLEN) goto out;
    struct ethhdr *outer_eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (outer_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *outer_iph = (struct iphdr *)(outer_eth + 1);

    // Check if IP packet is UDP and set UDP hdr ptr
    if (outer_iph->protocol != IPPROTO_UDP) goto out;
    struct udphdr *udph = (struct udphdr *)(outer_iph + 1);

    // Check if UDP packet is VXLAN/Geneve and set VXLAN/Geneve hdr ptr
    if (!is_encap(udph)) goto out;
    // UDP hdr = vxlan/geneve header = 8 bytes
    struct ethhdr * inner_eth = (struct ethhdr *)((void*)udph + UDPLEN + VXLANLEN);

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (inner_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *inner_iph = (struct iphdr *)(inner_eth + 1);
    // Finish all check, and this packet is definitely a packet we need to handle

///////////////////////// Start Pathinfo Init///////////////////////////////
#ifdef DEBUG
    bpf_printkm("(tc_init)INFO: Start initializing.");
#endif
    // Find the key in the map first
    struct podip podip_ = {
        .local_ip = inner_iph->saddr,
        .remote_ip = inner_iph->daddr
    };

    struct podinfo* podinfo_ = bpf_map_lookup_elem(&podip2podinfo, &inner_iph->saddr);
    if (!podinfo_) {
        bpf_printkm("(tc_init)ERROR: No pod info found, goto out.");
        goto out;
    }

#ifdef ENABLENP
    if (!get_rule_action(inner_iph, data_end, &rulesmap, 2)) {
#ifdef DEBUG
        bpf_printkm("(tc_masq)DEBUG: Drop a packet!");
#endif
        return TC_ACT_SHOT;
    }
#endif

    // Make sure there is elem in the map
    struct pathinfo tmpnodepathinfo_;
    initpathinfo(&tmpnodepathinfo_);
    err = bpf_map_update_elem(&podip2nodepathinfo, &podip_, &tmpnodepathinfo_, BPF_NOEXIST);

    uint32_t current_time = bpf_ktime_get_ns() >> 32;
    // Extract Pathinfo from vxlan packet
    struct pathinfo* nodepathinfo_ = bpf_map_lookup_elem(&podip2nodepathinfo, &podip_);
    if (!nodepathinfo_) goto out;

    // Save node path info
    __builtin_memcpy(nodepathinfo_->local_mac, outer_eth->h_source, ETH_ALEN);
    __builtin_memcpy(nodepathinfo_->remote_mac, outer_eth->h_dest, ETH_ALEN);
    nodepathinfo_->local_ip = outer_iph->saddr;
    nodepathinfo_->remote_ip = outer_iph->daddr;
    nodepathinfo_->last_refresh_time = current_time;

    // Save pod path info
    struct pathinfo podpathinfo_;
    initpathinfo(&podpathinfo_);
    __builtin_memcpy(podpathinfo_.local_mac, podinfo_->podmac, ETH_ALEN);
    __builtin_memcpy(podpathinfo_.remote_mac, inner_eth->h_dest, ETH_ALEN);
    podpathinfo_.local_ip = inner_iph->saddr;
    podpathinfo_.remote_ip = inner_iph->daddr;
    podpathinfo_.pod_ifkey = podinfo_->ifkey;
    podpathinfo_.last_refresh_time = current_time;

    err = 0;
    __be16 local_partial_key_ = 0;
    if (nodepathinfo_->local_partial_key == 0) {
        struct pathkey pathkey_ = {
            .ip = outer_iph->daddr,
            .pad = 0
        };
        // Generate a local_partial_key
        for (int i = 0; i < 9; i++) {
#if USE_FIELD == 0
            // We use only the higher 6bit
            local_partial_key_ = (bpf_get_prandom_u32() >> 16) & 0xfc00;
#elif USE_FIELD == 1
            // Sometimes the ip id field can changed on the routing path,
            // We can only use higher 12bit as key safely.
            local_partial_key_ = (bpf_get_prandom_u32() >> 16) & 0xf0ff;
#endif
            nodepathinfo_->local_partial_key = local_partial_key_;
            pathkey_.partial_key = local_partial_key_;
            err = bpf_map_update_elem(&pathkey2podpathinfo, &pathkey_, &podpathinfo_, BPF_NOEXIST);
            if (err == 0) {
#ifdef DEBUG
                bpf_printkm("(tc_init)INFO: Successfully added podpathinfo");
#endif
                break;
            }
        }
        if (err != 0) {
            bpf_printkm("(tc_init)ERROR: Failed to gen a restore key, goto out.");
            goto out;
        }
    } else {
        local_partial_key_ = nodepathinfo_->local_partial_key;
#ifdef WARNING
        bpf_printkm("(tc_init)WARNING: Already alloc key for this flow");
#endif
    }
    int state = 0;
    if (nodepathinfo_->remote_partial_key != 0) {
        state = 3;
    } else {
        state = 2;
    }
    // Local has sent the key to remote
    // Assume the packets do not loss.
    nodepathinfo_->remote_ready = 1;
#if USE_FIELD == 0
    __u8 newtos = (local_partial_key_ >> 8) | state;
    // Set tos in the inner header to mark the init packets
    set_ip_tos(skb, MACLEN + IPLEN + UDPLEN + VXLANLEN, newtos);
#elif USE_FIELD == 1
    set_ip_tos(skb, MACLEN + IPLEN + UDPLEN + VXLANLEN, state << 2);
    set_new_ipid(skb, MACLEN + IPLEN + UDPLEN + VXLANLEN, local_partial_key_);
#endif

#ifdef DEBUG
    bpf_printkm("(tc_init)INFO: finish tc init");
    bpf_printkm("(tc_init)SIP:%x, DIP:%x", podip_.local_ip, podip_.remote_ip);
#endif
out:
    return TC_ACT_OK;
}

SEC("tc_masq")
int tc_masq_func(struct __sk_buff *ctx) {
    int action = TC_ACT_OK;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data_end < data + MACLEN + IPLEN) goto out;
    struct ethhdr *eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *iphdr = (struct iphdr *)(eth + 1);
    unsigned char outproto = iphdr->protocol;
#ifdef DEBUG
    bpf_printkm("(tc_masq)DEBUG: Start masq!");
#endif
    // Use pod sdIP as key
    struct podip podip_ = {
        .local_ip = iphdr->saddr,
        .remote_ip = iphdr->daddr
    };

    // Use the local cache key to look up the pathinfo for masq
    struct pathinfo* pathinfo_ = bpf_map_lookup_elem(&podip2nodepathinfo, &podip_);
    if (!pathinfo_) {
#ifdef DEBUG
        bpf_printkm("(tc_masq)DEBUG: No pathinfo found, can not do masq. goto out");
#endif
        goto out;
    }
#ifdef DEBUG
    bpf_printkm("(tc_masq)DEBUG: Found pathinfo_!");
#endif

    // If the initialize have not finished yet.
    if (!complete_pathinfo(pathinfo_) || pathinfo_->remote_ready == 0) {
#ifdef WARNING
        bpf_printkm("(tc_masq)WARNING: Not complete pathinfo or remote not ready, goto out");
        bpf_printkm("(tc_masq)WARNING: SIP:%x, DIP:%x", podip_.local_ip, podip_.remote_ip);
        bpf_printkm("(tc_masq)WARNING: LocalKey:%d, RemoteKey:%d",
            pathinfo_->local_partial_key, pathinfo_->remote_partial_key);
#endif
        goto out;
    }

#ifdef DEBUG
    bpf_printkm("(tc_masq)DEBUG: SIP:%x, DIP:%x", htonl(podip_.local_ip), htonl(podip_.remote_ip));
#endif

#ifdef ENABLENP
    if (!get_rule_action(iphdr, data_end, &rulesmap, 0)) {
#ifdef DEBUG
        bpf_printkm("(tc_masq)DEBUG: Drop a packet!");
#endif
        return TC_ACT_SHOT;
    }
#endif
    // Change MAC to masqed MAC
    __builtin_memcpy(eth->h_dest, pathinfo_->remote_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, pathinfo_->local_mac, ETH_ALEN);

#if USE_FIELD == 0
    __u8 newtos = (0xfc & (pathinfo_->remote_partial_key >> 8)) | 0x3;
    set_ip_tos(ctx, 0, newtos);
#elif USE_FIELD == 1
    set_ip_tos(ctx, 0, 0xc);
    set_new_ipid(ctx, 0, pathinfo_->remote_partial_key);
#endif
    set_new_ip(ctx, 0, pathinfo_->local_ip, IS_SRC, outproto, false);
    set_new_ip(ctx, 0, pathinfo_->remote_ip, IS_DST, outproto, false);
    pathinfo_->last_refresh_time = bpf_ktime_get_ns() >> 32;

#ifdef DEBUG
    bpf_printkm("(tc_masq)DEBUG: Finished masq the packets");
#endif

    // Key for node interface is always 0
    int tmp = 0;
    unsigned int* ifidx = bpf_map_lookup_elem(&devmap, &tmp);
    if (!ifidx) {
        bpf_printkm("(tc_masq)ERROR: Can not find interface index. goto out");
        goto out;
    }
    action = bpf_redirect_rpeer(*ifidx, 0);
#ifdef DEBUG
    bpf_printkm("(tc_masq)DEBUG: Finished Masq and redirected out!");
#endif
    goto out;
out:
    return action;
}

SEC("tc_restore")
int tc_restore_func(struct __sk_buff *ctx) {
    int err, action = TC_ACT_OK;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data_end < data + MACLEN + IPLEN) goto out;
    struct ethhdr *outer_eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (outer_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *outer_iph = (struct iphdr *)(outer_eth + 1);
    unsigned int outproto = outer_iph->protocol;

    __be16 partial_key_;
#if USE_FIELD == 0
    partial_key_ = (outer_iph->tos & 0xfc) << 8;
#elif USE_FIELD == 1
    partial_key_ = outer_iph->id & 0xf0ff;
#endif
    struct pathkey pathkey_ = {
        .ip = outer_iph->saddr,
        .partial_key = partial_key_,
        .pad = 0
    };

    struct pathinfo* pathinfo_ = bpf_map_lookup_elem(&pathkey2podpathinfo, &pathkey_);
#if USE_FIELD == 0
    if ((!pathinfo_) && ((outer_iph->tos & 0x3) == 0x3)) {
#elif USE_FIELD == 1
    if ((!pathinfo_) && ((outer_iph->tos & 0xc) == 0xc)) {
#endif
        bpf_printkm("(tc_restore)ERROR: Cannot lookup the restore key %x for masqed flow", outer_iph->id);
        bpf_printkm("sip:%x, dip:%x", ntohl(outer_iph->saddr), ntohl(outer_iph->daddr));
    }

#if USE_FIELD == 0
    if (pathinfo_ && ((outer_iph->tos & 0x3) == 0x3)) {
#elif USE_FIELD == 1
    if (pathinfo_ && ((outer_iph->tos & 0xc) == 0xc)) {
#endif
#ifdef DEBUG
        bpf_printkm("(tc_restore)DEBUG: Start doing restore using key: %x", pathkey_.partial_key);
#endif
        // This packet is a masqed packet and should be restored
        // Change MAC to masqed MAC
        __builtin_memcpy(outer_eth->h_dest, pathinfo_->local_mac, ETH_ALEN);
        __builtin_memcpy(outer_eth->h_source, pathinfo_->remote_mac, ETH_ALEN);

        if (check_l4_bound(outproto, outer_iph + 1, data_end)) goto out;
        set_ip_tos(ctx, 0, 0x0);
        set_new_ip(ctx, 0, pathinfo_->remote_ip, IS_SRC, outproto, true);
        set_new_ip(ctx, 0, pathinfo_->local_ip, IS_DST, outproto, true);

#ifdef ENABLENP
        data_end = (void *)(long)ctx->data_end;
        data = (void *)(long)ctx->data;
        if (data_end < data + MACLEN + IPLEN) goto out;
        outer_iph = (struct iphdr *)(data + MACLEN);
        if (!get_rule_action(outer_iph, data_end, &rulesmap, 1)) {
#ifdef DEBUG
            bpf_printkm("(tc_restore)DEBUG: Drop a packet!");
#endif
            return TC_ACT_SHOT;
        }
#endif
        // Refresh the time for compute the expire time.
        pathinfo_->last_refresh_time = bpf_ktime_get_ns() >> 32;

        action = bpf_redirect_peer(pathinfo_->pod_ifkey, 0);
#ifdef DEBUG
        bpf_printkm("(tc_restore)INFO: Finished doing restore");
#endif
        goto out;

    } else {
        if (data_end < data + MACLEN * 2 + IPLEN * 2 + UDPLEN + VXLANLEN) goto out;

        // Check if IP packet is UDP and set UDP hdr ptr
        if (outer_iph->protocol != IPPROTO_UDP) goto out;
        struct udphdr *udph = (struct udphdr *)(outer_iph + 1);

        // Check if UDP packet is VXLAN/Geneve and set VXLAN/Geneve/OTV hdr ptr
        if (!is_encap(udph)) goto out;
        // UDP hdr = vxlan/geneve header = 8 bytes
        struct ethhdr * inner_eth = (struct ethhdr *)((void*)udph + UDPLEN + VXLANLEN);

        // Check if Ethernet frame has IP packet and set IP hdr ptr
        if (inner_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
        struct iphdr *inner_iph = (struct iphdr *)(inner_eth + 1);

        // Test if the packet is a init packet
        // The bit that stand for the remote key must be 1
#if USE_FIELD == 0
        int state = inner_iph->tos & 0x3;
#elif USE_FIELD == 1
        int state = (inner_iph->tos >> 2) & 0x3;
#endif
        if ((state & 0x2) != 0x2) goto out;
        // This is a init packet
#ifdef DEBUG
        bpf_printkm("(tc_restore)INFO: Start pathinfo init at restore!");
#endif
#ifdef ENABLENP
        if (!get_rule_action(inner_iph, data_end, &rulesmap, 2)) {
#ifdef DEBUG
            bpf_printkm("(tc_masq)DEBUG: Drop a packet!");
#endif
            return TC_ACT_SHOT;
        }
#endif
        // Find the key in the map first
        struct podip podip_ = {
            .local_ip = inner_iph->daddr,
            .remote_ip = inner_iph->saddr
        };
        // Make sure there is elem in the map
        struct pathinfo tmpnodepathinfo_;
        initpathinfo(&tmpnodepathinfo_);
        err = bpf_map_update_elem(&podip2nodepathinfo, &podip_, &tmpnodepathinfo_, BPF_NOEXIST);

        struct pathinfo* nodepathinfo_ = bpf_map_lookup_elem(&podip2nodepathinfo, &podip_);
        if (!nodepathinfo_) {
            bpf_printkm("(tc_restore)ERROR: No node_pathinfo_ found, goto out.");
            goto out;
        }
        if ((state & 0x1) != 0x1) {
            // If the remote does not know the local key
            // We should use VXLAN in next sending packet
            nodepathinfo_->remote_ready = 0;
        }
#if USE_FIELD == 0
        nodepathinfo_->remote_partial_key = (inner_iph->tos & 0xfc) << 8;
#elif USE_FIELD == 1
        nodepathinfo_->remote_partial_key = inner_iph->id;
#endif
        nodepathinfo_->last_refresh_time = bpf_ktime_get_ns() >> 32;
#ifdef DEBUG
        bpf_printkm("(tc_restore)INFO: Finished pathinfo init at restore!");
#endif
    }
out:
    return action;
}

char _license[] SEC("license") = "GPL";
