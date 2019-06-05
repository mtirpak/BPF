#include <linux/bpf.h>
#include <bpf_api.h> // from iproute2

// For header parsing
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct bpf_elf_map blacklisted_ips __section("maps") = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(uint32_t),
    .size_value     = sizeof(uint32_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 100,
};

int is_blacklisted(uint32_t addr)
{
    uint32_t *blacklisted = map_lookup_elem(&blacklisted_ips, &addr);
    if (blacklisted)
        return *blacklisted;
    else
        return 0;
}

__section("prog")
int xdp_ingress(struct xdp_md *xdp)
{
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;

    // sanity check
    if ((void*)(eth + 1) > data_end)
        return XDP_DROP;

    // skip anything else then ethernet+ipv4
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    iph = data + sizeof(struct ethhdr);
    if ((void*)(iph + 1) > data_end)
        return XDP_DROP;

    // Drop packets from blacklisted source addresses
    //if (is_blacklisted(ntohl(iph->saddr))) {
    if (is_blacklisted(iph->saddr)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char __license[] __section("license") = "GPL";

