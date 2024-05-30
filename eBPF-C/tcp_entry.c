#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_TABLE("hash", u32, u64, drop_port, 1024);

int drop_tcps_on_port(struct __sk_buff *skb) {
    u32 key = 0;
    u64 *value;

    struct iphdr *ip = skb_load_bytes(skb, skb->network_header, sizeof(struct iphdr));
    if (ip && ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = skb_load_bytes(skb, skb->network_header + sizeof(struct iphdr), sizeof(struct tcphdr));
        if (tcp && tcp->dest == htons(PORT_NUMBER)) { 
            value = drop_port.lookup_or_init(&key, &value);
            if (value) {
                *value += 1;
                return TC_ACT_SHOT;
            }
        }
    }
    return TC_ACT_OK;
}
