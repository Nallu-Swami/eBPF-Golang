#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PORT_NUMBER 4040
#define PROCESS_NAME "myprocess"

BPF_HASH(allowed_ports, u32, u32);

int filter_traffic(struct __sk_buff *skb) {
    u32 key = 0;
    u32 *value;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (strcmp(comm, PROCESS_NAME) == 0) {
        struct iphdr *ip = skb_load_bytes(skb, skb->network_header, sizeof(struct iphdr));
        if (ip && ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = skb_load_bytes(skb, skb->network_header + sizeof(struct iphdr), sizeof(struct tcphdr));
            if (tcp) {
                if (tcp->dest != htons(PORT_NUMBER)) {
                    return TC_ACT_SHOT;
                }
            }
        }
    }
    return TC_ACT_OK;
}
