package main
import (
    "fmt"
    "os"
    "os/signal"
    "strings"
    "syscall"

    "github.com/cilium/ebpf"
)
const (
    mapName   = "allowed_ports"
    mapSize   = 1024
    bpfSource = `#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PORT_NUMBER 4040
#define PROCESS_NAME "myprocess"

BPF_HASH(allowed_ports, u32, u32);

int filter_traffic(struct __sk_buff *skb) {
    u32 key = 0;
    u32 *value;

    // Retrieve the process name
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Check if the process name matches
    if (strcmp(comm, PROCESS_NAME) == 0) {
        struct iphdr *ip = skb_load_bytes(skb, skb->network_header, sizeof(struct iphdr));
        if (ip && ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = skb_load_bytes(skb, skb->network_header + sizeof(struct iphdr), sizeof(struct tcphdr));
            if (tcp) {
                // Check if the TCP port matches
                if (tcp->dest != htons(PORT_NUMBER)) {
                    // Drop the packet
                    return TC_ACT_SHOT;
                }
            }
        }
    }

    return TC_ACT_OK;
}`
)

func main() {
    spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(bpfSource))
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error loading BPF program: %v\n", err)
        return
    }
    m := spec.Maps[mapName]
    if m == nil {
        fmt.Fprintf(os.Stderr, "Map '%s' not found in BPF program\n", mapName)
        return
    }
    if m.Type != ebpf.Hash {
        fmt.Fprintf(os.Stderr, "Map '%s' is not of hash type\n", mapName)
        return
    }
    if m.KeySize != 4 || m.ValueSize != 4 {
        fmt.Fprintf(os.Stderr, "Map '%s' has incorrect key/value size\n", mapName)
        return
    }
    _, err = ebpf.NewMap(spec.Maps[mapName])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error creating map '%s': %v\n", mapName, err)
        return
    }
    prog := spec.Programs["filter_traffic"]
    if prog == nil {
        fmt.Fprintf(os.Stderr, "Program 'filter_traffic' not found in BPF program\n")
        return
    }
    if err := prog.Load(nil); err != nil {
        fmt.Fprintf(os.Stderr, "Error loading program 'filter_traffic': %v\n", err)
        return
    }
    if err := prog.AttachUprobe("netif_receive_skb", 0); err != nil {
        fmt.Fprintf(os.Stderr, "Error attaching program 'filter_traffic' to netif_receive_skb: %v\n", err)
        return
    }
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig
    prog.Detach()
    fmt.Println("Program detached, exiting...")
}
