package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)
const (
    mapName   = "drop_port"
    mapSize   = 1024
    bpfSource = `
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
`
)

func main() {

    portNumber := uint16(4040)

    spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(bpfSource))
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error loading BPF program: %v\n", err)
        return
    }
    bpfSource = strings.ReplaceAll(bpfSource, "PORT_NUMBER", strconv.Itoa(int(portNumber)))

    m := spec.Maps[mapName]
    if m == nil {
        fmt.Fprintf(os.Stderr, "Map '%s' not found in BPF program\n", mapName)
        return
    }
    if m.Type != ebpf.Hash {
        fmt.Fprintf(os.Stderr, "Map '%s' is not of hash type\n", mapName)
        return
    }
    if m.KeySize != 4 || m.ValueSize != 8 {
        fmt.Fprintf(os.Stderr, "Map '%s' has incorrect key/value size\n", mapName)
        return
    }
    _, err = ebpf.NewMap(spec.Maps[mapName])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error creating map '%s': %v\n", mapName, err)
        return
    }

    prog := spec.Programs["drop_tcps_on_port"]
    if prog == nil {
        fmt.Fprintf(os.Stderr, "Program 'drop_tcps_on_port' not found in BPF program\n")
        return
    }

    if err := prog.Load(nil); err != nil {
        fmt.Fprintf(os.Stderr, "Error loading program 'drop_tcps_on_port': %v\n", err)
        return
    }

    if err := prog.AttachUprobe("netif_receive_skb", 0); err != nil {
        fmt.Fprintf(os.Stderr, "Error attaching program 'drop_tcps_on_port' to netif_receive_skb: %v\n", err)
        return
    }
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig

    prog.Detach()

    fmt.Println("Program detached, exiting...")
}
