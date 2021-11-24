#include "bpf/types.h"
#include "bpf/builtins.h"

#include "bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/types.h>

#include <stddef.h>
#include <stdint.h>

char _license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} telemetry_buffer SEC(".maps");


struct telemetry
{
    __u64 timespamp;
    char data[32];
};


SEC(".xdp")
int xdp_aes(struct xdp_md* ctx)
{
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct telemetry *buf = bpf_ringbuf_reserve(&telemetry_buffer, sizeof(struct telemetry), 0);
    if (buf)
    {
        buf->timespamp = bpf_ktime_get_ns();
        if (data + 32 <= data_end)
            memcpy(&buf->data, data, 32);
        bpf_ringbuf_submit(buf, 0);
    }

    return XDP_PASS;
}
