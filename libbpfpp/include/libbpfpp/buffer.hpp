#pragma once
#include "error.hpp"
#include "map.hpp"

extern "C" {
#include <bpf.h>
#include <libbpf.h>
}

#include <cstdint>
#include <memory>


namespace Bpf {

class RingBuffer
{
public:
    RingBuffer(const Map &map, ring_buffer_sample_fn callback)
        : buffer(ring_buffer__new(map.getFd(), callback, nullptr, nullptr))
    {}

    void poll(int timeout)
    {
        ring_buffer__poll(buffer.get(), timeout);
    }

private:
    struct Deleter
    {
        void operator()(struct ring_buffer *buffer) const {
            ring_buffer__free(buffer);
        }
    };
    std::unique_ptr<struct ring_buffer, Deleter> buffer = nullptr;
};

} // namespace Bpf
