// Copyright (c) 2022 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef DEBUG_H_GUARD
#define DEBUG_H_GUARD

#define bpf_ringbuf_printf(ringbuf, fmt, args...)           \
({                                                          \
    static const char __fmt[] = fmt;                        \
    unsigned long long __param[___bpf_narg(args)];          \
    ___bpf_fill(__param, args);                             \
    char *ptr = bpf_ringbuf_reserve(ringbuf, 128, 0);       \
    if (ptr) {                                              \
    bpf_snprintf(ptr, 128, __fmt, __param, sizeof(__param));\
    bpf_ringbuf_submit(ptr, 0);                             \
    }                                                       \
})

#ifdef XDP_DEBUG_PRINT
#define printf(...) bpf_ringbuf_printf(&debug_ringbuf, ##__VA_ARGS__)
#else
#define printf(...)
#endif

#ifdef XDP_DEBUG_PRINT
// Ignore warnings because of call to static BPF helpers from inline functions
#pragma clang diagnostic ignored "-Wstatic-in-inline"
#endif

#endif // DEBUG_H_GUARD
