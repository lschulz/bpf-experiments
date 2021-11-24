#ifndef AES_HW_ACCEL_H_GUARD
#define AES_HW_ACCEL_H_GUARD

#include "aes.h"
#include <emmintrin.h>


void aes_key_expansion_128(__m128i key, __m128i key_schedule[AES_SCHED_SIZE / 4]);

__m128i aes_cypher_128(const __m128i input, const __m128i key_schedule[AES_SCHED_SIZE / 4]);

void aes_cypher_unaligned128(
    const struct aes_block *input,
    const __m128i key_schedule[AES_SCHED_SIZE / 4],
    struct aes_block *output);

void aes_cmac_subkeys_128(const __m128i key_schedule[AES_SCHED_SIZE / 4], __m128i subkeys[2]);

void aes_cmac_unaligned128(
    const uint8_t *data, size_t len,
    const __m128i key_schedule[AES_SCHED_SIZE / 4],
    const __m128i subkeys[2],
    struct aes_cmac *mac);

#endif // AES_HW_ACCEL_H_GUARD
