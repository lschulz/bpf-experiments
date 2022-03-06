extern "C" {
#include "aes/aes.h"
#include "aes/aes_hw_accel.h"
}

#include <chrono>
#include <iomanip>
#include <iostream>


static const struct aes_key key = {{ .w = {
    0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
}}};


void benchmarkSoft(unsigned int n)
{
    struct aes_key_schedule keySchedule = {};
    aes_key_expansion(&key, &keySchedule);
    struct aes_block subkeys[2] = {};
    aes_cmac_subkeys(&keySchedule, subkeys);

    uint64_t message[2] = {};
    struct aes_cmac mac = {};
    for (unsigned int i = 0; i < n; ++i)
    {
        message[0] = message[1] = i;
        auto t0 = std::chrono::high_resolution_clock::now();
        aes_cmac(
            reinterpret_cast<const uint8_t*>(message), sizeof(message),
            &keySchedule, subkeys, &mac);
        auto t1 = std::chrono::high_resolution_clock::now();
        auto delta = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        std::cout << "0x";
        for (unsigned int i = 0; i < 16; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << +mac.b[i];
        std::cout << " " << std::dec << std::setw(8) << std::setfill(' ') << delta << '\n';
    }
}

void benchmarkHard(unsigned int n)
{
    __m128i keyReg = _mm_loadu_si128((const __m128i_u*)&key);
    __m128i keySchedule[AES_SCHED_SIZE / 4] = {};
    aes_key_expansion_128(keyReg, keySchedule);
    __m128i subkeys[2] = {};
    aes_cmac_subkeys_128(keySchedule, subkeys);

    uint64_t message[2] = {};
    struct aes_cmac mac = {};
    for (unsigned int i = 0; i < n; ++i)
    {
        message[0] = message[1] = i;
        auto t0 = std::chrono::high_resolution_clock::now();
        aes_cmac_unaligned128(
            reinterpret_cast<const uint8_t*>(message), sizeof(message),
            keySchedule, subkeys, &mac);
        auto t1 = std::chrono::high_resolution_clock::now();
        auto delta = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        std::cout << "0x";
        for (unsigned int i = 0; i < 16; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << +mac.b[i];
        std::cout << " " << std::dec << std::setw(8) << std::setfill(' ') << delta << '\n';
    }
}

int main(int argc, char* argv[])
{
    std::cout << "AES CPU Benchmark\n";

    std::cout << "Software\n";
    benchmarkSoft(10);

    std::cout << "With Hardware Support\n";
    benchmarkHard(10);

    return 0;
}
