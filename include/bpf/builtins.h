/// \file
/// Macros for some compiler built-in functions we can use in BPF.

#ifndef BUILTIN_H_GUARD
#define BUILTIN_H_GUARD

#define ntohs(x) __builtin_bswap16(x)
#define ntohl(x) __builtin_bswap32(x)
#define ntohll(x) __builtin_bswap64(x)
#define htons(x) __builtin_bswap16(x)
#define htonl(x) __builtin_bswap32(x)
#define htonll(x) __builtin_bswap64(x)

#define memset(dest, ch, count) __builtin__memset((dest), (ch), (count))
#define memcpy(dest, src, count) __builtin_memcpy((dest), (src), (count))

#endif // BUILTIN_H_GUARD
