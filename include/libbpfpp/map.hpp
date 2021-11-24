#pragma once
#include "error.hpp"

extern "C" {
#include <bpf.h>
#include <libbpf.h>
}

#include <cstdint>


namespace Bpf {

class Map
{
public:
    /// \brief Returns the map's file descriptor.
    int getFd() const { return fd; }

    /// \brief Search for en element in the map and return its value in \p value .
    /// \param[in] key
    /// \param[in] keySize Length of \p key in bytes.
    /// \param[out] value
    /// \param[in] valueSize Length of \p value in bytes.
    /// \return True if the element was found, otherwise false.
    bool lookup(
        const void *key, std::uint32_t keySize,
        void *value, std::uint32_t valueSize) const;

    /// \brief Search for en element in the map, delete it and return its former value in \p value .
    /// \param[in] key
    /// \param[in] keySize Length of \p key in bytes.
    /// \param[out] value
    /// \param[in] valueSize Length of \p value in bytes.
    /// \return True if the element was found, otherwise false.
    bool lookupAndErase(
        const void *key, std::uint32_t keySize,
        void *value, std::uint32_t valueSize) const;

    /// \brief Create or update an element in the map.
    /// \param[in] key
    /// \param[in] keySize Length of \p key in bytes.
    /// \param[in] value
    /// \param[in] valueSize Length of \p value in bytes.
    /// \param[in] flags One of `BPF_ANY`, `BPF_NOEXIST`, `BPF_EXIST`.
    /// \return True if the update was successful, otherwise false.
    bool update(
        const void *key, std::uint32_t keySize,
        const void *value, std::uint32_t valueSize,
        std::uint64_t flags) const;

    /// \brief Erase an element from the map.
    /// \param[in] key
    /// \param[in] keySize Length of \p key in bytes.
    /// \return True if the element was removed, false if the key was not found.
    bool erase(const void *key, std::uint32_t keySize);

    const char* getPinPath() const { return bpf_map__get_pin_path(map); }
    void setPinPath(const char* path) { bpf_map__set_pin_path(map, path); }

    void pin(const char* path)
    {
        int err = bpf_map__pin(map, path);
        if (err) throw BpfError(err, "Pinning map failed");
    }

    void unpin(const char* path)
    {
        int err = bpf_map__unpin(map, path);
        if (err) throw BpfError(err, "Unpinning map failed");
    }

private:
    Map(struct bpf_map* map, std::uint32_t type);

    bool verifyArgSize(std::uint32_t key, std::uint32_t value) const;

    friend class Object;

private:
    struct bpf_map *map = nullptr;
    int fd;
    std::uint32_t mapType, keySize, valueSize;
};

} // namespac Bpf
