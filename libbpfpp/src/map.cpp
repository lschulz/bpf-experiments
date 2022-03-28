#include "libbpfpp/map.hpp"


namespace Bpf {

/////////
// Map //
/////////

Map::Map(int fd, std::uint32_t type)
    : mapType(type)
{
    struct bpf_map_info info;
    unsigned int infoLen = sizeof(info);
    int err = bpf_obj_get_info_by_fd(fd, &info, &infoLen);
    if (err) throw BpfError(err, "Error in bpf_obj_get_info_by_fd");
    if (infoLen != sizeof(info)) throw std::invalid_argument("Not a map");

    if (info.type != mapType)
        throw BpfError(0, "Map type mismatch");
    keySize = info.key_size;
    valueSize = info.value_size;
}

bool Map::lookup(
    const void *key, std::uint32_t keySize,
    void *value, std::uint32_t valueSize) const
{
    if (!verifyArgSize(keySize, valueSize))
        throw std::out_of_range("Invalid key/value size.");
    int err = bpf_map_lookup_elem(getFd(), key, value);
    if (err)
    {
        if (errno == ENOENT)
            return false; // element not found
        else
            throw BpfError(err, "Error in bpf_map_lookup_elem");
    }
    return true;
}

bool Map::lookupAndErase(
    const void *key, std::uint32_t keySize,
    void *value, std::uint32_t valueSize) const
{
    if (!verifyArgSize(keySize, valueSize))
        throw std::out_of_range("Invalid key/value size.");
    int err = bpf_map_lookup_and_delete_elem(getFd(), key, value);
    if (err)
    {
        if (errno == ENOENT)
            return false; // element not found
        else
            throw BpfError(err, "Error in bpf_map_lookup_and_delete_elem");
    }
    return true;
}

bool Map::update(
    const void *key, std::uint32_t keySize,
    const void *value, std::uint32_t valueSize,
    std::uint64_t flags) const
{
    if (!verifyArgSize(keySize, valueSize))
        throw std::out_of_range("Invalid key/value size.");
    int err = bpf_map_update_elem(getFd(), key, value, flags);
    if (err)
    {
        switch (errno)
        {
        case EEXIST:
            return false; // element exists already (if flags == BPF_NOEXIST)
        case ENOENT:
            return false; // element not found (if flags == BPF_EXIST)
        case E2BIG:
            return false; // map is full
        default:
            throw BpfError(0, "Error in bpf_map_update_elem");
        }
    }
    return true;
}

bool Map::erase(const void *key, std::uint32_t keySize)
{
    if (keySize < this->keySize)
        throw std::out_of_range("Invalid key size.");
    int err = bpf_map_delete_elem(getFd(), key);
    if (err)
    {
        if (errno == ENOENT)
            return false; // element not found
        else
            throw BpfError(err, "Error in bpf_map_delete_elem");
    }
    return true;
}

bool Map::verifyArgSize(std::uint32_t key, std::uint32_t value) const
{
    switch (mapType)
    {
    case BPF_MAP_TYPE_PERCPU_ARRAY:
    case BPF_MAP_TYPE_PERCPU_HASH:
        return key >= keySize && value >= (sysconf(_SC_NPROCESSORS_ONLN) * valueSize);
    default:
        return key >= keySize && value >= valueSize;
    }
}

///////////////
// BpfLibMap //
///////////////

static int getMapFd(struct bpf_map* map)
{
    int fd = bpf_map__fd(map);
    if (fd < 0) throw BpfError(-fd, "Cannot get map file descriptor");
    return fd;
}

BpfLibMap::BpfLibMap(struct bpf_map* map, std::uint32_t type)
    : Map(getMapFd(map), type), map(map)
{}

///////////////
// PinnedMap //
///////////////

PinnedMap PinnedMap::Open(const char* path, std::uint32_t type)
{
    FileDesc fd(bpf_obj_get(path));
    if (!fd) throw BpfError(-fd, std::string("Cannot open map pinned at ") + path);
    return PinnedMap(std::move(fd), type);
}

} // namespace Bpf
