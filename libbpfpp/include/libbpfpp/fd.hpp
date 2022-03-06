#pragma once

extern "C" {
#include <unistd.h>
}

#include <utility>


namespace Bpf {

/// \brief RAII wrapper for file descriptors.
class FileDesc
{
public:
    FileDesc() = default;
    FileDesc(int fd) : fd(fd) {}

    FileDesc(const FileDesc &other) = delete;
    FileDesc(FileDesc &&other) noexcept
        : fd(std::exchange(other.fd, -1))
    {}

    FileDesc& operator=(const FileDesc &other) = delete;
    FileDesc& operator=(FileDesc &&other) noexcept
    {
        std::swap(fd, other.fd);
        return *this;
    }

    ~FileDesc()
    {
        if (fd >= 0) close(fd);
    }

    operator bool() const { return fd >= 0; }

    int get() const { return fd; }
    int release() { return std::exchange(fd, -1); }

private:
    int fd = -1;
};

} // namespace Bpf
