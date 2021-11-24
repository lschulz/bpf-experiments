#pragma once

#include <utility>


/// \brief RAII wrapper for file descriptors.
class FileDesc
{
public:
    FileDesc() = default;
    FileDesc(int fd)
        : fd(fd)
    {}

    FileDesc(const FileDesc &other) = delete;
    FileDesc(FileDesc &&other) noexcept
    {
        fd = other.release();
    }

    FileDesc& operator=(const FileDesc &other) = delete;
    FileDesc& operator=(FileDesc &&other) noexcept
    {
        if (&other != this) reset(other.release());
        return *this;
    }

    ~FileDesc()
    {
        reset(-1);
    }

    int get() const { return fd; }

    void reset(int fd)
    {
        if (this->fd != -1) close(this->fd);
        this->fd = fd;
    }

    int release()
    {
        return std::exchange(fd, -1);
    }

private:
    int fd = -1;
};
