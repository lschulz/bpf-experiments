#pragma once

#include <stdexcept>
#include <string>
#include <sstream>



namespace Bpf {

class BpfError : public virtual std::exception
{
public:
    BpfError(int code, const std::string& message = "");
    int getCode() const { return code; }
    const char* what() const noexcept override { return message.c_str(); }

protected:
    BpfError() = default;

protected:
    int code;
    std::string message;
};

class XdpAttachError : public virtual BpfError
{
public:
    XdpAttachError(int code, int ifindex, const std::string& message = "");
    int getIfIndex() const { return ifindex; }

protected:
    int ifindex;
};

} // namespace Bpf
