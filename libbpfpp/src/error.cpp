#include "libbpfpp/error.hpp"

#include <string.h>


namespace Bpf {

BpfError::BpfError(int code, const std::string& message)
    : code(code)
{
    std::stringstream stream;
    stream << "BPF Error: " << message << " (" << strerror(code) << ")";
    this->message = stream.str();
}

XdpAttachError::XdpAttachError(int code, int ifindex, const std::string& message)
{
    this->code = code;
    this->ifindex = ifindex;

    std::stringstream stream;
    stream << "XDP Attachment Error: " << message << " (IF: " << ifindex << ")";
    this->message = stream.str();
}

} // namespace Bpf
