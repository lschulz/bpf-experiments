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

#include "scion_addr.hpp"

extern "C" {
#include <arpa/inet.h>
}


IA IA::from_string(std::string &raw)
{
    static std::regex pattern(
        "([0-9]+)-([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})");
    std::smatch match;
    std::stringstream conv;

    if (!std::regex_match(raw, match, pattern))
        throw std::invalid_argument("Invalid IA");
    std::size_t size = match.size();

    // Parse ISD
    std::uint16_t isd = 0;
    conv << match[1];
    conv >> isd;
    if (!conv) throw std::invalid_argument("Invalid ISD");

    // Parse ASN
    ASN asn = 0;
    for (int i = 2; i < size; ++i)
    {
        conv.clear();
        std::uint32_t group = 0;
        conv << match[i].str();
        conv >> std::hex >> group;
        if (!conv) throw std::invalid_argument("Invalid ASN");
        asn <<= ASN_GROUP_BITS;
        asn |= group;
    }

    return IA(isd, asn);
}

std::uint64_t IA::toNetworkOrder() const
{
    return ((std::uint64_t)(htonl(ia)) << 32) | ((std::uint64_t)(htonl(ia >> 32)));
}

std::ostream& operator<<(std::ostream &stream, IA ia)
{
    ISD isd = ia.getISD();
    ASN asn = ia.getASN();
    stream
        << std::dec << isd << '-'
        << std::hex << ((asn >> 2 * IA::ASN_GROUP_BITS) & IA::ASN_GROUP_MAX_VALUE) << ':'
        << ((asn >> IA::ASN_GROUP_BITS) & IA::ASN_GROUP_MAX_VALUE) << ':'
        << ((asn) & IA::ASN_GROUP_MAX_VALUE) << std::dec;
    return stream;
}
