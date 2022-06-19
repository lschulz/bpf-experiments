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

#pragma once

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <regex>
#include <stdexcept>
#include <string>


using ISD = std::uint16_t;
using ASN = std::uint64_t;


/// \brief Isolation domain and AS number of a SCION AS.
class IA
{
public:
    static constexpr int ISD_BITS = 16;
    static constexpr int ASN_BITS = 48;
    static constexpr int ASN_GROUP_BITS = 16;
    static constexpr std::uint64_t ASN_MAX_VALUE = (1ull << ASN_BITS) - 1;
    static constexpr std::uint64_t ASN_GROUP_MAX_VALUE = (1ull << ASN_GROUP_BITS) - 1;

    IA() = default;
    IA(ISD isd, ASN asn)
        : ia((static_cast<std::uint64_t>(isd) << ASN_BITS) | asn)
    {}

    /// \brief Parse a string of the form `1-ff00:0:1`.
    /// \exception std::invalid_argument if the address format is invalid
    static IA from_string(std::string &raw);

    std::uint64_t get() const { return ia; }
    ISD getISD() const { return ia >> ASN_BITS; }
    ASN getASN() const { return ia & ASN_MAX_VALUE; }

    /// \brief Returns the ISD-AS pair in network byte order.
    std::uint64_t toNetworkOrder() const;

    friend std::ostream& operator<<(std::ostream &stream, IA ia);

private:
    std::uint64_t ia = 0;
};
