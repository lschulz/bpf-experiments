#pragma once

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>


struct UdpEp
{
    boost::asio::ip::address ip;
    std::uint16_t port;
};

std::ostream& operator<<(std::ostream &stream, const UdpEp &brIf);

struct ExternalIface
{
    std::uint32_t scionIfId;
    std::string ifname;
    UdpEp local;
    UdpEp remote;
};

struct SiblingIface
{
    std::uint32_t scionIfId;
    UdpEp destBr;
};

struct InternalIface
{
    std::string ifname;
    UdpEp local;
};

struct BrInterfaces
{
    std::vector<ExternalIface> external;
    std::vector<SiblingIface> sibling;
    std::vector<InternalIface> internal;
};

std::ostream& operator<<(std::ostream &stream, const BrInterfaces &brIf);

struct BrConfig
{
    std::string self;
    BrInterfaces ifs;
};

std::optional<BrConfig> loadConfig(const char *configFile);
std::ostream& operator<<(std::ostream &stream, const BrConfig &config);
