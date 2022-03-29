#pragma once

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>


/// \brief IPv4 or IPv6 UDP Endpoint
struct UdpEp
{
    boost::asio::ip::address ip;
    std::uint16_t port;
};
std::ostream& operator<<(std::ostream &stream, const UdpEp &brIf);

/// \brief Describes an external interface of the border router, i.e., an interface to another AS.
struct ExternalIface
{
    std::uint32_t scionIfId; ///< SCION interface id
    std::string ifname;      ///< Name of the physical interface
    UdpEp local;             ///< Local endpoint of the underlay connection
    UdpEp remote;            ///< Remote endpoint of the underlay connection
};

/// \brief Describes a sibling interface, i.e., an external interface at another border router
/// belonging to the same AS.
struct SiblingIface
{
    std::uint32_t scionIfId; ///< SCION interface id
    UdpEp destBr;            ///< Underlay connection to sibling
};

/// \brief Describes an internal interface, i.e., an interface to the internal network.
struct InternalIface
{
    std::string ifname; ///< Name of the physical interface
    UdpEp local;        ///< Source address for SCION packets sent on the internal interface
};

/// \brief Lists of all border router interfaces.
struct BrInterfaces
{
    std::vector<ExternalIface> external;
    std::vector<SiblingIface> sibling;
    std::vector<InternalIface> internal;
};
std::ostream& operator<<(std::ostream &stream, const BrInterfaces &brIf);

/// \brief The border router root configuration object.
struct BrConfig
{
    std::string self;
    BrInterfaces ifs;
};
std::ostream& operator<<(std::ostream &stream, const BrConfig &config);

/// \brief Load the border router configuration file.
/// \return Empty, if loading the configuration failed.
std::optional<BrConfig> loadConfig(const char *configFile);
