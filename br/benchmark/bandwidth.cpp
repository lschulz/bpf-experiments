#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <vector>

using ip_address = boost::asio::ip::address;
using boost::asio::ip::udp;
using std::uint8_t;
using std::size_t;

static constexpr size_t MTU = 1500;


std::vector<uint8_t> loadPacket(const char *filePath)
{
    std::vector<uint8_t> pkt;
    pkt.resize(MTU);

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return pkt;

    file.read(reinterpret_cast<char*>(pkt.data()), pkt.size());
    pkt.resize(file.gcount());
    return pkt;
}

////////////
// Server //
////////////

class Server
{
public:
    Server(boost::asio::io_context &ctx, const udp::endpoint &ep)
        : socket(ctx, ep)
        , timer(ctx, std::chrono::seconds(1))
        , vec(2048)
    {}

    void start()
    {
        using namespace std::placeholders;

        auto buffer = boost::asio::buffer(vec);
        udp::endpoint remoteEp;
        socket.async_receive_from(buffer, remoteEp,
            std::bind(&Server::receivedPktHandler, this, _1, _2));
        timer.async_wait(std::bind(&Server::printRate, this, _1));

        pkts = 0;
        lastInterval = std::chrono::high_resolution_clock::now();
    }

    void receivedPktHandler(const boost::system::error_code &error, std::size_t len)
    {
        using namespace std::placeholders;

        ++pkts;
        auto buffer = boost::asio::buffer(vec);
        udp::endpoint remoteEp;
        socket.async_receive_from(buffer, remoteEp,
            std::bind(&Server::receivedPktHandler, this, _1, _2));
    }

    void printRate(const boost::system::error_code &error)
    {
        using namespace std::placeholders;

        auto duration = std::chrono::high_resolution_clock::now() - lastInterval;
        double seconds = 1e-9 * std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
        auto rate = (double)pkts / seconds;
        std::cout << "Rate: " << std::fixed << std::setprecision(4) << rate
                  << " pkts/second" << std::endl;

        pkts = 0;
        lastInterval = std::chrono::high_resolution_clock::now();
        timer.expires_at(timer.expiry() + std::chrono::seconds(1));
        timer.async_wait(std::bind(&Server::printRate, this, _1));
    }

private:
    udp::socket socket;
    boost::asio::steady_timer timer;
    std::vector<char> vec;
    unsigned int pkts = 0;
    std::chrono::high_resolution_clock::time_point lastInterval;
};

////////////
// Client //
////////////

void runClient(
    boost::asio::io_context &ctx, const udp::endpoint &ep,
    const std::vector<uint8_t> &scionPkt, unsigned long count
)
{
    auto buffer = boost::asio::buffer(scionPkt);

    udp::socket socket(ctx);
    socket.connect(ep);
    for (unsigned int i = 0; i < count; ++i)
    {
        socket.send(buffer);
    }
}

//////////
// Main //
//////////

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        std::cerr << "Usage: " << argv[0] << " server <ip> <port>\n";
        std::cerr << "       " << argv[0] << " client <ip> <port> <packet> <rate>\n";
        return 1;
    }

    // Parse IP
    boost::system::error_code err;
    auto addr = boost::asio::ip::make_address(argv[2], err);
    if (err)
    {
        std::cerr << err.message() << '\n';
        return 1;
    }

    // Parse port
    unsigned long port = 0;
    try {
        port = std::stoul(argv[3]);
    }
    catch (std::exception&) {
        std::cerr << "Invalid port number\n";
        return 1;
    }
    if (port > 65535)
    {
        std::cout << "Invalid port number\n";
        return 1;
    }

    // Load packet data and parse packet rate
    std::vector<uint8_t> pkt;
    unsigned long count = 0;
    if (std::strcmp(argv[1], "client") == 0)
    {
        if (argc < 6)
        {
            std::cerr << "Specify packet contents and count\n";
            return 1;
        }

        pkt = loadPacket(argv[4]);
        if (pkt.empty())
        {
            std::cerr << "Loading packet data failed\n";
            return 1;
        }
        std::cout << "Packet size: " << pkt.size() << " bytes\n";

        try {
            count = std::stoul(argv[5]);
        }
        catch (std::exception&) {
            std::cerr << "Invalid packet count\n";
            return 1;
        }

    }

    udp::endpoint ep(addr, port);
    std::cout << "Endpoint: " << ep << std::endl;
    boost::asio::io_context ctx;

    try {
        if (std::strcmp(argv[1], "server") == 0)
        {
            Server server(ctx, ep);
            server.start();
            ctx.run();
        }
        else if (std::strcmp(argv[1], "client") == 0)
        {
            runClient(ctx, ep, pkt, count);
        }
        else
            std::cerr << "Invalid mode\n";
    }
    catch (std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
