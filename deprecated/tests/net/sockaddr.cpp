#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/net/sockaddr.hpp>

using namespace certpp;
using namespace certpp::net;

TEST_CASE("SSocketAddress resolves numeric and hostname addresses") {
    SSocketAddress ipv4;
    REQUIRE(SSocketAddress::resolve(ipv4, CString("127.0.0.1"), 8443, EAF_INET) == ERET_OK);
    CHECK(ipv4.family() == EAF_INET);
    CHECK(ipv4.port() == 8443);
    CHECK(ipv4.loopback());

    SSocketAddress hostname;
    REQUIRE(SSocketAddress::resolve(hostname, CString("localhost"), 443, EAF_UNSPEC) == ERET_OK);
    CHECK(hostname.family() != EAF_UNSPEC);
    CHECK(hostname.port() == 443);

    std::vector<SSocketAddress> addresses;
    REQUIRE(SSocketAddress::resolve(addresses, CString("localhost"), 5353) == ERET_OK);
    REQUIRE(!addresses.empty());
    CHECK(addresses.front().port() == 5353);

    SSocketAddress missing;
    CHECK(SSocketAddress::resolve(missing, CString("libcertpp-no-such-host.invalid")) == ERET_NOTFOUND);
}
