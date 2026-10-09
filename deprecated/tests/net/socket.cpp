#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/net/socket.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::net;

TEST_CASE("CSocket reports lifecycle and address errors and transfers TCP data") {
    CSocket empty;
    CHECK(empty.close() == ERET_ALREADY);
    CHECK(empty.listen(1) == ERET_INVAL);
    CHECK(empty.connect(SSocketAddress()) == ERET_INVAL);

    CSocket listener;
    REQUIRE(listener.create(EAF_INET, ESOCK_STREAM, EPROT_TCP) == ERET_OK);
    CHECK(listener.create(EAF_INET, ESOCK_STREAM, EPROT_TCP) == ERET_ALREADY);
    CHECK(listener.listen(-1) == ERET_INVAL);
    CHECK(listener.noDelay(true) == ERET_OK);
    CHECK(listener.blocking(false) == ERET_OK);
    CHECK(listener.blocking(true) == ERET_OK);
    CHECK(listener.recvTimeout(STimeSpan(1000)) == ERET_OK);
    CHECK(listener.sendTimeout(STimeSpan(1000)) == ERET_OK);
    CHECK(listener.recvTimeout(STimeSpan(-1)) == ERET_INVAL);
    CHECK(listener.sendTimeout(STimeSpan(-1)) == ERET_INVAL);

    SSocketAddress bindAddress;
    REQUIRE(SSocketAddress::loopback(bindAddress, 0, EAF_INET) == ERET_OK);
    REQUIRE(listener.bind(bindAddress) == ERET_OK);
    REQUIRE(listener.listen(4) == ERET_OK);

    SSocketAddress serverAddress;
    REQUIRE(listener.localAddress(serverAddress) == ERET_OK);
    REQUIRE(serverAddress.port() > 0);
    CHECK(listener.remoteAddress(serverAddress) == ERET_NOTCONN);

    CSocket duplicateBind;
    REQUIRE(duplicateBind.create(EAF_INET, ESOCK_STREAM, EPROT_TCP) == ERET_OK);
    CHECK(duplicateBind.bind(serverAddress) == ERET_ADDRINUSE);

    CSocket client;
    REQUIRE(client.create(EAF_INET, ESOCK_STREAM, EPROT_TCP) == ERET_OK);
    REQUIRE(client.connect(serverAddress) == ERET_OK);

    CSocket accepted;
    REQUIRE(listener.accept(accepted) == ERET_OK);
    CHECK(accepted.remoteAddress(serverAddress) == ERET_OK);
    CHECK(serverAddress.loopback());

    CSocket duplicate;
    REQUIRE(accepted.dup(duplicate) == ERET_OK);
    CHECK(duplicate);

    const char message[] = "socket round-trip";
    size_t written = 0;
    REQUIRE(client.send(message, sizeof(message), written) == ERET_OK);
    CHECK(written == sizeof(message));

    char received[sizeof(message)] = {};
    size_t read = 0;
    REQUIRE(accepted.recv(received, sizeof(received), read) == ERET_OK);
    CHECK(read == sizeof(message));
    CHECK(std::memcmp(received, message, sizeof(message)) == 0);

    CHECK(client.send(nullptr, 1, written) == ERET_INVAL);
    CHECK(accepted.close() == ERET_OK);
    CHECK(accepted.close() == ERET_ALREADY);
}

TEST_CASE("CSocket maps connection refusal to ERET_CONNREFUSED") {
    CSocket udp;
    REQUIRE(udp.create(EAF_INET, ESOCK_DGRAM, EPROT_UDP) == ERET_OK);
    SSocketAddress address;
    REQUIRE(SSocketAddress::loopback(address, 0, EAF_INET) == ERET_OK);
    REQUIRE(udp.bind(address) == ERET_OK);
    REQUIRE(udp.localAddress(address) == ERET_OK);

    CSocket tcp;
    REQUIRE(tcp.create(EAF_INET, ESOCK_STREAM, EPROT_TCP) == ERET_OK);
    CHECK(tcp.connect(address) == ERET_CONNREFUSED);
}

TEST_CASE("CSocket recv returns ERET_AGAIN on a nonblocking empty socket") {
    CSocket socket;
    REQUIRE(socket.create(EAF_INET, ESOCK_DGRAM, EPROT_UDP) == ERET_OK);
    REQUIRE(socket.blocking(false) == ERET_OK);
    SSocketAddress bindAddress;
    REQUIRE(SSocketAddress::loopback(bindAddress, 0, EAF_INET) == ERET_OK);
    REQUIRE(socket.bind(bindAddress) == ERET_OK);

    char buffer[1] = {};
    size_t read = 99;
    CHECK(socket.recv(buffer, sizeof(buffer), read) == ERET_AGAIN);
    CHECK(read == 0);
}

TEST_CASE("CSocket poll reports readiness, timeouts and invalid sockets") {
    CSocket empty;
    CHECK(empty.poll(EPOLL_RCV, STimeSpan(0)) == ERET_INVAL);

    CSocket receiver;
    CSocket sender;
    REQUIRE(receiver.create(EAF_INET, ESOCK_DGRAM, EPROT_UDP) == ERET_OK);
    REQUIRE(sender.create(EAF_INET, ESOCK_DGRAM, EPROT_UDP) == ERET_OK);
    SSocketAddress address;
    REQUIRE(SSocketAddress::loopback(address, 0, EAF_INET) == ERET_OK);
    REQUIRE(receiver.bind(address) == ERET_OK);
    REQUIRE(receiver.localAddress(address) == ERET_OK);

    EPollHow ready = EPOLL_ANY;
    CHECK(receiver.poll(EPOLL_RCV, STimeSpan(20), &ready) == ERET_TIMEOUT);
    CHECK(ready == 0);

    CHECK(receiver.poll(EPOLL_SND, STimeSpan(0), &ready) == ERET_OK);
    CHECK((ready & EPOLL_SND) != 0);
    CHECK((ready & EPOLL_RCV) == 0);

    const char byte = 'x';
    size_t written = 0;
    REQUIRE(sender.sendTo(address, &byte, 1, written) == ERET_OK);
    CHECK(receiver.poll(EPOLL_RCV, STimeSpan(2000), &ready) == ERET_OK);
    CHECK((ready & EPOLL_RCV) != 0);
    CHECK(receiver.poll(EPOLL_RCV | EPOLL_SND, STimeSpan(-1), &ready) == ERET_OK);
    CHECK(ready == (EPOLL_RCV | EPOLL_SND));
}

TEST_CASE("CSocket sends and receives UDP datagrams with actual address lengths") {
    CSocket receiver;
    CSocket sender;
    REQUIRE(receiver.create(EAF_INET, ESOCK_DGRAM, EPROT_UDP) == ERET_OK);
    REQUIRE(sender.create(EAF_INET, ESOCK_DGRAM, EPROT_UDP) == ERET_OK);

    SSocketAddress bindAddress;
    REQUIRE(SSocketAddress::loopback(bindAddress, 0, EAF_INET) == ERET_OK);
    REQUIRE(receiver.bind(bindAddress) == ERET_OK);

    SSocketAddress receiverAddress;
    REQUIRE(receiver.localAddress(receiverAddress) == ERET_OK);

    const char message[] = "udp";
    size_t written = 0;
    REQUIRE(sender.sendTo(receiverAddress, message, sizeof(message), written) == ERET_OK);
    CHECK(written == sizeof(message));

    char received[sizeof(message)] = {};
    size_t read = 0;
    SSocketAddress senderAddress;
    REQUIRE(receiver.recvFrom(senderAddress, received, sizeof(received), read) == ERET_OK);
    CHECK(read == sizeof(message));
    CHECK(senderAddress.family() == EAF_INET);
    CHECK(senderAddress.port() > 0);
    CHECK(std::memcmp(received, message, sizeof(message)) == 0);
}
