#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/net/sockstream.hpp>
#include <cstring>
#include <vector>

using namespace certpp;
using namespace certpp::net;

static ERetCode createTcpPair(CSocket& client, CSocket& accepted, CSocket& listener) {
    ERetCode result = listener.create(EAF_INET, ESOCK_STREAM, EPROT_TCP);
    if (result != ERET_OK) {
        return result;
    }

    SSocketAddress address;
    result = SSocketAddress::loopback(address, 0, EAF_INET);
    if (result != ERET_OK) {
        return result;
    }
    result = listener.bind(address);
    if (result != ERET_OK) {
        return result;
    }
    result = listener.listen(1);
    if (result != ERET_OK) {
        return result;
    }
    result = listener.localAddress(address);
    if (result != ERET_OK) {
        return result;
    }
    result = client.create(EAF_INET, ESOCK_STREAM, EPROT_TCP);
    if (result != ERET_OK) {
        return result;
    }
    result = client.connect(address);
    if (result != ERET_OK) {
        return result;
    }
    return listener.accept(accepted);
}

TEST_CASE("CSocketStream handles an empty socket") {
    CSocketStream stream{ CSocketPtr() };
    CHECK(stream.capabilities() == 0);
    CHECK(stream.capacity() == 0);
    CHECK(stream.length() == 0);
    CHECK(stream.read(nullptr, 0) == 0);
    CHECK(stream.write(nullptr, 0) == 0);
    CHECK(stream.flush() == ERET_BADREQ);
    CHECK(stream.close() == ERET_BADREQ);
}

TEST_CASE("CSocketStream buffers bidirectional I/O and handles peer EOF") {
    CSocket client;
    CSocket accepted;
    CSocket listener;
    REQUIRE(createTcpPair(client, accepted, listener) == ERET_OK);

    CSocketPtr socket = toShared(accepted);
    REQUIRE(socket);
    CHECK(!accepted);

    CSocketStream stream(socket);
    CHECK(stream.socket() == socket);
    CHECK(stream.capabilities() == (ESTREAM_READ | ESTREAM_WRITE));
    CHECK(stream.capacity() == IStream::MAX_SIZE);
    CHECK(stream.length() == IStream::MAX_SIZE);
    CHECK(stream.position() == 0);
    CHECK(stream.seek(0, ESEEK_SET) == ERET_NOTSUP);
    CHECK(stream.trimExcess() == ERET_NOTSUP);
    CHECK(stream.length(0) == ERET_NOTSUP);
    CHECK(stream.read(nullptr, 10) == 0);
    CHECK(stream.write(nullptr, 10) == 0);

    std::vector<uint8_t> outgoing(10 * 1024);
    for (size_t i = 0; i < outgoing.size(); ++i) {
        outgoing[i] = static_cast<uint8_t>(i);
    }
    CHECK(stream.write(outgoing.data(), outgoing.size()) == outgoing.size());
    CHECK(stream.flush() == ERET_OK);

    std::vector<uint8_t> received(outgoing.size());
    size_t read = 0;
    REQUIRE(client.recv(received.data(), received.size(), read) == ERET_OK);
    CHECK(read == received.size());
    CHECK(received == outgoing);

    const uint8_t incoming[] = { 3, 1, 4, 1, 5 };
    size_t written = 0;
    REQUIRE(client.send(incoming, sizeof(incoming), written) == ERET_OK);
    REQUIRE(written == sizeof(incoming));
    REQUIRE(client.shutdown(ESHUT_WR) == ERET_OK);

    uint8_t readBuffer[16] = {};
    CHECK(stream.read(readBuffer, sizeof(readBuffer)) == sizeof(incoming));
    CHECK(std::memcmp(readBuffer, incoming, sizeof(incoming)) == 0);
    CHECK(stream.read(readBuffer, sizeof(readBuffer)) == 0);

    CHECK(stream.close() == ERET_OK);
    CHECK(!*socket);
    CHECK(stream.capabilities() == 0);
    CHECK(stream.close() == ERET_BADREQ);
    CHECK(stream.flush() == ERET_BADREQ);
}

TEST_CASE("CSocketStream returns from nonblocking reads without waiting for the requested length") {
    CSocket client;
    CSocket accepted;
    CSocket listener;
    REQUIRE(createTcpPair(client, accepted, listener) == ERET_OK);
    REQUIRE(accepted.blocking(false) == ERET_OK);
    REQUIRE(accepted.recvTimeout(STimeSpan(100)) == ERET_OK);

    CSocketStream stream(toShared(accepted));
    stream.pollTimeout(STimeSpan(100));
    CHECK(stream.pollTimeout() == STimeSpan(100));
    uint8_t buffer[1] = {};
    CHECK(stream.read(buffer, sizeof(buffer)) == 0);

    // Data arriving while the stream is waiting out ERET_AGAIN is picked up.
    const uint8_t byte = 7;
    size_t written = 0;
    REQUIRE(client.send(&byte, 1, written) == ERET_OK);
    stream.pollTimeout(STimeSpan(2000));
    CHECK(stream.read(buffer, sizeof(buffer)) == 1);
    CHECK(buffer[0] == 7);
}

TEST_CASE("CSocketStream preserves queued bytes and reports flush errors") {
    CSocket client;
    CSocket accepted;
    CSocket listener;
    REQUIRE(createTcpPair(client, accepted, listener) == ERET_OK);

    CSocketPtr socket = toShared(accepted);
    CSocketStream stream(socket);
    REQUIRE(socket->close() == ERET_OK);

    const uint8_t byte = 42;
    CHECK(stream.write(&byte, 1) == 1);
    CHECK(stream.flush() == ERET_INVAL);
    CHECK(stream.close() == ERET_INVAL);
}
