#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/io/stream.hpp>
#include <cstring>

using namespace certpp;

TEST_CASE("IStream::createMemory() write reports the number of bytes actually written") {
    // Regression test: MemStream::write() computed and stored the written bytes correctly (the
    // read-back content was right), but its final `return 0;` (instead of `return len;`) made
    // every caller that checks the return value -- the only way to detect a short/failed write
    // per the IStream::write() contract -- see success be misreported as writing nothing.
    IStreamPtr stream = IStream::createMemory();
    REQUIRE(stream);

    const uint8_t data[] = { 1, 2, 3, 4, 5 };
    size_t written = stream->write(data, sizeof(data));
    CHECK(written == sizeof(data));
    CHECK(stream->length() == sizeof(data));
}

TEST_CASE("IStream::createMemory() read/write/seek round-trip") {
    IStreamPtr stream = IStream::createMemory();
    REQUIRE(stream);

    const uint8_t data[] = { 10, 20, 30, 40 };
    REQUIRE(stream->write(data, sizeof(data)) == sizeof(data));
    CHECK(stream->position() == sizeof(data));

    REQUIRE(stream->seek(0, ESEEK_SET) == ERET_OK);
    CHECK(stream->position() == 0);

    uint8_t readBack[sizeof(data)] = {};
    CHECK(stream->read(readBack, sizeof(readBack)) == sizeof(data));
    CHECK(std::memcmp(readBack, data, sizeof(data)) == 0);

    // Read past the end returns 0, not a partial/garbage read.
    uint8_t extra[4];
    CHECK(stream->read(extra, sizeof(extra)) == 0);
}

TEST_CASE("IStream::createMemory(buf) initializes content and rewinds to the start") {
    const uint8_t data[] = { 7, 8, 9 };
    IStreamPtr stream = IStream::createMemory(SReadOnlyByteSpan(data, sizeof(data)));
    REQUIRE(stream);

    CHECK(stream->length() == sizeof(data));
    CHECK(stream->position() == 0);

    uint8_t readBack[sizeof(data)] = {};
    REQUIRE(stream->read(readBack, sizeof(readBack)) == sizeof(data));
    CHECK(std::memcmp(readBack, data, sizeof(data)) == 0);
}

TEST_CASE("IStream::createMemory() multiple sequential writes append and report correctly") {
    IStreamPtr stream = IStream::createMemory();
    REQUIRE(stream);

    const uint8_t first[] = { 1, 2, 3 };
    const uint8_t second[] = { 4, 5 };

    CHECK(stream->write(first, sizeof(first)) == sizeof(first));
    CHECK(stream->write(second, sizeof(second)) == sizeof(second));
    CHECK(stream->length() == sizeof(first) + sizeof(second));

    REQUIRE(stream->seek(0, ESEEK_SET) == ERET_OK);
    uint8_t readBack[5] = {};
    REQUIRE(stream->read(readBack, sizeof(readBack)) == sizeof(readBack));
    CHECK(readBack[0] == 1);
    CHECK(readBack[3] == 4);
    CHECK(readBack[4] == 5);
}
