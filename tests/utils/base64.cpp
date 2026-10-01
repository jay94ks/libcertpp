#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp/utils/base64.hpp>
#include <certpp/string.hpp>
#include <cstring>

using namespace certpp;

namespace {
    inline SReadOnlyByteSpan toSpan(const char* text) {
        return SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text), std::strlen(text));
    }

    /* Drains finish() into buf (starting at *total), following its own doc note to keep calling
     * it until it returns 0 -- exercised directly (with a deliberately tiny out) by the
     * "finish() can be called repeatedly" test below, and used here as a generic helper so every
     * other test doesn't have to hand-roll the same loop. */
    void drainFinish(CBase64& b64, uint8_t* buf, size_t bufSize, size_t& total) {
        size_t more;
        do {
            SByteSpan tail(buf + total, bufSize - total);
            more = b64.finish(tail);
            total += more;
        } while (more > 0);
    }

    /* Runs a whole input through one push() call (assumed to fit `out` in one shot -- see
     * CBase64::push()'s own doc comment on why it requires that, unlike finish()) followed by
     * drainFinish(), returning the result as a CString for easy comparison against a literal. */
    CString runOneShot(EBase64Mode mode, const SReadOnlyByteSpan& in) {
        CBase64 b64(mode);

        uint8_t buf[8192];
        SByteSpan out(buf, sizeof(buf));
        size_t total = b64.push(in, out);
        REQUIRE(b64.state() == ERET_OK);

        drainFinish(b64, buf, sizeof(buf), total);
        REQUIRE(b64.state() == ERET_OK);

        return CString(reinterpret_cast<const char*>(buf), total);
    }

    CString encodeOneShot(const char* text) {
        return runOneShot(EB64M_ENCODE, toSpan(text));
    }

    CString decodeOneShot(const char* text) {
        return runOneShot(EB64M_DECODE, toSpan(text));
    }

    /* Compares a CBuffer's raw content against a C string's bytes (excluding its terminator). */
    bool bufferEqualsText(const CBuffer& buf, const char* text) {
        size_t len = std::strlen(text);
        if (buf.size() != len) {
            return false;
        }
        return len == 0 || std::memcmp(buf.toPtr(), text, len) == 0;
    }
}

TEST_CASE("CBase64: encode matches RFC 4648's own test vectors") {
    CHECK(encodeOneShot("") == CString(""));
    CHECK(encodeOneShot("f") == CString("Zg=="));
    CHECK(encodeOneShot("fo") == CString("Zm8="));
    CHECK(encodeOneShot("foo") == CString("Zm9v"));
    CHECK(encodeOneShot("foob") == CString("Zm9vYg=="));
    CHECK(encodeOneShot("fooba") == CString("Zm9vYmE="));
    CHECK(encodeOneShot("foobar") == CString("Zm9vYmFy"));
}

TEST_CASE("CBase64: decode matches RFC 4648's own test vectors, and tolerates missing padding") {
    CHECK(decodeOneShot("") == CString(""));
    CHECK(decodeOneShot("Zg==") == CString("f"));
    CHECK(decodeOneShot("Zm8=") == CString("fo"));
    CHECK(decodeOneShot("Zm9v") == CString("foo"));
    CHECK(decodeOneShot("Zm9vYg==") == CString("foob"));
    CHECK(decodeOneShot("Zm9vYmE=") == CString("fooba"));
    CHECK(decodeOneShot("Zm9vYmFy") == CString("foobar"));

    // This decoder is lenient about padding -- finish() infers the final group's shape purely
    // from how many real characters are left over, so omitting the '=' padding entirely still
    // decodes correctly.
    CHECK(decodeOneShot("Zg") == CString("f"));
    CHECK(decodeOneShot("Zm8") == CString("fo"));
}

TEST_CASE("CBase64: decode skips embedded whitespace (line-broken/PEM-style input)") {
    CHECK(decodeOneShot("Zm9v\nYmFy") == CString("foobar"));
    CHECK(decodeOneShot("Zm9v\r\nYmFy\r\n") == CString("foobar"));
    CHECK(decodeOneShot("Zm 9v Ym Fy") == CString("foobar"));
}

TEST_CASE("CBase64: encode/decode round-trip every byte value across a range of lengths") {
    // Lengths spanning all three (input mod 3) cases: 0, 1, and 2 leftover bytes.
    for (size_t len : { size_t(0), size_t(1), size_t(2), size_t(3), size_t(29), size_t(30), size_t(31) }) {
        uint8_t original[32];
        for (size_t i = 0; i < len; ++i) {
            original[i] = static_cast<uint8_t>((i * 37 + 11) & 0xFF);
        }

        CBase64 encoder(EB64M_ENCODE);
        uint8_t encoded[128];
        SByteSpan encOut(encoded, sizeof(encoded));
        size_t encTotal = encoder.push(SReadOnlyByteSpan(original, len), encOut);
        REQUIRE(encoder.state() == ERET_OK);
        drainFinish(encoder, encoded, sizeof(encoded), encTotal);
        REQUIRE(encoder.state() == ERET_OK);

        CBase64 decoder(EB64M_DECODE);
        uint8_t decoded[32];
        SByteSpan decOut(decoded, sizeof(decoded));
        size_t decTotal = decoder.push(SReadOnlyByteSpan(encoded, encTotal), decOut);
        REQUIRE(decoder.state() == ERET_OK);
        drainFinish(decoder, decoded, sizeof(decoded), decTotal);
        REQUIRE(decoder.state() == ERET_OK);

        REQUIRE(decTotal == len);
        CHECK(SReadOnlyByteSpan(decoded, decTotal).sequencialEqual(SReadOnlyByteSpan(original, len)));
    }
}

TEST_CASE("CBase64: a single push() call larger than the internal 2K buffer cap still round-trips") {
    // CBase64 never lets its internal buffer grow past 2048 bytes -- it chunks a larger input
    // internally instead (see pushEncode()/pushDecode()'s own comments). This drives that
    // chunking path directly with one push() call spanning several chunks' worth of input.
    static constexpr size_t LEN = 10000;
    uint8_t* original = new uint8_t[LEN];
    for (size_t i = 0; i < LEN; ++i) {
        original[i] = static_cast<uint8_t>((i * 131 + 7) & 0xFF);
    }

    CBase64 encoder(EB64M_ENCODE);
    size_t encCap = 4 * ((LEN + 2) / 3) + 16;
    uint8_t* encoded = new uint8_t[encCap];
    SByteSpan encOut(encoded, encCap);
    size_t encTotal = encoder.push(SReadOnlyByteSpan(original, LEN), encOut);
    REQUIRE(encoder.state() == ERET_OK);
    drainFinish(encoder, encoded, encCap, encTotal);
    REQUIRE(encoder.state() == ERET_OK);

    CBase64 decoder(EB64M_DECODE);
    uint8_t* decoded = new uint8_t[LEN];
    SByteSpan decOut(decoded, LEN);
    size_t decTotal = decoder.push(SReadOnlyByteSpan(encoded, encTotal), decOut);
    REQUIRE(decoder.state() == ERET_OK);
    drainFinish(decoder, decoded, LEN, decTotal);
    REQUIRE(decoder.state() == ERET_OK);

    REQUIRE(decTotal == LEN);
    CHECK(SReadOnlyByteSpan(decoded, decTotal).sequencialEqual(SReadOnlyByteSpan(original, LEN)));

    delete[] original;
    delete[] encoded;
    delete[] decoded;
}

TEST_CASE("CBase64: push() assembles a group split across several calls") {
    // "Man" ('M','a','n') is exactly one 3-byte group -> "TWFu"; feed it one byte per call.
    CBase64 b64(EB64M_ENCODE);
    uint8_t out[16];

    SByteSpan out1(out, sizeof(out));
    CHECK(b64.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("M"), 1), out1) == 0);
    CHECK(b64.state() == ERET_OK);

    SByteSpan out2(out, sizeof(out));
    CHECK(b64.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("a"), 1), out2) == 0);
    CHECK(b64.state() == ERET_OK);

    SByteSpan out3(out, sizeof(out));
    size_t written = b64.push(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("n"), 1), out3);
    CHECK(b64.state() == ERET_OK);
    REQUIRE(written == 4);
    CHECK(CString(reinterpret_cast<const char*>(out), written) == CString("TWFu"));

    size_t total = written;
    drainFinish(b64, out, sizeof(out), total);
    CHECK(total == written); // nothing left buffered -- "Man" is an exact multiple of 3.
}

TEST_CASE("CBase64: push() reports ERET_NOSPC (recoverable) when out is too small, and succeeds on retry") {
    CBase64 b64(EB64M_ENCODE);
    uint8_t tiny[3]; // "foo" needs 4 bytes to encode -- one short.
    SByteSpan tinyOut(tiny, sizeof(tiny));

    CHECK(b64.push(toSpan("foo"), tinyOut) == 0);
    CHECK(b64.state() == ERET_NOSPC);

    // Nothing was consumed or committed -- the exact same call with a big-enough out succeeds.
    uint8_t big[8];
    SByteSpan bigOut(big, sizeof(big));
    size_t written = b64.push(toSpan("foo"), bigOut);
    CHECK(b64.state() == ERET_OK);
    REQUIRE(written == 4);
    CHECK(CString(reinterpret_cast<const char*>(big), written) == CString("Zm9v"));
}

TEST_CASE("CBase64: decode reports ERET_INVAL on a byte outside the alphabet") {
    CBase64 b64(EB64M_DECODE);
    uint8_t out[16];
    SByteSpan outSpan(out, sizeof(out));

    CHECK(b64.push(toSpan("Zm9v!"), outSpan) == 0);
    CHECK(b64.state() == ERET_INVAL);
}

TEST_CASE("CBase64: finish() can be called repeatedly with an arbitrarily small out span") {
    // "fo" -> "Zm8=" (4 chars) is buffered entirely by push() (< 1 full 3-byte group), so the
    // whole encoded result only ever appears via finish() -- draining it 1 byte at a time proves
    // finish() genuinely supports being called repeatedly, per its own doc comment.
    CBase64 b64(EB64M_ENCODE);
    uint8_t discard[1];
    SByteSpan discardOut(discard, sizeof(discard));
    CHECK(b64.push(toSpan("fo"), discardOut) == 0);
    CHECK(b64.state() == ERET_OK);

    CString result;
    uint8_t one[1];
    for (;;) {
        SByteSpan tiny(one, 1);
        size_t written = b64.finish(tiny);
        CHECK(b64.state() == ERET_OK);
        if (written == 0) {
            break;
        }
        REQUIRE(tiny.size == written);
        result.append(reinterpret_cast<const char*>(one), written);
    }

    CHECK(result == CString("Zm8="));
}

TEST_CASE("CBase64: EB64M_ENCODE_BR wraps output at 64 characters per line") {
    // 49 raw bytes -> 68 Base64 characters (49 is not a multiple of 3, so the final group is
    // padded): the first 64 chars fill exactly one line, the remaining 4 plus padding start a
    // second, unterminated-until-finish() line.
    uint8_t original[49];
    for (size_t i = 0; i < sizeof(original); ++i) {
        original[i] = static_cast<uint8_t>(i);
    }

    CBase64 b64(EB64M_ENCODE_BR);
    uint8_t out[128];
    SByteSpan outSpan(out, sizeof(out));
    size_t total = b64.push(SReadOnlyByteSpan(original, sizeof(original)), outSpan);
    REQUIRE(b64.state() == ERET_OK);
    drainFinish(b64, out, sizeof(out), total);
    REQUIRE(b64.state() == ERET_OK);

    CString result(reinterpret_cast<const char*>(out), total);

    auto firstBreak = result.find('\n');
    REQUIRE(firstBreak >= 0);
    CHECK(firstBreak == 64);

    // The whole thing still round-trips through the decoder (which tolerates the embedded '\n').
    CBase64 decoder(EB64M_DECODE);
    uint8_t decoded[64];
    SByteSpan decOut(decoded, sizeof(decoded));
    size_t decTotal = decoder.push(result.toSpan().reinterpret<uint8_t>(), decOut);
    REQUIRE(decoder.state() == ERET_OK);
    drainFinish(decoder, decoded, sizeof(decoded), decTotal);
    REQUIRE(decoder.state() == ERET_OK);

    REQUIRE(decTotal == sizeof(original));
    CHECK(SReadOnlyByteSpan(decoded, decTotal).sequencialEqual(SReadOnlyByteSpan(original, sizeof(original))));
}

TEST_CASE("CBase64: push() after finish() is rejected until reset()") {
    CBase64 b64(EB64M_ENCODE);
    uint8_t out[16];
    SByteSpan outSpan(out, sizeof(out));
    b64.push(toSpan("hi"), outSpan);

    size_t total = 0;
    drainFinish(b64, out, sizeof(out), total);
    REQUIRE(b64.state() == ERET_OK);

    SByteSpan moreOut(out, sizeof(out));
    CHECK(b64.push(toSpan("more"), moreOut) == 0);
    CHECK(b64.state() == ERET_INVAL);

    b64.reset();
    CHECK(b64.state() == ERET_OK);

    SByteSpan retryOut(out, sizeof(out));
    size_t written = b64.push(toSpan("hi"), retryOut);
    CHECK(b64.state() == ERET_OK);
    REQUIRE(written == 0); // "hi" is only 2 bytes -- buffered, not yet a full group.

    size_t retryTotal = 0;
    drainFinish(b64, out, sizeof(out), retryTotal);
    CHECK(CString(reinterpret_cast<const char*>(out), retryTotal) == CString("aGk="));
}

TEST_CASE("CBase64::encode()/decode(): one-shot convenience wrappers match RFC 4648's vectors") {
    CString encoded;
    REQUIRE(CBase64::encode(encoded, toSpan("foobar")));
    CHECK(encoded == CString("Zm9vYmFy"));

    CBuffer decoded;
    REQUIRE(CBase64::decode(decoded, encoded));
    CHECK(bufferEqualsText(decoded, "foobar"));

    // Every (input length mod 3) case, round-tripped through the one-shot wrappers directly.
    for (const char* text : { "", "f", "fo", "foo", "foob", "fooba", "foobar" }) {
        CString enc;
        REQUIRE(CBase64::encode(enc, toSpan(text)));

        CBuffer dec;
        REQUIRE(CBase64::decode(dec, enc));
        CHECK(bufferEqualsText(dec, text));
    }
}

TEST_CASE("CBase64::encode(breakLines=true) wraps at 64 characters, and decode() reads it back") {
    uint8_t original[100];
    for (size_t i = 0; i < sizeof(original); ++i) {
        original[i] = static_cast<uint8_t>(i * 3);
    }

    CString encoded;
    REQUIRE(CBase64::encode(encoded, SReadOnlyByteSpan(original, sizeof(original)), true));

    auto firstBreak = encoded.find('\n');
    REQUIRE(firstBreak >= 0);
    CHECK(firstBreak == 64);

    CBuffer decoded;
    REQUIRE(CBase64::decode(decoded, encoded));
    REQUIRE(decoded.size() == sizeof(original));
    CHECK(SReadOnlyByteSpan(decoded.toPtr(), decoded.size()).sequencialEqual(SReadOnlyByteSpan(original, sizeof(original))));
}

TEST_CASE("CBase64::decode() fails on an invalid character and leaves out cleared") {
    CBuffer out;
    CHECK_FALSE(CBase64::decode(out, CString("Zm9v!")));
    CHECK(out.empty());
}
