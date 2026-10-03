#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include <cstring>
#include <string>

using namespace certpp;
using namespace certpp::dnssec;

// DNSKEY/DS/RRSIG against the published examples in RFC 5702 (RSA), RFC 6605 (ECDSA) and
// RFC 8080 (EdDSA).
//
// These are strong vectors for this code specifically, because both values they publish -- the
// key tag and the DS digest -- are computed over the *whole* DNSKEY RDATA. Any error in the field
// order, the field widths, the flags byte order, or the canonicalisation of the owner name
// changes both. There is no way to get a published key tag by accident.
//
// One gap is worth naming, since it is not obvious and it decided which vectors appear here: the
// ECDSA and EdDSA examples all use flags 257, and 257 is 0x0101, which reads the same in either
// byte order. Those six examples cannot tell a big-endian flags field from a little-endian one.
// The RFC 5702 RSA examples use flags 256 == 0x0100 and can, which is why they are included even
// though they publish no DS record to check.

namespace {
    /* The RFCs print their keys wrapped across lines; CBase64::decode() skips whitespace, so the
     * strings below are copied from the RFCs as they appear rather than re-joined by hand. */
    CBuffer fromBase64(const char* text) {
        CBuffer out;
        REQUIRE(CBase64::decode(out, CString(text)));
        return out;
    }

    std::string toHex(const uint8_t* data, size_t size) {
        static const char* DIGITS = "0123456789abcdef";

        std::string out;
        out.reserve(size * 2);
        for (size_t i = 0; i < size; ++i) {
            out.push_back(DIGITS[data[i] >> 4]);
            out.push_back(DIGITS[data[i] & 0x0F]);
        }
        return out;
    }

    SDnskey makeKey(uint16_t flags, EDnsAlgorithms algorithm, const char* keyBase64) {
        SDnskey key;
        key.flags = flags;
        key.protocol = SDnskey::PROTOCOL_DNSSEC;
        key.algorithm = algorithm;
        key.publicKey = fromBase64(keyBase64);
        return key;
    }

    uint16_t tagOf(const SDnskey& key) {
        uint16_t tag = 0;
        REQUIRE(key.keyTag(tag));
        return tag;
    }

    std::string dsOf(const char* owner, const SDnskey& key, EDnsDigests digestType) {
        SDsRecord ds;
        REQUIRE(SDsRecord::fromDnskey(CString(owner), key, digestType, ds));
        return toHex(ds.digest.toPtr(), ds.digest.size());
    }
}

TEST_CASE("DNSKEY: RFC 6605 6.1 -- ECDSA P-256, key tag and SHA-256 DS") {
    const SDnskey key = makeKey(257, EDNSALG_ECDSAP256SHA256,
        "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb"
        "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");

    CHECK(key.publicKey.size() == 64);          // x | y, 32 octets each
    CHECK(tagOf(key) == 55648);
    CHECK(dsOf("example.net.", key, EDNSDIG_SHA256)
          == "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17");
}

TEST_CASE("DNSKEY: RFC 6605 6.2 -- ECDSA P-384, key tag and SHA-384 DS") {
    const SDnskey key = makeKey(257, EDNSALG_ECDSAP384SHA384,
        "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1"
        "w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8"
        "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40");

    CHECK(key.publicKey.size() == 96);          // x | y, 48 octets each
    CHECK(tagOf(key) == 10771);
    CHECK(dsOf("example.net.", key, EDNSDIG_SHA384)
          == "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0"
             "563a9b5f4d288405c3008a946df983d6");
}

TEST_CASE("DNSKEY: RFC 8080 -- Ed25519, both examples") {
    const SDnskey first = makeKey(257, EDNSALG_ED25519,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");

    CHECK(first.publicKey.size() == 32);
    CHECK(tagOf(first) == 3613);
    CHECK(dsOf("example.com.", first, EDNSDIG_SHA256)
          == "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b");

    const SDnskey second = makeKey(257, EDNSALG_ED25519,
        "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=");

    CHECK(second.publicKey.size() == 32);
    CHECK(tagOf(second) == 35217);
    CHECK(dsOf("example.com.", second, EDNSDIG_SHA256)
          == "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c");
}

TEST_CASE("DNSKEY: RFC 8080 -- Ed448, both examples") {
    const SDnskey first = makeKey(257, EDNSALG_ED448,
        "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx"
        "1FYYUcJKm1MDpJtIA");

    // 57, not 56: Ed448 encodes a point in 57 octets.
    CHECK(first.publicKey.size() == 57);
    CHECK(tagOf(first) == 9713);
    CHECK(dsOf("example.com.", first, EDNSDIG_SHA256)
          == "6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2b19c7");

    const SDnskey second = makeKey(257, EDNSALG_ED448,
        "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcN"
        "Lp5HlHAMy12VoISsA");

    CHECK(second.publicKey.size() == 57);
    CHECK(tagOf(second) == 38353);
    CHECK(dsOf("example.com.", second, EDNSDIG_SHA256)
          == "645ff078b3568f5852b70cb60e8e696cc77b75bfaaffc118cf79cbda1ba28af4");
}

TEST_CASE("DNSKEY: RFC 5702 -- RSA, the only published examples with flags 256") {
    // These two are what pin the flags byte order; see the note at the top of this file.
    const SDnskey sha256Key = makeKey(256, EDNSALG_RSASHA256,
        "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36Bponcw"
        "tkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=");

    CHECK(tagOf(sha256Key) == 9033);

    const SDnskey sha512Key = makeKey(256, EDNSALG_RSASHA512,
        "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6p"
        "nWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVs"
        "Mu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL");

    CHECK(tagOf(sha512Key) == 3740);

    // Swapping the flags bytes must change the tag -- which is exactly what the flags-257
    // examples above cannot demonstrate.
    SDnskey swapped = sha256Key;
    swapped.flags = 0x0001;                     // 256 byte-swapped
    CHECK(tagOf(swapped) != 9033);
}

TEST_CASE("DNSKEY: the owner name is folded to lowercase before the DS digest") {
    const SDnskey key = makeKey(257, EDNSALG_ECDSAP256SHA256,
        "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb"
        "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");

    const char* expected =
        "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17";

    // RFC 4034 6.2: the owner name is canonicalised, so a mixed-case spelling of the same name
    // must produce the same digest as the lowercase one the RFC prints.
    CHECK(dsOf("ExAmPlE.nEt.", key, EDNSDIG_SHA256) == expected);
    CHECK(dsOf("EXAMPLE.NET.", key, EDNSDIG_SHA256) == expected);

    // A trailing dot is optional and means the same name.
    CHECK(dsOf("example.net", key, EDNSDIG_SHA256) == expected);

    // A genuinely different name must not.
    CHECK(dsOf("example.com.", key, EDNSDIG_SHA256) != expected);
}

TEST_CASE("DNSKEY: RDATA round-trips, and the flag accessors read the published records") {
    const SDnskey ksk = makeKey(257, EDNSALG_ED25519,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");

    CHECK(ksk.isZoneKey());
    CHECK(ksk.isSecureEntryPoint());            // 257 == zone key + SEP, i.e. a KSK
    CHECK_FALSE(ksk.isRevoked());

    TArray<uint8_t> rdata;
    REQUIRE(ksk.toRdata(rdata));
    CHECK(rdata.size() == 4 + 32);
    CHECK(rdata[0] == 0x01);                    // flags, big-endian
    CHECK(rdata[1] == 0x01);
    CHECK(rdata[2] == 3);                       // protocol
    CHECK(rdata[3] == 15);                      // algorithm

    SDnskey parsed;
    REQUIRE(parsed.fromRdata(SReadOnlyByteSpan(rdata.begin(), rdata.size())));
    CHECK(parsed.flags == 257);
    CHECK(parsed.protocol == 3);
    CHECK(parsed.algorithm == EDNSALG_ED25519);
    CHECK(parsed.publicKey.size() == ksk.publicKey.size());
    CHECK(std::memcmp(parsed.publicKey.toPtr(), ksk.publicKey.toPtr(),
                      ksk.publicKey.size()) == 0);
    CHECK(tagOf(parsed) == 3613);

    SDnskey zsk = makeKey(256, EDNSALG_ED25519,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");
    CHECK(zsk.isZoneKey());
    CHECK_FALSE(zsk.isSecureEntryPoint());      // 256 == zone key only, i.e. a ZSK
}

TEST_CASE("DNSKEY: malformed RDATA is rejected") {
    SDnskey key;

    uint8_t tooShort[4] = { 0x01, 0x01, 0x03, 0x0F };
    CHECK_FALSE(key.fromRdata(SReadOnlyByteSpan(tooShort, 3)));

    // Four octets of header and no key at all is not a key.
    CHECK_FALSE(key.fromRdata(SReadOnlyByteSpan(tooShort, 4)));

    // RFC 4034 2.1.2 fixes the protocol field at 3; anything else is malformed.
    uint8_t badProtocol[5] = { 0x01, 0x01, 0x02, 0x0F, 0xAA };
    CHECK_FALSE(key.fromRdata(SReadOnlyByteSpan(badProtocol, 5)));

    uint8_t good[5] = { 0x01, 0x01, 0x03, 0x0F, 0xAA };
    CHECK(key.fromRdata(SReadOnlyByteSpan(good, 5)));

    CHECK_FALSE(key.fromRdata(SReadOnlyByteSpan(nullptr, 0)));
}

TEST_CASE("DS: RDATA round-trips, and matches() accepts only the key it was built from") {
    const SDnskey key = makeKey(257, EDNSALG_ECDSAP256SHA256,
        "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb"
        "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");

    SDsRecord ds;
    REQUIRE(SDsRecord::fromDnskey(CString("example.net."), key, EDNSDIG_SHA256, ds));
    CHECK(ds.keyTag == 55648);
    CHECK(ds.algorithm == EDNSALG_ECDSAP256SHA256);
    CHECK(ds.digestType == EDNSDIG_SHA256);
    CHECK(ds.digest.size() == 32);

    TArray<uint8_t> rdata;
    REQUIRE(ds.toRdata(rdata));
    CHECK(rdata.size() == 4 + 32);

    SDsRecord parsed;
    REQUIRE(parsed.fromRdata(SReadOnlyByteSpan(rdata.begin(), rdata.size())));
    CHECK(parsed.keyTag == ds.keyTag);
    CHECK(parsed.algorithm == ds.algorithm);
    CHECK(parsed.digestType == ds.digestType);

    CHECK(parsed.matches(CString("example.net."), key));
    CHECK_FALSE(parsed.matches(CString("example.com."), key));

    const SDnskey other = makeKey(257, EDNSALG_ED25519,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");
    CHECK_FALSE(parsed.matches(CString("example.net."), other));

    // A digest length that disagrees with its digest algorithm is a malformed record, not an
    // unknown one.
    TArray<uint8_t> truncated;
    REQUIRE(ds.toRdata(truncated));
    REQUIRE(truncated.resize(truncated.size() - 1));
    SDsRecord rejected;
    CHECK_FALSE(rejected.fromRdata(SReadOnlyByteSpan(truncated.begin(), truncated.size())));
}

TEST_CASE("DS: an unimplemented digest algorithm is reported rather than guessed") {
    const SDnskey key = makeKey(257, EDNSALG_ED25519,
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");

    SDsRecord ds;
    // GOST R 34.11-94 has no implementation here and is forbidden by RFC 8624 besides.
    CHECK_FALSE(SDsRecord::fromDnskey(CString("example.com."), key, EDNSDIG_GOST, ds));
    CHECK_FALSE(SDsRecord::fromDnskey(CString("example.com."), key, EDNSDIG_UNKNOWN, ds));

    // SHA-1 is deprecated but implemented, so it must still work -- a validator has to be able
    // to evaluate a record before deciding to reject it.
    CHECK(SDsRecord::fromDnskey(CString("example.com."), key, EDNSDIG_SHA1, ds));
    CHECK(ds.digest.size() == 20);
}

TEST_CASE("RRSIG: RDATA round-trips, and the signed prefix is the RDATA minus the signature") {
    SRrsig sig;
    sig.typeCovered = 1;                        // A
    sig.algorithm = EDNSALG_ECDSAP256SHA256;
    sig.labels = 3;
    sig.originalTtl = 3600;
    sig.expiration = 1284026679;                // 20100909100439
    sig.inception = 1281607479;                 // 20100812100439
    sig.keyTag = 55648;
    sig.signerName = CString("example.net.");
    sig.signature = fromBase64(
        "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA"
        "yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==");

    REQUIRE(sig.signature.size() == 64);        // r | s, 32 octets each

    TArray<uint8_t> rdata;
    REQUIRE(sig.toRdata(rdata));

    TArray<uint8_t> prefix;
    REQUIRE(sig.toSignedPrefix(prefix));

    // RFC 4034 3.1.8.1: the signature covers the RDATA with the signature field omitted, so the
    // prefix must be exactly the leading bytes of the RDATA.
    CHECK(prefix.size() == rdata.size() - sig.signature.size());
    CHECK(std::memcmp(prefix.begin(), rdata.begin(), prefix.size()) == 0);

    // 18 fixed octets, then "example.net." in wire format, which is 13: a length octet plus
    // 7 for "example", a length octet plus 3 for "net", and the root label. The length octets
    // are easy to leave out of that sum by hand -- this assertion did, at first.
    CHECK(prefix.size() == 18 + 13);
    CHECK(rdata[0] == 0x00);                    // type covered, big-endian
    CHECK(rdata[1] == 0x01);
    CHECK(rdata[2] == 13);                      // algorithm
    CHECK(rdata[3] == 3);                       // labels

    SRrsig parsed;
    REQUIRE(parsed.fromRdata(SReadOnlyByteSpan(rdata.begin(), rdata.size())));
    CHECK(parsed.typeCovered == sig.typeCovered);
    CHECK(parsed.algorithm == sig.algorithm);
    CHECK(parsed.labels == sig.labels);
    CHECK(parsed.originalTtl == sig.originalTtl);
    CHECK(parsed.expiration == sig.expiration);
    CHECK(parsed.inception == sig.inception);
    CHECK(parsed.keyTag == sig.keyTag);
    CHECK(std::string(parsed.signerName.toPtr()) == "example.net.");
    CHECK(parsed.signature.size() == sig.signature.size());
    CHECK(std::memcmp(parsed.signature.toPtr(), sig.signature.toPtr(),
                      sig.signature.size()) == 0);
}

TEST_CASE("RRSIG: malformed RDATA is rejected") {
    SRrsig sig;

    uint8_t header[19] = { 0 };
    header[18] = 0;                             // root signer name, then nothing

    // Eighteen fixed octets plus a root label leaves no signature.
    CHECK_FALSE(sig.fromRdata(SReadOnlyByteSpan(header, 19)));

    // Short of the eighteen fixed octets.
    CHECK_FALSE(sig.fromRdata(SReadOnlyByteSpan(header, 18)));
    CHECK_FALSE(sig.fromRdata(SReadOnlyByteSpan(header, 10)));

    // A label length that runs past the end of the RDATA.
    uint8_t runaway[20] = { 0 };
    runaway[18] = 40;
    CHECK_FALSE(sig.fromRdata(SReadOnlyByteSpan(runaway, 20)));

    // A compression pointer where a label length belongs. DNSSEC forbids these in signed names,
    // and the top two bits being set is what marks one.
    uint8_t pointer[21] = { 0 };
    pointer[18] = 0xC0;
    pointer[19] = 0x0C;
    CHECK_FALSE(sig.fromRdata(SReadOnlyByteSpan(pointer, 21)));

    // A signature is required.
    SRrsig unsigned_;
    unsigned_.signerName = CString("example.net.");
    TArray<uint8_t> rdata;
    CHECK_FALSE(unsigned_.toRdata(rdata));
}
