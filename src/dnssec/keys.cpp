#include <certpp/dnssec/keys.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/crypto/asym.hpp>
#include <certpp/utils/bignum.hpp>
#include <cstring>

namespace certpp {
namespace dnssec {

    namespace {

        /* Appends a block of bytes, growing once and copying in bulk. */
        bool appendBytes(TArray<uint8_t>& out, const uint8_t* data, size_t size) {
            if (size == 0) {
                return true;
            }

            const size_t at = out.size();
            if (!out.resize(at + size)) {
                return false;
            }

            std::memcpy(out.begin() + at, data, size);
            return true;
        }

        /* The width of one ECDSA coordinate, and of one signature half, for the two curves RFC
         * 6605 defines. Both are fixed by the curve, which is what lets `x | y` and `r | s` be
         * split without a length prefix. */
        bool ecdsaHalfBytes(EDnsAlgorithms which, size_t& out) {
            switch (which) {
                case EDNSALG_ECDSAP256SHA256: out = 32; return true;
                case EDNSALG_ECDSAP384SHA384: out = 48; return true;
                default:
                    return false;
            }
        }

        /* The key and signature widths of the two EdDSA algorithms (RFC 8080 3). Ed448's 57 is
         * not a typo for 56: Ed448 encodes a point in 57 octets. */
        bool eddsaKeyBytes(EDnsAlgorithms which, size_t& keyBytes, size_t& signatureBytes) {
            switch (which) {
                case EDNSALG_ED25519: keyBytes = 32; signatureBytes = 64;  return true;
                case EDNSALG_ED448:   keyBytes = 57; signatureBytes = 114; return true;
                default:
                    return false;
            }
        }

        /* Reads RFC 3110 2's exponent-length prefix: one octet, or a zero octet followed by two
         * octets when the exponent needs more than 255 bytes. */
        bool splitRsaKey(
            const SReadOnlyByteSpan& key, SReadOnlyByteSpan& exponent, SReadOnlyByteSpan& modulus
        ) {
            if (!key.data || key.size < 2) {
                return false;
            }

            size_t exponentBytes = 0;
            size_t offset = 0;

            if (key.data[0] != 0) {
                exponentBytes = key.data[0];
                offset = 1;
            }
            else {
                if (key.size < 3) {
                    return false;
                }

                exponentBytes = (size_t(key.data[1]) << 8) | key.data[2];
                offset = 3;

                // A three-octet form that encodes a length under 256 is not what RFC 3110 asks
                // for, and accepting it would mean one key having two encodings.
                if (exponentBytes < 256) {
                    return false;
                }
            }

            if (exponentBytes == 0 || key.size <= offset + exponentBytes) {
                return false;
            }

            exponent = SReadOnlyByteSpan(key.data + offset, exponentBytes);
            modulus = SReadOnlyByteSpan(
                key.data + offset + exponentBytes, key.size - offset - exponentBytes);

            return true;
        }

    }

    /* Maps a DNSSEC algorithm number to this library's algorithm enumerator. */
    bool CDnssecKeys::asymmetricOf(EDnsAlgorithms which, crypto::EAsymmetrics& out) {
        switch (which) {
            case EDNSALG_RSAMD5:
            case EDNSALG_RSASHA1:
            case EDNSALG_RSASHA1_NSEC3_SHA1:
            case EDNSALG_RSASHA256:
            case EDNSALG_RSASHA512:
                out = crypto::EASYM_RSA;
                return true;

            case EDNSALG_DSA:
            case EDNSALG_DSA_NSEC3_SHA1:
                out = crypto::EASYM_DSA;
                return true;

            case EDNSALG_ECDSAP256SHA256:
                out = crypto::EASYM_P256;
                return true;

            case EDNSALG_ECDSAP384SHA384:
                out = crypto::EASYM_P384;
                return true;

            case EDNSALG_ED25519:
                out = crypto::EASYM_ED25519;
                return true;

            case EDNSALG_ED448:
                out = crypto::EASYM_ED448;
                return true;

            // GOST R 34.10-2001 (algorithm 12) has no implementation here, and RFC 8624 forbids
            // it in any case. It is listed in EDnsAlgorithms so a record carrying it can be
            // named and rejected, rather than parsed as something else.
            default:
                return false;
        }
    }

    /* Maps a DNSSEC algorithm number to the hash it signs with. */
    bool CDnssecKeys::hasherOf(EDnsAlgorithms which, crypto::EHashers& out) {
        switch (which) {
            case EDNSALG_RSAMD5:
                out = crypto::EHASH_MD5;
                return true;

            case EDNSALG_DSA:
            case EDNSALG_DSA_NSEC3_SHA1:
            case EDNSALG_RSASHA1:
            case EDNSALG_RSASHA1_NSEC3_SHA1:
                out = crypto::EHASH_SHA1;
                return true;

            case EDNSALG_RSASHA256:
            case EDNSALG_ECDSAP256SHA256:
                out = crypto::EHASH_SHA256;
                return true;

            case EDNSALG_RSASHA512:
                out = crypto::EHASH_SHA512;
                return true;

            case EDNSALG_ECDSAP384SHA384:
                out = crypto::EHASH_SHA384;
                return true;

            // Ed25519 and Ed448 take the message itself and hash it internally as part of the
            // signature scheme, so there is no separate hash for a caller to apply first.
            // Reporting EHASH_UNKNOWN rather than failing is deliberate: the algorithm *is*
            // supported, it just has no external hash.
            case EDNSALG_ED25519:
            case EDNSALG_ED448:
                out = crypto::EHASH_UNKNOWN;
                return true;

            default:
                return false;
        }
    }

    /* Converts a DNSKEY record into a usable public key. */
    bool CDnssecKeys::toPublicKey(const SDnskey& key, crypto::IPublicKeyPtr& out) {
        crypto::EAsymmetrics which = crypto::EASYM_RSA;
        if (!asymmetricOf(key.algorithm, which)) {
            return false;
        }

        crypto::IAsymmetricPtr algorithm = crypto::IAsymmetric::builtIn(which);
        if (!algorithm) {
            return false;
        }

        const SReadOnlyByteSpan material(key.publicKey.toPtr(), key.publicKey.size());
        if (!material.data || material.size == 0) {
            return false;
        }

        size_t halfBytes = 0;
        size_t keyBytes = 0;
        size_t signatureBytes = 0;

        if (ecdsaHalfBytes(key.algorithm, halfBytes)) {
            // RFC 6605 2: "x | y", which is the SEC1 uncompressed point with its 0x04 prefix
            // stripped off. Rejecting any other length matters -- a 63-byte value accepted as a
            // P-256 point would be split at the wrong place and yield a key that verifies
            // nothing, with no error anywhere.
            if (material.size != halfBytes * 2) {
                return false;
            }

            TArray<uint8_t> sec1;
            if (!sec1.add(uint8_t(0x04)) || !appendBytes(sec1, material.data, material.size)) {
                return false;
            }

            out = algorithm->createPublicKey(
                SReadOnlyByteSpan(sec1.begin(), sec1.size()));
            return out != nullptr;
        }

        if (eddsaKeyBytes(key.algorithm, keyBytes, signatureBytes)) {
            if (material.size != keyBytes) {
                return false;
            }

            out = algorithm->createPublicKey(material);
            return out != nullptr;
        }

        if (which == crypto::EASYM_RSA) {
            SReadOnlyByteSpan exponent;
            SReadOnlyByteSpan modulus;
            if (!splitRsaKey(material, exponent, modulus)) {
                return false;
            }

            // Note the order: DNS writes the exponent first, this library's DER wants the
            // modulus first. Getting that backwards produces a key whose modulus is 3.
            const CBigNum n = CBigNum::fromBigEndian(modulus);
            const CBigNum e = CBigNum::fromBigEndian(exponent);

            if (n.isZero() || e.isZero()) {
                return false;
            }

            TArray<uint8_t> inner;
            if (!asn1::CDer::appendBigInteger(inner, n)
                || !asn1::CDer::appendBigInteger(inner, e)) {
                return false;
            }

            TArray<uint8_t> der;
            if (!asn1::CDer::appendSequence(
                    der, SReadOnlyByteSpan(inner.begin(), inner.size()))) {
                return false;
            }

            out = algorithm->createPublicKey(SReadOnlyByteSpan(der.begin(), der.size()));
            return out != nullptr;
        }

        // DSA (algorithms 3 and 6) has a DNS key encoding of its own (RFC 2536) that this does
        // not implement. It is reported unsupported rather than guessed at.
        return false;
    }

    /* Converts a public key into a DNSKEY record. */
    bool CDnssecKeys::fromPublicKey(
        const crypto::IPublicKeyPtr& publicKey, EDnsAlgorithms algorithm,
        uint16_t flags, SDnskey& out
    ) {
        crypto::EAsymmetrics which = crypto::EASYM_RSA;
        if (!publicKey || !asymmetricOf(algorithm, which)) {
            return false;
        }

        COctet native;
        if (publicKey->serialize(native) != ERET_OK || native.size() == 0) {
            return false;
        }

        const SReadOnlyByteSpan material = native.toSpan();

        size_t halfBytes = 0;
        size_t keyBytes = 0;
        size_t signatureBytes = 0;

        if (ecdsaHalfBytes(algorithm, halfBytes)) {
            // The SEC1 uncompressed point, less its 0x04 prefix. A compressed point (0x02/0x03)
            // cannot be converted without decompressing it, and is rejected rather than
            // truncated -- which would otherwise produce a DNSKEY holding half a point.
            if (material.size != halfBytes * 2 + 1 || material.data[0] != 0x04) {
                return false;
            }

            if (!out.publicKey.resize(halfBytes * 2)) {
                return false;
            }

            std::memcpy(out.publicKey.toPtr(), material.data + 1, halfBytes * 2);
        }
        else if (eddsaKeyBytes(algorithm, keyBytes, signatureBytes)) {
            if (material.size != keyBytes) {
                return false;
            }

            if (!out.publicKey.resize(keyBytes)) {
                return false;
            }

            std::memcpy(out.publicKey.toPtr(), material.data, keyBytes);
        }
        else if (which == crypto::EASYM_RSA) {
            TReadOnlySpan<uint8_t> content;
            if (!asn1::CDer::readOuterSequence(material, content)) {
                return false;
            }

            CBigNum n, e;
            if (!asn1::CDer::readBigInteger(content, n)
                || !asn1::CDer::readBigInteger(content, e) || !content.empty()) {
                return false;
            }

            TArray<uint8_t> exponent;
            TArray<uint8_t> modulus;
            e.toBigEndian(exponent);
            n.toBigEndian(modulus);

            if (exponent.size() == 0 || modulus.size() == 0) {
                return false;
            }

            TArray<uint8_t> encoded;

            // RFC 3110 2: a one-octet length for an exponent of 1..255 bytes, otherwise a zero
            // octet and a two-octet length.
            if (exponent.size() < 256) {
                if (!encoded.add(uint8_t(exponent.size()))) {
                    return false;
                }
            }
            else {
                if (exponent.size() > 0xFFFF) {
                    return false;
                }

                if (!encoded.add(uint8_t(0))
                    || !encoded.add(uint8_t(exponent.size() >> 8))
                    || !encoded.add(uint8_t(exponent.size()))) {
                    return false;
                }
            }

            if (!appendBytes(encoded, exponent.begin(), exponent.size())
                || !appendBytes(encoded, modulus.begin(), modulus.size())) {
                return false;
            }

            if (!out.publicKey.resize(encoded.size())) {
                return false;
            }

            std::memcpy(out.publicKey.toPtr(), encoded.begin(), encoded.size());
        }
        else {
            return false;
        }

        out.flags = flags;
        out.protocol = SDnskey::PROTOCOL_DNSSEC;
        out.algorithm = algorithm;

        return true;
    }

    /* Converts an RRSIG signature into this library's encoding. */
    bool CDnssecKeys::signatureToNative(
        EDnsAlgorithms algorithm, const SReadOnlyByteSpan& signature, TArray<uint8_t>& out
    ) {
        out.clear();

        if (!signature.data || signature.size == 0) {
            return false;
        }

        size_t halfBytes = 0;
        if (ecdsaHalfBytes(algorithm, halfBytes)) {
            if (signature.size != halfBytes * 2) {
                return false;
            }

            const CBigNum r = CBigNum::fromBigEndian(
                SReadOnlyByteSpan(signature.data, halfBytes));
            const CBigNum s = CBigNum::fromBigEndian(
                SReadOnlyByteSpan(signature.data + halfBytes, halfBytes));

            TArray<uint8_t> inner;
            if (!asn1::CDer::appendBigInteger(inner, r)
                || !asn1::CDer::appendBigInteger(inner, s)) {
                out.clear();
                return false;
            }

            if (!asn1::CDer::appendSequence(
                    out, SReadOnlyByteSpan(inner.begin(), inner.size()))) {
                out.clear();
                return false;
            }

            return true;
        }

        size_t keyBytes = 0;
        size_t signatureBytes = 0;
        if (eddsaKeyBytes(algorithm, keyBytes, signatureBytes)) {
            if (signature.size != signatureBytes) {
                return false;
            }

            return appendBytes(out, signature.data, signature.size);
        }

        crypto::EAsymmetrics which = crypto::EASYM_RSA;
        if (asymmetricOf(algorithm, which) && which == crypto::EASYM_RSA) {
            // An RSA signature is one integer the width of the modulus, and DNS writes it
            // exactly as this library does.
            return appendBytes(out, signature.data, signature.size);
        }

        return false;
    }

    /* Converts a signature this library produced into RRSIG's encoding. */
    bool CDnssecKeys::signatureFromNative(
        EDnsAlgorithms algorithm, const SReadOnlyByteSpan& signature, TArray<uint8_t>& out
    ) {
        out.clear();

        if (!signature.data || signature.size == 0) {
            return false;
        }

        size_t halfBytes = 0;
        if (ecdsaHalfBytes(algorithm, halfBytes)) {
            TReadOnlySpan<uint8_t> content;
            if (!asn1::CDer::readOuterSequence(signature, content)) {
                return false;
            }

            CBigNum r, s;
            if (!asn1::CDer::readBigInteger(content, r)
                || !asn1::CDer::readBigInteger(content, s) || !content.empty()) {
                return false;
            }

            if (!out.resize(halfBytes * 2)) {
                return false;
            }

            // Fixed width, zero-padded on the left. This is the step that cannot be skipped: a
            // DER INTEGER carries no leading zero octets, so an r below 2^(8*(halfBytes-1))
            // emits short and, written without padding, shifts s left by however many octets r
            // was missing. RFC 6605 2 requires each to be exactly halfBytes long.
            if (!r.toBigEndian(SByteSpan(out.begin(), halfBytes))
                || !s.toBigEndian(SByteSpan(out.begin() + halfBytes, halfBytes))) {
                out.clear();
                return false;
            }

            return true;
        }

        size_t keyBytes = 0;
        size_t signatureBytes = 0;
        if (eddsaKeyBytes(algorithm, keyBytes, signatureBytes)) {
            if (signature.size != signatureBytes) {
                return false;
            }

            return appendBytes(out, signature.data, signature.size);
        }

        crypto::EAsymmetrics which = crypto::EASYM_RSA;
        if (asymmetricOf(algorithm, which) && which == crypto::EASYM_RSA) {
            return appendBytes(out, signature.data, signature.size);
        }

        return false;
    }

}
}
