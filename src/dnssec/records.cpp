#include <certpp/dnssec/records.hpp>
#include <certpp/dnssec/name.hpp>
#include <certpp/crypto/hasher.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

namespace certpp {
namespace dnssec {

    namespace {

        /* DNS puts its integers in network byte order, so these are big-endian throughout --
         * unlike Poly1305 and ChaCha20 next door, which are little-endian. */
        inline bool appendU16(TArray<uint8_t>& out, uint16_t value) {
            return out.add(uint8_t(value >> 8)) && out.add(uint8_t(value));
        }

        inline bool appendU32(TArray<uint8_t>& out, uint32_t value) {
            return out.add(uint8_t(value >> 24)) && out.add(uint8_t(value >> 16))
                && out.add(uint8_t(value >> 8)) && out.add(uint8_t(value));
        }

        inline uint16_t readU16(const uint8_t* p) {
            return uint16_t((uint16_t(p[0]) << 8) | p[1]);
        }

        inline uint32_t readU32(const uint8_t* p) {
            return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
                 | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
        }

        /* Appends a block of bytes, growing once and copying in bulk rather than adding one
         * element at a time. */
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

        /* Maps a DS digest number to this library's hasher. GOST R 34.11-94 (digest 3) has no
         * implementation here and is in any case forbidden by RFC 8624, so it is reported as
         * unsupported rather than silently treated as something else. */
        bool digestHasher(EDnsDigests which, crypto::IHasherPtr& out) {
            crypto::EHashers hasher = crypto::EHASH_UNKNOWN;

            switch (which) {
                case EDNSDIG_SHA1:   hasher = crypto::EHASH_SHA1;   break;
                case EDNSDIG_SHA256: hasher = crypto::EHASH_SHA256; break;
                case EDNSDIG_SHA384: hasher = crypto::EHASH_SHA384; break;
                default:
                    return false;
            }

            return crypto::IHasher::create(hasher, out) == ERET_OK && out;
        }

    }

    /* Constructs an empty DNSKEY record. */
    SDnskey::SDnskey()
        : flags(0), protocol(PROTOCOL_DNSSEC), algorithm(EDNSALG_UNKNOWN) {
    }

    /* Parses DNSKEY RDATA. */
    bool SDnskey::fromRdata(const SReadOnlyByteSpan& rdata) {
        if (!rdata.data || rdata.size < 4) {
            return false;
        }

        const uint8_t protocolOctet = rdata.data[2];

        // RFC 4034 2.1.2: the protocol field MUST be 3, and a DNSKEY with any other value MUST
        // be treated as malformed. Rejecting it here rather than passing it through is what
        // keeps a record that merely looks like a DNSKEY from being used as one.
        if (protocolOctet != PROTOCOL_DNSSEC) {
            return false;
        }

        if (rdata.size == 4) {
            return false;                               // a DNSKEY with no key is not a key
        }

        if (!publicKey.resize(rdata.size - 4)) {
            return false;
        }

        std::memcpy(publicKey.toPtr(), rdata.data + 4, rdata.size - 4);

        flags = readU16(rdata.data);
        protocol = protocolOctet;
        algorithm = EDnsAlgorithms(rdata.data[3]);

        return true;
    }

    /* Serialises a DNSKEY record to RDATA. */
    bool SDnskey::toRdata(TArray<uint8_t>& out) const {
        out.clear();

        if (publicKey.size() == 0) {
            return false;
        }

        if (!appendU16(out, flags) || !out.add(protocol) || !out.add(uint8_t(algorithm))) {
            out.clear();
            return false;
        }

        if (!appendBytes(out, publicKey.toPtr(), publicKey.size())) {
            out.clear();
            return false;
        }

        return true;
    }

    /* Computes a DNSKEY's key tag. */
    bool SDnskey::keyTag(uint16_t& out) const {
        TArray<uint8_t> rdata;
        if (!toRdata(rdata)) {
            return false;
        }

        const uint8_t* data = rdata.begin();
        const size_t size = rdata.size();

        // RFC 4034 Appendix B.1 special-cases algorithm 1 to "the most significant 16 bits of
        // the least significant 24 bits in the public key modulus". Those are bits 8..23, i.e.
        // the third- and second-to-last octets, which is what this computes -- and since the
        // modulus is the last field of an RSA DNSKEY, the last octet of the modulus is the last
        // octet of the RDATA, so indexing from the end of the RDATA is the same thing.
        //
        // Appendix B.1 then glosses that as "the 4th to last and 3rd to last octets", which
        // disagrees with its own normative clause by one: those octets are bits 16..31, which
        // are not inside the least significant 24 bits at all. The arithmetic definition is the
        // one followed here; the parenthetical is simply wrong, and this comment exists so that
        // a later reader checking the gloss does not "correct" this into a bug.
        //
        // Unverified against any published vector, because there is none for algorithm 1 -- it
        // is forbidden by RFC 8624. It is implemented rather than skipped because a resolver
        // still has to compute the tag of a record it is about to reject.
        if (algorithm == EDNSALG_RSAMD5) {
            if (size < 7) {
                return false;
            }

            out = uint16_t((uint16_t(data[size - 3]) << 8) | data[size - 2]);
            return true;
        }

        // Appendix B otherwise: sum the RDATA as big-endian 16-bit words -- which is what
        // weighting the even offsets by 256 amounts to -- then fold the carry back in.
        uint32_t total = 0;
        for (size_t i = 0; i < size; ++i) {
            total += (i & 1) ? uint32_t(data[i]) : (uint32_t(data[i]) << 8);
        }

        total += (total >> 16) & 0xFFFFu;
        out = uint16_t(total & 0xFFFFu);

        return true;
    }

    /* Constructs an empty DS record. */
    SDsRecord::SDsRecord()
        : keyTag(0), algorithm(EDNSALG_UNKNOWN), digestType(EDNSDIG_UNKNOWN) {
    }

    /* Parses DS RDATA. */
    bool SDsRecord::fromRdata(const SReadOnlyByteSpan& rdata) {
        if (!rdata.data || rdata.size <= 4) {
            return false;
        }

        const EDnsDigests type = EDnsDigests(rdata.data[3]);

        // The digest length is fixed by the digest algorithm, so a length that disagrees with it
        // is a malformed record rather than an unknown one. Checking it here means a caller can
        // trust digest.size() without re-deriving what it should have been.
        crypto::IHasherPtr hasher;
        if (digestHasher(type, hasher) && rdata.size - 4 != hasher->byteWidth()) {
            return false;
        }

        if (!digest.resize(rdata.size - 4)) {
            return false;
        }

        std::memcpy(digest.toPtr(), rdata.data + 4, rdata.size - 4);

        keyTag = readU16(rdata.data);
        algorithm = EDnsAlgorithms(rdata.data[2]);
        digestType = type;

        return true;
    }

    /* Serialises a DS record to RDATA. */
    bool SDsRecord::toRdata(TArray<uint8_t>& out) const {
        out.clear();

        if (digest.size() == 0) {
            return false;
        }

        if (!appendU16(out, keyTag) || !out.add(uint8_t(algorithm))
            || !out.add(uint8_t(digestType))) {
            out.clear();
            return false;
        }

        if (!appendBytes(out, digest.toPtr(), digest.size())) {
            out.clear();
            return false;
        }

        return true;
    }

    /* Builds the DS record for a DNSKEY. */
    bool SDsRecord::fromDnskey(
        const CString& owner, const SDnskey& key, EDnsDigests digestType, SDsRecord& out
    ) {
        TArray<uint8_t> ownerWire;
        if (!CDnsName::toWire(owner, ownerWire)) {
            return false;
        }

        TArray<uint8_t> rdata;
        if (!key.toRdata(rdata)) {
            return false;
        }

        uint16_t tag = 0;
        if (!key.keyTag(tag)) {
            return false;
        }

        crypto::IHasherPtr hasher;
        if (!digestHasher(digestType, hasher)) {
            return false;
        }

        hasher->reset();
        if (hasher->push(SReadOnlyByteSpan(ownerWire.begin(), ownerWire.size()))
                != ownerWire.size()) {
            return false;
        }
        if (hasher->push(SReadOnlyByteSpan(rdata.begin(), rdata.size())) != rdata.size()) {
            return false;
        }

        if (!out.digest.resize(hasher->byteWidth())) {
            return false;
        }

        if (!hasher->finish(SByteSpan(out.digest.toPtr(), out.digest.size()))) {
            return false;
        }

        out.keyTag = tag;
        out.algorithm = key.algorithm;
        out.digestType = digestType;

        return true;
    }

    /* Reports whether this DS record vouches for a given DNSKEY. */
    bool SDsRecord::matches(const CString& owner, const SDnskey& key) const {
        SDsRecord recomputed;
        if (!fromDnskey(owner, key, digestType, recomputed)) {
            return false;
        }

        if (recomputed.keyTag != keyTag || recomputed.algorithm != algorithm) {
            return false;
        }

        if (recomputed.digest.size() != digest.size()) {
            return false;
        }

        // Compared in constant time. A DS digest is public, so this is not guarding a secret;
        // it is here because a byte-at-a-time comparison in a validator is the kind of thing
        // that gets reused somewhere it does matter.
        return CSecure::equals(
            SReadOnlyByteSpan(recomputed.digest.toPtr(), recomputed.digest.size()),
            SReadOnlyByteSpan(digest.toPtr(), digest.size())
        );
    }

    /* Constructs an empty RRSIG record. */
    SRrsig::SRrsig()
        : typeCovered(0), algorithm(EDNSALG_UNKNOWN), labels(0), originalTtl(0),
          expiration(0), inception(0), keyTag(0) {
    }

    /* Parses RRSIG RDATA. */
    bool SRrsig::fromRdata(const SReadOnlyByteSpan& rdata) {
        // Type covered (2), algorithm (1), labels (1), original TTL (4), expiration (4),
        // inception (4), key tag (2) -- eighteen octets before the signer's name.
        if (!rdata.data || rdata.size < 19) {
            return false;
        }

        CString name;
        size_t nameBytes = 0;
        if (!CDnsName::fromWirePrefix(
                SReadOnlyByteSpan(rdata.data + 18, rdata.size - 18), name, nameBytes)) {
            return false;
        }

        const size_t signatureAt = 18 + nameBytes;
        if (signatureAt >= rdata.size) {
            return false;                               // an RRSIG with no signature
        }

        if (!signature.resize(rdata.size - signatureAt)) {
            return false;
        }

        std::memcpy(signature.toPtr(), rdata.data + signatureAt, rdata.size - signatureAt);

        typeCovered = readU16(rdata.data);
        algorithm = EDnsAlgorithms(rdata.data[2]);
        labels = rdata.data[3];
        originalTtl = readU32(rdata.data + 4);
        expiration = readU32(rdata.data + 8);
        inception = readU32(rdata.data + 12);
        keyTag = readU16(rdata.data + 16);
        signerName = name;

        return true;
    }

    /* Serialises everything an RRSIG's signature covers from the record itself. */
    bool SRrsig::toSignedPrefix(TArray<uint8_t>& out) const {
        out.clear();

        TArray<uint8_t> nameWire;
        if (!CDnsName::toWire(signerName, nameWire)) {
            return false;
        }

        const bool ok = appendU16(out, typeCovered)
            && out.add(uint8_t(algorithm))
            && out.add(labels)
            && appendU32(out, originalTtl)
            && appendU32(out, expiration)
            && appendU32(out, inception)
            && appendU16(out, keyTag)
            && appendBytes(out, nameWire.begin(), nameWire.size());

        if (!ok) {
            out.clear();
            return false;
        }

        return true;
    }

    /* Serialises an RRSIG record to RDATA. */
    bool SRrsig::toRdata(TArray<uint8_t>& out) const {
        if (signature.size() == 0) {
            out.clear();
            return false;
        }

        // The RDATA is exactly the signed prefix with the signature appended, which is the whole
        // reason RFC 4034 3.1.8.1 can describe the signed data as "RRSIG_RDATA" minus one field.
        if (!toSignedPrefix(out)) {
            return false;
        }

        if (!appendBytes(out, signature.toPtr(), signature.size())) {
            out.clear();
            return false;
        }

        return true;
    }

} // namespace dnssec
} // namespace certpp
