#include <certpp.hpp>
#include <cstring>

using namespace certpp;
using namespace certpp::dnssec;

// Each example is one function, preceded by a `// === <TypeName> ===` marker. The function body
// is what gets published as that type's example, dedented, so write it as the code a caller
// would write -- not as a test. See the brief for the rules.

// === CDnsName ===
// Encodes a presentation-format name into the canonical wire form everything DNSSEC hashes over,
// and counts its labels. toWire() always folds ASCII uppercase to lowercase and always writes the
// root label, so "Example.NET" and "example.net." produce identical bytes; a name that reaches a
// DS digest or an RRSIG prefix unfolded yields a digest that disagrees with every published one.
void exampleCDnsName(const CString& owner) {
    TArray<uint8_t> wire;
    if (!CDnsName::toWire(owner, wire)) {
        return;                     // an empty label, a label over 63 bytes, or a name over 255
    }

    const SReadOnlyByteSpan canonical(wire.begin(), wire.size());

    // Always true of toWire() output; worth asserting on a name that arrived from the wire,
    // where fromWire() hands back whatever case the sender used.
    if (!CDnsName::isCanonical(canonical)) {
        return;
    }

    size_t labels = 0;
    if (!CDnsName::countLabels(canonical, labels)) {
        return;
    }

    // labels excludes the root, which is the value RRSIG's Labels field carries: two for
    // "example.net.", and the caller subtracts one more for a wildcard owner.
    SRrsig sig;
    sig.labels = uint8_t(labels);
}

// === SDnskey ===
// Parses DNSKEY RDATA and derives the key tag an RRSIG refers to it by. The key tag is a checksum
// over the whole RDATA rather than a stored field, so it is computed on demand and can never
// disagree with the key it names; the public key stays in its DNS encoding until CDnssecKeys
// converts it.
void exampleSDnskey(const SReadOnlyByteSpan& rdata) {
    SDnskey key;
    if (!key.fromRdata(rdata)) {
        return;                     // too short, or a protocol field that is not 3
    }

    if (!key.isZoneKey() || key.isRevoked()) {
        return;                     // not a key that signs zone data (RFC 4034, RFC 5011)
    }

    uint16_t tag = 0;
    if (!key.keyTag(tag)) {
        return;
    }

    // The flags field is 16 bits big-endian. 257 -- a zone key that is also a secure entry
    // point, i.e. the conventional KSK -- is 0x0101 and reads the same either way round, so it
    // is 256 that catches a byte-swapped field.
    const bool keySigningKey = key.isSecureEntryPoint();

    TArray<uint8_t> reencoded;
    if (!key.toRdata(reencoded)) {
        return;
    }
}

// === SDsRecord ===
// Checks a DS record published by the parent zone against the DNSKEY it should vouch for, then
// builds the DS the child zone would submit. matches() recomputes the digest and compares it in
// constant time, so never pull .digest out and memcmp it; the owner name has to be passed in
// because the digest covers the canonical owner name followed by the DNSKEY RDATA, and the RDATA
// alone does not carry it.
bool exampleSDsRecord(const CString& owner, const SDnskey& key, const SReadOnlyByteSpan& dsRdata) {
    SDsRecord published;
    if (!published.fromRdata(dsRdata)) {
        return false;               // too short, or a digest length its digest type disallows
    }

    if (!published.matches(owner, key)) {
        return false;               // key tag, algorithm, digest type or digest disagrees
    }

    SDsRecord mine;
    if (!SDsRecord::fromDnskey(owner, key, EDNSDIG_SHA256, mine)) {
        return false;
    }

    TArray<uint8_t> rdata;
    if (!mine.toRdata(rdata)) {
        return false;
    }

    return true;                    // rdata holds the DS RDATA to hand to the parent zone
}

// === SRrsig ===
// Parses RRSIG RDATA, checks its validity window, and assembles the data the signature covers.
// toSignedPrefix() writes the eighteen fixed octets followed by the signer's name in canonical
// wire form -- the RDATA with the signature field omitted -- and the canonical RRset, which this
// library does not model, is appended to it by the caller.
void exampleSRrsig(const SReadOnlyByteSpan& rdata, const SReadOnlyByteSpan& canonicalRrset,
    uint32_t nowUnixSeconds) {
    SRrsig sig;
    if (!sig.fromRdata(rdata)) {
        return;                     // too short, or a malformed signer's name
    }

    if (nowUnixSeconds < sig.inception || nowUnixSeconds > sig.expiration) {
        return;                     // outside the signature's validity window
    }

    TArray<uint8_t> signedData;
    if (!sig.toSignedPrefix(signedData)) {
        return;
    }

    const size_t prefixBytes = signedData.size();
    if (!signedData.resize(prefixBytes + canonicalRrset.size)) {
        return;
    }

    std::memcpy(signedData.begin() + prefixBytes, canonicalRrset.data, canonicalRrset.size);

    // signedData is now what the hash runs over. sig.signature is still in RRSIG's own
    // encoding, so it goes through CDnssecKeys::signatureToNative() before verify().
}

// === CDnssecKeys ===
// Verifies an RRSIG against the DNSKEY that made it. DNSSEC reuses none of X.509's encodings --
// a DNSKEY's key material is not a SubjectPublicKeyInfo and an ECDSA RRSIG signature is bare
// `r | s` rather than a DER SEQUENCE -- so both have to come through these conversions; handing
// either straight to createPublicKey() or verify() is the bug this class exists to prevent.
bool exampleCDnssecKeys(const SDnskey& key, const SRrsig& sig, const SReadOnlyByteSpan& digest) {
    crypto::EAsymmetrics asymmetric = crypto::EASYM_UNKNOWN;
    crypto::IPublicKeyPtr publicKey;
    if (!CDnssecKeys::asymmetricOf(sig.algorithm, asymmetric)
        || !CDnssecKeys::toPublicKey(key, publicKey)) {
        return false;               // no implementation for that number, or malformed material
    }

    TArray<uint8_t> signature;
    if (!CDnssecKeys::signatureToNative(sig.algorithm,
            SReadOnlyByteSpan(sig.signature.toPtr(), sig.signature.size()), signature)) {
        return false;               // an ECDSA signature the wrong length for its curve
    }

    crypto::IAsymmetricPtr algorithm = crypto::IAsymmetric::builtIn(asymmetric);
    crypto::IAsymmetricContextPtr context = algorithm ? algorithm->createContext() : nullptr;
    if (!context) {
        return false;
    }

    // Public half only: a verify that somehow reached for a private key fails here rather than
    // passing for the wrong reason.
    context->keyPair(publicKey, nullptr);

    return context->verify(
        digest, SReadOnlyByteSpan(signature.begin(), signature.size())) == ERET_OK;
}

// === EDnsAlgorithms ===
// The algorithm number selects the hash too -- RFC 5702, 6605 and 8080 bind one to the other
// instead of leaving it to the signer -- so hasherOf() is how a verifier decides what to hash
// with. It reports EHASH_UNKNOWN with a true return for Ed25519 and Ed448, which hash internally
// and take the signed data whole; treating that as a failure would reject two supported
// algorithms.
void exampleEDnsAlgorithms(EDnsAlgorithms algorithm, const SReadOnlyByteSpan& signedData) {
    crypto::EHashers which = crypto::EHASH_UNKNOWN;
    if (!CDnssecKeys::hasherOf(algorithm, which)) {
        return;                     // e.g. EDNSALG_ECC_GOST, named so it can be rejected
    }

    if (which == crypto::EHASH_UNKNOWN) {
        return;                     // Ed25519/Ed448: pass signedData to verify() unhashed
    }

    crypto::IHasherPtr hasher;
    if (crypto::IHasher::create(which, hasher) != ERET_OK) {
        return;
    }

    if (hasher->push(signedData) != signedData.size) {
        return;
    }

    // byteWidth() is the digest length this algorithm number implies: 32 for
    // EDNSALG_ECDSAP256SHA256, 48 for EDNSALG_ECDSAP384SHA384, 64 for EDNSALG_RSASHA512.
    uint8_t buffer[64];
    const SByteSpan digest(buffer, hasher->byteWidth());
    if (!hasher->finish(digest)) {
        return;
    }
}

// === EDnsDigests ===
// Picks the digest a DS record is built with. The enumerator fixes the digest length, so a parent
// zone that wants both SHA-256 and SHA-384 publishes two DS records over the one DNSKEY;
// EDNSDIG_GOST is listed only so a DS carrying it can be named, and fromDnskey() reports failure
// for it rather than producing a digest of the wrong kind.
void exampleEDnsDigests(const CString& owner, const SDnskey& key) {
    SDsRecord sha256;
    if (!SDsRecord::fromDnskey(owner, key, EDNSDIG_SHA256, sha256)) {
        return;
    }

    SDsRecord sha384;
    if (!SDsRecord::fromDnskey(owner, key, EDNSDIG_SHA384, sha384)) {
        return;
    }

    // 32 and 48 bytes respectively, and fromRdata() rejects any other length for these two.
    const size_t shortDigest = sha256.digest.size();
    const size_t longDigest = sha384.digest.size();

    SDsRecord gost;
    if (!SDsRecord::fromDnskey(owner, key, EDNSDIG_GOST, gost)) {
        // The expected outcome: there is no GOST R 34.11-94 hash here, and RFC 8624 forbids the
        // algorithm anyway, so nothing is produced instead of something unverifiable.
    }
}
