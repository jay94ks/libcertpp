#include <certpp/x509/chain/pfx.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/hmac.hpp>
#include <certpp/crypto/pbkdf2.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/crypto/sym.hpp>
#include <certpp/io/array.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>
#include <utility>

namespace certpp {
namespace x509 {

    using asn1::CDecoder;
    using asn1::CDer;
    using asn1::CEncoder;
    using asn1::CReader;
    using asn1::CTag;
    using asn1::EAENC_DER;
    using asn1::EATAG_CONTEXT_SPECIFIC;

    namespace {

        // ------------------------------------------------------------------ OIDs
        //
        // Written out as text and encoded through CEncoder rather than kept as pre-encoded byte
        // arrays, so that a typo is a mismatch rather than a silently different OID. The
        // PKCS#12 arc (1.2.840.113549.1.12.10.1.x) numbers its bags 1..6 consecutively, so an
        // off-by-one here reads a shrouded key bag as a plain one.

        constexpr const char* OID_PKCS7_DATA           = "1.2.840.113549.1.7.1";
        constexpr const char* OID_PKCS7_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";

        constexpr const char* OID_KEY_BAG              = "1.2.840.113549.1.12.10.1.1";
        constexpr const char* OID_SHROUDED_KEY_BAG     = "1.2.840.113549.1.12.10.1.2";
        constexpr const char* OID_CERT_BAG             = "1.2.840.113549.1.12.10.1.3";
        constexpr const char* OID_X509_CERTIFICATE     = "1.2.840.113549.1.9.22.1";

        constexpr const char* OID_FRIENDLY_NAME        = "1.2.840.113549.1.9.20";
        constexpr const char* OID_LOCAL_KEY_ID         = "1.2.840.113549.1.9.21";

        constexpr const char* OID_PBES2                = "1.2.840.113549.1.5.13";
        constexpr const char* OID_PBKDF2               = "1.2.840.113549.1.5.12";
        constexpr const char* OID_AES256_CBC           = "2.16.840.1.101.3.4.1.42";
        constexpr const char* OID_AES128_CBC           = "2.16.840.1.101.3.4.1.2";
        constexpr const char* OID_AES192_CBC           = "2.16.840.1.101.3.4.1.22";

        constexpr const char* OID_HMAC_SHA1            = "1.2.840.113549.2.7";
        constexpr const char* OID_HMAC_SHA224          = "1.2.840.113549.2.8";
        constexpr const char* OID_HMAC_SHA256          = "1.2.840.113549.2.9";
        constexpr const char* OID_HMAC_SHA384          = "1.2.840.113549.2.10";
        constexpr const char* OID_HMAC_SHA512          = "1.2.840.113549.2.11";

        constexpr const char* OID_SHA1                 = "1.3.14.3.2.26";
        constexpr const char* OID_SHA224               = "2.16.840.1.101.3.4.2.4";
        constexpr const char* OID_SHA256               = "2.16.840.1.101.3.4.2.1";
        constexpr const char* OID_SHA384               = "2.16.840.1.101.3.4.2.2";
        constexpr const char* OID_SHA512               = "2.16.840.1.101.3.4.2.3";

        /** The hash `save()` MACs with, and the one its PBKDF2 uses as a PRF. */
        constexpr crypto::EHashers MAC_HASH = crypto::EHASH_SHA256;

        /** AES-256's key and block lengths, in bytes. */
        constexpr size_t AES256_KEY_BYTES = 32;
        constexpr size_t CBC_IV_BYTES = 16;

        /** The largest digest any hash here produces, for stack buffers. */
        constexpr size_t MAX_DIGEST_BYTES = 64;

        /* Encodes a dotted-decimal OID's content octets. Infallible for the constants above, so
         * the callers treat a failure as "this build is broken" rather than as a data error. */
        bool encodeOid(const char* text, CBuffer& out) {
            const CString str(text);
            const size_t needed = CEncoder::encodedOidStringSize(str);
            if (!needed || !out.resize(needed)) {
                return false;
            }

            size_t written = 0;
            if (!CEncoder::encodeOidString(out.toSpan(), str, written) || written != needed) {
                return false;
            }

            return true;
        }

        /* Appends a complete OBJECT IDENTIFIER TLV for a dotted-decimal OID. */
        bool appendOid(CBuffer& out, const char* text) {
            CBuffer content;
            return encodeOid(text, content) && CDer::appendTlv(out, CTag::OBJ_ID, content.toSpan());
        }

        /* Appends an AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }.
         * An empty `params` means the field is absent, which is a different encoding from an
         * explicit NULL -- PBKDF2's prf wants the NULL, RFC 8410's key algorithms want neither. */
        bool appendAlgoId(CBuffer& out, const char* oid, SReadOnlyByteSpan params) {
            CBuffer content;
            if (!appendOid(content, oid)) {
                return false;
            }
            if (params.size != 0 && !CDer::appendRaw(content, params)) {
                return false;
            }

            return CDer::appendSequence(out, content.toSpan());
        }

        /* Appends an INTEGER TLV for a value that fits in 32 bits, which every length and
         * iteration count in this format does. */
        bool appendInteger(CBuffer& out, uint32_t value) {
            uint8_t buf[8];
            size_t written = 0;
            if (!CEncoder::encodeInteger(TSpan<uint8_t>(buf, sizeof(buf)), int64_t(value), written)) {
                return false;
            }

            return CDer::appendTlv(out, CTag::INTEGER, SReadOnlyByteSpan(buf, written));
        }

        // -------------------------------------------------- the password, twice over
        //
        // The two KDFs in a PFX want the password in two different encodings, and this is the
        // detail that most often makes a container that only its author can read. See
        // CPfxFormat's own doc comment.

        /* Converts the password span, read as UTF-8, to the NUL-terminated big-endian UTF-16 form
         * RFC 7292 B.1's KDF takes -- "a BMPString with a 2-byte NUL terminator". False if the
         * span is not valid UTF-8, since a PKCS#12 password is by definition text. */
        bool toBmpPassword(const SReadOnlyByteSpan& password, CBuffer& out) {
            TArray<uint8_t> units;

            const uint8_t* p = password.data;
            const uint8_t* end = p + password.size;

            while (p < end) {
                uint32_t cp = 0;
                size_t extra = 0;

                if (*p < 0x80) {
                    cp = *p; extra = 0;
                } else if ((*p & 0xE0) == 0xC0) {
                    cp = *p & 0x1Fu; extra = 1;
                } else if ((*p & 0xF0) == 0xE0) {
                    cp = *p & 0x0Fu; extra = 2;
                } else if ((*p & 0xF8) == 0xF0) {
                    cp = *p & 0x07u; extra = 3;
                } else {
                    return false; // a continuation byte or an invalid lead byte.
                }

                if (size_t(end - p) <= extra) {
                    return false; // truncated sequence.
                }

                ++p;
                for (size_t i = 0; i < extra; ++i, ++p) {
                    if ((*p & 0xC0) != 0x80) {
                        return false;
                    }
                    cp = (cp << 6) | uint32_t(*p & 0x3Fu);
                }

                if (cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) {
                    return false;
                }

                if (cp < 0x10000u) {
                    if (!units.add(uint8_t(cp >> 8)) || !units.add(uint8_t(cp & 0xFF))) {
                        return false;
                    }
                } else {
                    // Strictly outside a BMPString's range, but the surrogate pair is what every
                    // implementation that converts UTF-8 to "BMPString" here actually writes.
                    const uint32_t v = cp - 0x10000u;
                    const uint16_t hi = uint16_t(0xD800u + (v >> 10));
                    const uint16_t lo = uint16_t(0xDC00u + (v & 0x3FFu));
                    if (!units.add(uint8_t(hi >> 8)) || !units.add(uint8_t(hi & 0xFF))
                        || !units.add(uint8_t(lo >> 8)) || !units.add(uint8_t(lo & 0xFF)))
                    {
                        return false;
                    }
                }
            }

            // The terminating NUL is part of the KDF input, not a C-string artefact: omitting it
            // derives a different key from every other implementation.
            if (!units.add(uint8_t(0)) || !units.add(uint8_t(0))) {
                return false;
            }

            if (!out.resize(units.size())) {
                return false;
            }

            std::memcpy(out.toPtr(), units.begin(), units.size());
            return true;
        }

        /* RFC 7292 Appendix B.2's key derivation, used for exactly one thing: the `MacData` MAC
         * key, with purposeId 3.
         *
         * This is a legacy construction and is deliberately not exposed as a general-purpose KDF
         * -- it is here because RFC 7292 section 4 mandates it for the MAC and every real file
         * therefore uses it, not because it is a good way to stretch a password. For that, see
         * `CPbkdf2`, which is what the *encryption* keys in this format come from.
         *
         *   D = purposeId repeated v bytes
         *   I = salt extended to a multiple of v, then password extended to a multiple of v
         *   A(i) = H^c(D || I), and between blocks I is incremented by (A(i) extended to v) + 1
         *
         * `v` is the hash's block size, `u` its output length. The increment is over each v-byte
         * chunk of I independently, with the carry discarded at each chunk -- not over I as one
         * big integer, which is the easy misreading. */
        bool p12Kdf(
            crypto::EHashers hasherType, const SReadOnlyByteSpan& bmpPassword,
            const SReadOnlyByteSpan& salt, uint32_t iterations,
            const SByteSpan& out, uint8_t purposeId
        ) {
            if (iterations == 0 || out.size == 0 || !out.data) {
                return false;
            }

            const size_t v = crypto::CHmac::blockBytesOf(hasherType);
            if (v == 0 || v > crypto::CHmac::MAX_BLOCK_BYTES) {
                return false;
            }

            crypto::IHasherPtr hasher;
            if (crypto::IHasher::create(hasherType, hasher) != ERET_OK || !hasher) {
                return false;
            }

            const size_t u = hasher->byteWidth();
            if (u == 0 || u > MAX_DIGEST_BYTES) {
                return false;
            }

            // An empty password or salt extends to nothing at all rather than to v zero bytes,
            // which is what RFC 7292 B.2 means by "if the length is 0, omit it".
            auto extended = [v](const SReadOnlyByteSpan& in, CBuffer& dst) -> bool {
                if (in.size == 0) {
                    dst.clear();
                    return true;
                }

                const size_t blocks = (in.size + v - 1) / v;
                if (!dst.resize(blocks * v)) {
                    return false;
                }

                uint8_t* ptr = dst.toPtr();
                for (size_t i = 0; i < dst.size(); i += in.size) {
                    const size_t take = (dst.size() - i < in.size) ? (dst.size() - i) : in.size;
                    std::memcpy(ptr + i, in.data, take);
                }

                return true;
            };

            CBuffer saltBlock, passBlock;
            if (!extended(salt, saltBlock) || !extended(bmpPassword, passBlock)) {
                return false;
            }

            CBuffer ivec;
            if (!ivec.resize(saltBlock.size() + passBlock.size())) {
                return false;
            }
            if (saltBlock.size() != 0) {
                std::memcpy(ivec.toPtr(), saltBlock.toPtr(), saltBlock.size());
            }
            if (passBlock.size() != 0) {
                std::memcpy(ivec.toPtr() + saltBlock.size(), passBlock.toPtr(), passBlock.size());
            }

            CBuffer diversifier;
            if (!diversifier.resize(v)) {
                return false;
            }
            std::memset(diversifier.toPtr(), purposeId, v);

            uint8_t digest[MAX_DIGEST_BYTES];
            CBuffer bBlock;
            bool ok = bBlock.resize(v);
            size_t written = 0;

            while (ok && written < out.size) {
                hasher->reset();
                ok = hasher->push(diversifier.toSpan()) == v
                    && (ivec.size() == 0 || hasher->push(ivec.toSpan()) == ivec.size())
                    && hasher->finish(SByteSpan(digest, u));

                for (uint32_t round = 1; ok && round < iterations; ++round) {
                    hasher->reset();
                    ok = hasher->push(SReadOnlyByteSpan(digest, u)) == u
                        && hasher->finish(SByteSpan(digest, u));
                }

                if (!ok) {
                    break;
                }

                const size_t take = (out.size - written < u) ? (out.size - written) : u;
                std::memcpy(out.data + written, digest, take);
                written += take;

                if (written >= out.size) {
                    break;
                }

                // B = A extended to v bytes, then I += B + 1 per v-byte chunk.
                uint8_t* bPtr = bBlock.toPtr();
                for (size_t i = 0; i < v; i += u) {
                    const size_t take2 = (v - i < u) ? (v - i) : u;
                    std::memcpy(bPtr + i, digest, take2);
                }

                uint8_t* ivPtr = ivec.toPtr();
                for (size_t chunk = 0; chunk < ivec.size(); chunk += v) {
                    uint32_t carry = 1;
                    for (size_t i = v; i-- > 0;) {
                        const uint32_t sum = uint32_t(ivPtr[chunk + i]) + uint32_t(bPtr[i]) + carry;
                        ivPtr[chunk + i] = uint8_t(sum & 0xFF);
                        carry = sum >> 8;
                    }
                    // The carry out of each chunk is discarded: the arithmetic is mod 2^(v*8)
                    // per chunk, not across the whole of I.
                }
            }

            // Every one of these is derived from the password.
            CSecure::zero(SByteSpan(digest, sizeof(digest)));
            CSecure::zero(SByteSpan(bBlock.toPtr(), bBlock.size()));
            CSecure::zero(SByteSpan(ivec.toPtr(), ivec.size()));
            CSecure::zero(SByteSpan(passBlock.toPtr(), passBlock.size()));

            return ok;
        }

        // ------------------------------------------------------------- PBES2

        /* Everything PBES2 needs, either parsed out of a container or generated for a new one. */
        struct SPbes2 {
            crypto::EHashers prf = crypto::EHASH_SHA1;  // PBKDF2-params' DEFAULT is hmacWithSHA1.
            CBuffer salt;
            uint32_t iterations = 0;
            size_t keyBytes = 0;
            CBuffer iv;
        };

        /* Maps an hmacWith* OID onto the hash it names. */
        bool resolvePrf(const CString& oid, crypto::EHashers& out) {
            if (oid.compare(OID_HMAC_SHA256) == 0) { out = crypto::EHASH_SHA256; return true; }
            if (oid.compare(OID_HMAC_SHA512) == 0) { out = crypto::EHASH_SHA512; return true; }
            if (oid.compare(OID_HMAC_SHA384) == 0) { out = crypto::EHASH_SHA384; return true; }
            if (oid.compare(OID_HMAC_SHA224) == 0) { out = crypto::EHASH_SHA224; return true; }
            if (oid.compare(OID_HMAC_SHA1) == 0)   { out = crypto::EHASH_SHA1;   return true; }
            return false;
        }

        /* Maps a digest OID onto the hash it names, for MacData's DigestInfo. */
        bool resolveDigest(const CString& oid, crypto::EHashers& out) {
            if (oid.compare(OID_SHA256) == 0) { out = crypto::EHASH_SHA256; return true; }
            if (oid.compare(OID_SHA512) == 0) { out = crypto::EHASH_SHA512; return true; }
            if (oid.compare(OID_SHA384) == 0) { out = crypto::EHASH_SHA384; return true; }
            if (oid.compare(OID_SHA224) == 0) { out = crypto::EHASH_SHA224; return true; }
            if (oid.compare(OID_SHA1) == 0)   { out = crypto::EHASH_SHA1;   return true; }
            return false;
        }

        /* The OID for a digest, for writing MacData. */
        const char* digestOidOf(crypto::EHashers which) {
            switch (which) {
                case crypto::EHASH_SHA1:   return OID_SHA1;
                case crypto::EHASH_SHA224: return OID_SHA224;
                case crypto::EHASH_SHA256: return OID_SHA256;
                case crypto::EHASH_SHA384: return OID_SHA384;
                case crypto::EHASH_SHA512: return OID_SHA512;
                default: return nullptr;
            }
        }

        /* Parses a PBES2 AlgorithmIdentifier's parameters (RFC 8018 A.4):
         *   PBES2-params ::= SEQUENCE { keyDerivationFunc AlgId, encryptionScheme AlgId }
         *
         * ERET_NOTSUP, not ERET_BADREQ, for a well-formed scheme this class does not implement --
         * the legacy PKCS#12 ciphers land here, and a caller needs to be able to tell "I cannot
         * read this" from "this is not a PFX".
         *
         * `params` is the SEQUENCE's *content*, not the SEQUENCE's own TLV -- which is what every
         * caller has, since they all reach it through `readNextElement()`. Wrapping a reader
         * around it and asking for a SEQUENCE instead reads the keyDerivationFunc as if it were
         * the whole of PBES2-params, which fails one level further down with a confusing error. */
        ERetCode parsePbes2(SReadOnlyByteSpan params, SPbes2& out) {
            CReader seq(params, EAENC_DER);

            CReader kdf;
            CString kdfOid;
            if (!seq.readSequence(kdf) || !kdf.readOidString(kdfOid)) {
                return ERET_BADREQ;
            }
            if (kdfOid.compare(OID_PBKDF2) != 0) {
                return ERET_NOTSUP; // e.g. scrypt (RFC 7914), which this library has no KDF for.
            }

            // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER,
            //                              keyLength INTEGER OPTIONAL,
            //                              prf AlgId DEFAULT hmacWithSHA1 }
            CReader kdfParams;
            SReadOnlyByteSpan salt;
            int64_t iterations = 0;
            if (!kdf.readSequence(kdfParams) || !kdfParams.readOctetString(salt)
                || !kdfParams.readInteger(iterations))
            {
                return ERET_BADREQ;
            }
            if (iterations <= 0 || iterations > 0x7FFFFFFF) {
                // Zero is not "no stretching" (see CPbkdf2), and a negative count is nonsense.
                return ERET_BADREQ;
            }

            out.iterations = uint32_t(iterations);
            out.keyBytes = 0;
            out.prf = crypto::EHASH_SHA1; // the DEFAULT, which is omitted from the encoding.

            while (!kdfParams.atEnd()) {
                CTag tag;
                SReadOnlyByteSpan content;
                if (!kdfParams.readNextElement(tag, content)) {
                    return ERET_BADREQ;
                }

                if (tag == CTag::INTEGER) {
                    // keyLength, when present. Bounded because it sizes an allocation.
                    if (content.size == 0 || content.size > 2) {
                        return ERET_BADREQ;
                    }

                    size_t value = 0;
                    for (size_t i = 0; i < content.size; ++i) {
                        value = (value << 8) | content.data[i];
                    }
                    out.keyBytes = value;
                } else if (tag == CTag::SEQ) {
                    CReader prf(content, EAENC_DER);
                    CString prfOid;
                    if (!prf.readOidString(prfOid)) {
                        return ERET_BADREQ;
                    }
                    if (!resolvePrf(prfOid, out.prf)) {
                        return ERET_NOTSUP;
                    }
                }
            }

            // encryptionScheme: AES-CBC only. The parameters are the IV as an OCTET STRING.
            CReader scheme;
            CString schemeOid;
            if (!seq.readSequence(scheme) || !scheme.readOidString(schemeOid)) {
                return ERET_BADREQ;
            }

            size_t cipherKeyBytes = 0;
            if (schemeOid.compare(OID_AES256_CBC) == 0)      { cipherKeyBytes = 32; }
            else if (schemeOid.compare(OID_AES192_CBC) == 0) { cipherKeyBytes = 24; }
            else if (schemeOid.compare(OID_AES128_CBC) == 0) { cipherKeyBytes = 16; }
            else { return ERET_NOTSUP; }

            SReadOnlyByteSpan iv;
            if (!scheme.readOctetString(iv) || iv.size != CBC_IV_BYTES) {
                return ERET_BADREQ;
            }

            // RFC 8018 A.2 makes keyLength OPTIONAL "since the key length is implied by the
            // encryption scheme" -- OpenSSL omits it. Where it is present and disagrees with the
            // cipher, the cipher wins, because that is what the key is actually used for.
            out.keyBytes = cipherKeyBytes;

            if (!out.salt.resize(salt.size) || !out.iv.resize(iv.size)) {
                return ERET_NOMEM;
            }
            if (salt.size != 0) {
                std::memcpy(out.salt.toPtr(), salt.data, salt.size);
            }
            std::memcpy(out.iv.toPtr(), iv.data, iv.size);

            return ERET_OK;
        }

        /* Writes a PBES2 AlgorithmIdentifier for `spec`, as the contentEncryptionAlgorithm of an
         * EncryptedContentInfo or the encryptionAlgorithm of an EncryptedPrivateKeyInfo. */
        bool appendPbes2AlgoId(CBuffer& out, const SPbes2& spec) {
            const char* prfOid = nullptr;
            switch (spec.prf) {
                case crypto::EHASH_SHA256: prfOid = OID_HMAC_SHA256; break;
                case crypto::EHASH_SHA512: prfOid = OID_HMAC_SHA512; break;
                case crypto::EHASH_SHA384: prfOid = OID_HMAC_SHA384; break;
                default: return false;
            }

            CBuffer prfNull;
            if (!CDer::appendTlv(prfNull, CTag::NULL_, SReadOnlyByteSpan(nullptr, 0))) {
                return false;
            }

            CBuffer kdfParams;
            if (!CDer::appendTlv(kdfParams, CTag::STRING_OCTET, spec.salt.toSpan())
                || !appendInteger(kdfParams, spec.iterations)
                || !appendAlgoId(kdfParams, prfOid, prfNull.toSpan()))
            {
                return false;
            }

            CBuffer kdfParamsSeq;
            if (!CDer::appendSequence(kdfParamsSeq, kdfParams.toSpan())) {
                return false;
            }

            CBuffer schemeIv;
            if (!CDer::appendTlv(schemeIv, CTag::STRING_OCTET, spec.iv.toSpan())) {
                return false;
            }

            CBuffer pbes2Params;
            if (!appendAlgoId(pbes2Params, OID_PBKDF2, kdfParamsSeq.toSpan())
                || !appendAlgoId(pbes2Params, OID_AES256_CBC, schemeIv.toSpan()))
            {
                return false;
            }

            CBuffer pbes2ParamsSeq;
            if (!CDer::appendSequence(pbes2ParamsSeq, pbes2Params.toSpan())) {
                return false;
            }

            return appendAlgoId(out, OID_PBES2, pbes2ParamsSeq.toSpan());
        }

        /* Runs AES-CBC over `input` in one shot, into `out`.
         *
         * `key` is the derived key, which the caller owns wiping; this function wipes nothing of
         * the caller's and allocates nothing the caller cannot see. PKCS#7 padding is the
         * context's default, and on decryption `transformFinal()` already validates it in
         * constant time -- which matters less here than it would elsewhere, because the MAC has
         * already established that the ciphertext is the one the password's owner wrote. */
        ERetCode aesCbc(
            bool encrypting, const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& iv,
            const SReadOnlyByteSpan& input, CBuffer& out
        ) {
            crypto::ISymmetricPtr aes = crypto::ISymmetric::builtIn(crypto::ESYM_AES);
            if (!aes) {
                return ERET_NOTSUP;
            }

            crypto::ISymmetricKeyPtr symKey = aes->createKey(key);
            if (!symKey) {
                return ERET_KEY_ERROR;
            }

            crypto::ISymmetricContextPtr ctx = aes->createContext(symKey);
            if (!ctx) {
                return ERET_UNKNOWN;
            }

            ctx->key(symKey, CBuffer(iv.data, iv.size));

            crypto::ISymmetricTransformerPtr xf;
            const ERetCode created = encrypting
                ? ctx->createEncrypter(xf)
                : ctx->createDecrypter(xf);
            if (created != ERET_OK || !xf) {
                return created == ERET_OK ? ERET_UNKNOWN : created;
            }

            // One whole extra block of headroom: encrypting always appends a pad block, and
            // decrypting never produces more than it consumes.
            if (!out.resize(input.size + 2 * CBC_IV_BYTES)) {
                return ERET_NOMEM;
            }

            SByteSpan first(out.toPtr(), out.size());
            ERetCode result = xf->transform(input, first);
            if (result != ERET_OK) {
                return result;
            }

            SByteSpan rest(out.toPtr() + first.size, out.size() - first.size);
            result = xf->transformFinal(rest);
            if (result != ERET_OK) {
                return result;
            }

            const size_t total = first.size + rest.size;
            if (total > out.size()) {
                return ERET_NOSPC;
            }

            // `out` is oversized by a block on purpose, and trimming it with `out.resize(total)`
            // would be wrong in a way that is easy to miss: `CBuffer::resize()` always allocates
            // a fresh block, copies the part it keeps, and `delete[]`s the old one -- **without
            // wiping it**. On the decrypt path that old block holds the complete plaintext, which
            // for a pkcs8ShroudedKeyBag is a private key, so trimming would hand the key back to
            // the allocator in the clear and the caller's own wipe would then scrub the copy
            // instead. Copy the exact length out, wipe the oversized block, and swap it away.
            CBuffer exact;
            if (!exact.resize(total)) {
                CSecure::zero(SByteSpan(out.toPtr(), out.size()));
                return ERET_NOMEM;
            }

            std::memcpy(exact.toPtr(), out.toPtr(), total);
            CSecure::zero(SByteSpan(out.toPtr(), out.size()));

            // Move-assignment swaps (this library's convention), so `exact` leaves holding the
            // oversized block -- already wiped above -- and destroys it.
            out = std::move(exact);
            return ERET_OK;
        }

        /* Derives a PBES2 key and runs the cipher, wiping the key on every path out. */
        ERetCode pbes2Transform(
            bool encrypting, const SPbes2& spec, const SReadOnlyByteSpan& password,
            const SReadOnlyByteSpan& input, CBuffer& out
        ) {
            if (spec.keyBytes == 0 || spec.keyBytes > AES256_KEY_BYTES) {
                return ERET_NOTSUP;
            }

            uint8_t key[AES256_KEY_BYTES];
            ERetCode result = crypto::CPbkdf2::derive(
                spec.prf, password, spec.salt.toSpan(), spec.iterations,
                SByteSpan(key, spec.keyBytes));

            if (result == ERET_OK) {
                result = aesCbc(
                    encrypting, SReadOnlyByteSpan(key, spec.keyBytes), spec.iv.toSpan(),
                    input, out);
            }

            // --> Three `return`s above this line and one below it, which is why the wipe is here
            // and not beside any of them.
            CSecure::zero(SByteSpan(key, sizeof(key)));
            return result;
        }

        // ------------------------------------------------------- bags and attributes

        /* One SafeBag, as read out of a SafeContents.
         *
         * `bagValue` is a *copy* of the [0] EXPLICIT wrapper's content rather than a span into
         * it. A bag out of an encrypted SafeContents points into a decrypted plaintext buffer,
         * and a span would tie that buffer's lifetime to the whole of `load()`: it could not be
         * wiped until every bag had been consumed, which for a container with several encrypted
         * ContentInfos means several plaintexts sitting in memory at once for no reason.
         *
         * (Holding spans into a `TArray<CBuffer>` would in fact have *worked* -- `TArray` grows
         * by move-constructing, and `CBuffer`'s move hands over the same heap block, so the
         * addresses survive. Depending on that is the part worth avoiding; the copy costs a few
         * hundred bytes per bag and depends on nothing.) */
        struct SBag {
            CString bagId;
            COctet bagValue;
            CString friendlyName;
            COctet localKeyId;

            /* A bagValue is usually public -- a certificate, or a key already encrypted into an
             * EncryptedPrivateKeyInfo -- but for a plain `keyBag` inside an encrypted
             * SafeContents it is a PKCS#8 private key in the clear. Wiping in the destructor
             * rather than at the end of load() covers that case on every path out, including the
             * half-dozen error returns between here and there. */
            ~SBag() {
                CSecure::zero(SByteSpan(
                    const_cast<uint8_t*>(bagValue.toPtr()), bagValue.size()));
            }
        };

        /* Reads a SafeBag's bagAttributes SET OF Attribute, picking out the two PKCS#9 attributes
         * a PFX actually uses. Anything else is skipped rather than refused: real containers carry
         * Microsoft's own CSP-name attributes and a reader that choked on them would be useless. */
        bool readAttributes(CReader& set, SBag& out) {
            while (!set.atEnd()) {
                CReader attr;
                CString oid;
                if (!set.readSequence(attr) || !attr.readOidString(oid)) {
                    return false;
                }

                CReader values;
                if (!attr.readSet(values)) {
                    return false;
                }

                CTag tag;
                SReadOnlyByteSpan content;
                if (!values.readNextElement(tag, content)) {
                    continue; // an attribute with no values at all; nothing to take.
                }

                if (oid.compare(OID_LOCAL_KEY_ID) == 0 && tag == CTag::STRING_OCTET) {
                    out.localKeyId = COctet(content);
                } else if (oid.compare(OID_FRIENDLY_NAME) == 0
                           && tag.value() == asn1::EAUTAG_STRING_BMP)
                {
                    // BMPString: UTF-16BE. Converted to UTF-8 here, since CString is a byte
                    // string and SCertEntry::friendlyName is one.
                    CString text;
                    for (size_t i = 0; i + 1 < content.size; i += 2) {
                        const uint32_t unit = (uint32_t(content.data[i]) << 8)
                                            | uint32_t(content.data[i + 1]);

                        // Lone surrogates are passed over rather than encoded: WTF-8 is not UTF-8,
                        // and a friendlyName is a label, not key material.
                        if (unit >= 0xD800u && unit <= 0xDFFFu) {
                            continue;
                        }

                        if (unit < 0x80u) {
                            text.append(char(unit));
                        } else if (unit < 0x800u) {
                            text.append(char(0xC0u | (unit >> 6)));
                            text.append(char(0x80u | (unit & 0x3Fu)));
                        } else {
                            text.append(char(0xE0u | (unit >> 12)));
                            text.append(char(0x80u | ((unit >> 6) & 0x3Fu)));
                            text.append(char(0x80u | (unit & 0x3Fu)));
                        }
                    }

                    out.friendlyName = std::move(text);
                }
            }

            return true;
        }

        /* Reads a SafeContents ::= SEQUENCE OF SafeBag into `out`, appended. */
        bool readSafeContents(SReadOnlyByteSpan der, TArray<SBag>& out) {
            CReader reader(der, EAENC_DER);
            CReader contents;
            if (!reader.readSequence(contents)) {
                return false;
            }

            while (!contents.atEnd()) {
                CReader bag;
                if (!contents.readSequence(bag)) {
                    return false;
                }

                SBag parsed;
                if (!bag.readOidString(parsed.bagId)) {
                    return false;
                }

                // bagValue [0] EXPLICIT ANY -- a constructed context tag whose single child is
                // the bag's real value. The child's own TLV is what the bag handlers below want,
                // so the wrapper's content is kept whole rather than unwrapped another step.
                CTag tag;
                SReadOnlyByteSpan value;
                if (!bag.readNextElement(tag, value)
                    || tag.tagClass() != EATAG_CONTEXT_SPECIFIC || tag.value() != 0)
                {
                    return false;
                }

                // Copied, not referenced -- see SBag's own comment on why.
                parsed.bagValue = COctet(value);
                if (value.size != 0 && parsed.bagValue.empty()) {
                    return false;
                }

                if (!bag.atEnd()) {
                    CReader set;
                    if (!bag.readSet(set) || !readAttributes(set, parsed)) {
                        return false;
                    }
                }

                if (!out.add(std::move(parsed))) {
                    return false;
                }
            }

            return true;
        }

        /* Pulls the DER certificate out of a certBag's bagValue:
         *   CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT ANY }
         * with certId x509Certificate and certValue an OCTET STRING of the Certificate's DER. */
        bool readCertBag(const SReadOnlyByteSpan& bagValue, COctet& out) {
            CReader reader(bagValue, EAENC_DER);
            CReader seq;
            CString certId;
            if (!reader.readSequence(seq) || !seq.readOidString(certId)) {
                return false;
            }
            if (certId.compare(OID_X509_CERTIFICATE) != 0) {
                return false; // an SDSI certificate, or something newer; not an X.509 one.
            }

            CTag tag;
            SReadOnlyByteSpan wrapper;
            if (!seq.readNextElement(tag, wrapper)
                || tag.tagClass() != EATAG_CONTEXT_SPECIFIC || tag.value() != 0)
            {
                return false;
            }

            CReader inner(wrapper, EAENC_DER);
            SReadOnlyByteSpan der;
            if (!inner.readOctetString(der) || der.size == 0) {
                return false;
            }

            out = COctet(der);
            return true;
        }

        /* Reads an EncryptedPrivateKeyInfo (RFC 5958 3) out of a pkcs8ShroudedKeyBag, decrypts it
         * and parses the PKCS#8 inside. The plaintext is wiped before returning, on both the
         * success and failure paths -- it is the private key. */
        ERetCode readShroudedKeyBag(
            const SReadOnlyByteSpan& bagValue, const SReadOnlyByteSpan& password,
            crypto::IPrivateKeyPtr& out
        ) {
            CReader reader(bagValue, EAENC_DER);
            CReader seq;
            CReader algo;
            CString algoOid;
            if (!reader.readSequence(seq) || !seq.readSequence(algo)
                || !algo.readOidString(algoOid))
            {
                return ERET_BADREQ;
            }
            if (algoOid.compare(OID_PBES2) != 0) {
                return ERET_NOTSUP; // PBES1/pbeWithSHAAnd3-KeyTripleDES-CBC and friends.
            }

            CTag paramsTag;
            SReadOnlyByteSpan params;
            if (!algo.readNextElement(paramsTag, params) || paramsTag != CTag::SEQ) {
                return ERET_BADREQ;
            }

            SPbes2 spec;
            ERetCode result = parsePbes2(params, spec);
            if (result != ERET_OK) {
                return result;
            }

            SReadOnlyByteSpan ciphertext;
            if (!seq.readOctetString(ciphertext) || ciphertext.size == 0) {
                return ERET_BADREQ;
            }

            CBuffer plain;
            result = pbes2Transform(false, spec, password, ciphertext, plain);
            if (result == ERET_OK) {
                result = CCert::importPkcs8PrivateKey(plain.toSpan(), out);
            } else {
                // The MAC has already passed, so this is a damaged file rather than a bad
                // password -- but the interface reports both the same way on purpose, and the
                // caller must not be able to tell which happened.
                result = ERET_KEY_ERROR;
            }

            CSecure::zero(SByteSpan(plain.toPtr(), plain.size()));
            return result;
        }

        // ------------------------------------------------------- writing attributes

        /* Appends one Attribute ::= SEQUENCE { attrId OID, attrValues SET OF ANY }. */
        bool appendAttribute(CBuffer& out, const char* oid, SReadOnlyByteSpan valueTlv) {
            CBuffer valueSet;
            if (!CDer::appendTlv(valueSet, CTag::SET_OF, valueTlv)) {
                return false;
            }

            CBuffer content;
            if (!appendOid(content, oid) || !CDer::appendRaw(content, valueSet.toSpan())) {
                return false;
            }

            return CDer::appendSequence(out, content.toSpan());
        }

        /* Appends a SafeBag's bagAttributes SET, or nothing when the entry has neither attribute.
         * The friendlyName goes out as a BMPString, which is what RFC 7292 specifies and what
         * every reader expects -- a UTF8String there is read as mojibake or rejected. */
        bool appendBagAttributes(CBuffer& out, const CString& friendlyName, const COctet& localKeyId) {
            if (friendlyName.empty() && localKeyId.empty()) {
                return true;
            }

            CBuffer attrs;

            if (!localKeyId.empty()) {
                CBuffer value;
                if (!CDer::appendTlv(value, CTag::STRING_OCTET, localKeyId.toSpan())
                    || !appendAttribute(attrs, OID_LOCAL_KEY_ID, value.toSpan()))
                {
                    return false;
                }
            }

            if (!friendlyName.empty()) {
                // UTF-8 in, UTF-16BE out. Invalid UTF-8 in a caller-supplied label is dropped
                // byte by byte rather than failing the whole save: a mangled name is a cosmetic
                // problem, a refused export is not.
                TArray<uint8_t> units;
                const uint8_t* p = reinterpret_cast<const uint8_t*>(friendlyName.toPtr());
                const uint8_t* end = p + friendlyName.size();

                while (p < end) {
                    uint32_t cp = 0;
                    size_t extra = 0;

                    if (*p < 0x80) { cp = *p; extra = 0; }
                    else if ((*p & 0xE0) == 0xC0) { cp = *p & 0x1Fu; extra = 1; }
                    else if ((*p & 0xF0) == 0xE0) { cp = *p & 0x0Fu; extra = 2; }
                    else if ((*p & 0xF8) == 0xF0) { cp = *p & 0x07u; extra = 3; }
                    else { ++p; continue; }

                    if (size_t(end - p) <= extra) {
                        break;
                    }

                    ++p;
                    bool valid = true;
                    for (size_t i = 0; i < extra; ++i, ++p) {
                        if ((*p & 0xC0) != 0x80) { valid = false; break; }
                        cp = (cp << 6) | uint32_t(*p & 0x3Fu);
                    }

                    // A BMPString holds one 16-bit unit per character, so anything above the BMP
                    // cannot go in one at all and is replaced rather than split into surrogates.
                    if (!valid) {
                        continue;
                    }
                    if (cp > 0xFFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) {
                        cp = 0xFFFDu;
                    }

                    if (!units.add(uint8_t(cp >> 8)) || !units.add(uint8_t(cp & 0xFF))) {
                        return false;
                    }
                }

                CBuffer value;
                const SReadOnlyByteSpan unitSpan = units.size() == 0
                    ? SReadOnlyByteSpan(nullptr, 0)
                    : SReadOnlyByteSpan(units.begin(), units.size());

                if (!CDer::appendTlv(value, CTag(asn1::EAUTAG_STRING_BMP, false), unitSpan)
                    || !appendAttribute(attrs, OID_FRIENDLY_NAME, value.toSpan()))
                {
                    return false;
                }
            }

            return CDer::appendTlv(out, CTag::SET_OF, attrs.toSpan());
        }

        /* Appends a SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY, attrs SET? }. */
        bool appendSafeBag(
            CBuffer& out, const char* bagOid, SReadOnlyByteSpan bagValueTlv,
            const CString& friendlyName, const COctet& localKeyId
        ) {
            CBuffer content;
            if (!appendOid(content, bagOid)
                || !CDer::appendTlv(content, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), bagValueTlv)
                || !appendBagAttributes(content, friendlyName, localKeyId))
            {
                return false;
            }

            return CDer::appendSequence(out, content.toSpan());
        }

    } // namespace

    /* Constructs the format handler. */
    CPfxFormat::CPfxFormat(uint32_t iterations)
        : _iterations(iterations == 0 ? DEFAULT_ITERATIONS : iterations)
    {
    }

    /* Destroys the format handler. */
    CPfxFormat::~CPfxFormat() {
    }

    /* Returns the iteration count save() will use. */
    uint32_t CPfxFormat::iterations() const {
        return _iterations;
    }

    /* Returns ECHAINFMT_PFX. */
    EChainFormats CPfxFormat::format() const {
        return ECHAINFMT_PFX;
    }

    /* Returns true: a PFX without a password is not a PFX. */
    bool CPfxFormat::needsPassword() const {
        return true;
    }

    /* Reads a PFX into a collection, verifying its MAC before anything else. */
    ERetCode CPfxFormat::load(
        const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& password,
        CCertCollection& out
    ) const {
        if (!data.data || data.size == 0) {
            return ERET_BADREQ;
        }
        if (data.size > MAX_CONTAINER_BYTES) {
            return ERET_BADREQ;
        }
        if (!password.data || password.size == 0) {
            return ERET_BADREQ;
        }

        // --- PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData MacData OPTIONAL }
        CReader reader(data, EAENC_DER);
        CReader pfx;
        int64_t version = 0;
        if (!reader.readSequence(pfx) || !pfx.readInteger(version)) {
            return ERET_BADREQ;
        }
        if (version != 3) {
            return ERET_BADREQ; // v3 is the only version RFC 7292 defines.
        }

        // authSafe ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }. For a
        // password-integrity PFX the type is pkcs7-data and the content is an OCTET STRING whose
        // bytes are the AuthenticatedSafe -- and those exact bytes are what the MAC covers.
        CReader authSafe;
        CString authSafeType;
        if (!pfx.readSequence(authSafe) || !authSafe.readOidString(authSafeType)) {
            return ERET_BADREQ;
        }
        if (authSafeType.compare(OID_PKCS7_DATA) != 0) {
            // A public-key-integrity PFX wraps signedData here. Not implemented, and saying so is
            // better than reporting the file as malformed.
            return ERET_NOTSUP;
        }

        CTag wrapTag;
        SReadOnlyByteSpan wrapped;
        if (!authSafe.readNextElement(wrapTag, wrapped)
            || wrapTag.tagClass() != EATAG_CONTEXT_SPECIFIC || wrapTag.value() != 0)
        {
            return ERET_BADREQ;
        }

        SReadOnlyByteSpan authenticated;
        {
            CReader octet(wrapped, EAENC_DER);
            if (!octet.readOctetString(authenticated) || authenticated.size == 0) {
                return ERET_BADREQ;
            }
        }

        // --- The MAC, checked before one byte of `authenticated` is parsed or decrypted. ---
        //
        // Up to this point nothing has been trusted beyond the outer envelope needed to *find*
        // the MAC. From here on the bytes have been vouched for by someone who knows the
        // password, which is what makes the rest of this method safe to run at all.
        if (pfx.atEnd()) {
            // No MacData. RFC 7292 makes it OPTIONAL, which is a statement about the ASN.1 and
            // not permission to read an unauthenticated container -- there is no integrity
            // protection here and nothing to fall back on, so it is refused with the same code a
            // failed MAC gets.
            return ERET_KEY_ERROR;
        }

        {
            CReader macData;
            CReader digestInfo;
            CReader digestAlgo;
            CString digestOid;
            if (!pfx.readSequence(macData) || !macData.readSequence(digestInfo)
                || !digestInfo.readSequence(digestAlgo) || !digestAlgo.readOidString(digestOid))
            {
                return ERET_BADREQ;
            }

            crypto::EHashers macHash = crypto::EHASH_UNKNOWN;
            if (!resolveDigest(digestOid, macHash)) {
                return ERET_NOTSUP;
            }

            SReadOnlyByteSpan expected;
            SReadOnlyByteSpan macSalt;
            if (!digestInfo.readOctetString(expected) || !macData.readOctetString(macSalt)) {
                return ERET_BADREQ;
            }

            int64_t macIterations = 1; // MacData's iterations field has DEFAULT 1.
            if (!macData.atEnd() && !macData.readInteger(macIterations)) {
                return ERET_BADREQ;
            }
            // Zero is not "no stretching" (see CPbkdf2), and the upper bound matters here in a
            // way it does not for the PBES2 counts below: this derivation runs *before* the MAC
            // has vouched for anything, so the count is an attacker's parameter. See
            // MAX_MAC_ITERATIONS.
            if (macIterations <= 0 || macIterations > int64_t(MAX_MAC_ITERATIONS)) {
                return ERET_BADREQ;
            }

            crypto::IHasherPtr probe;
            if (crypto::IHasher::create(macHash, probe) != ERET_OK || !probe) {
                return ERET_NOTSUP;
            }

            const size_t macBytes = probe->byteWidth();
            if (macBytes == 0 || macBytes > MAX_DIGEST_BYTES || expected.size != macBytes) {
                return ERET_BADREQ;
            }

            CBuffer bmp;
            if (!toBmpPassword(password, bmp)) {
                return ERET_BADREQ; // the password is not text, so it is not a BMPString.
            }

            uint8_t macKey[MAX_DIGEST_BYTES];
            uint8_t actual[MAX_DIGEST_BYTES];
            bool verified = false;

            // RFC 7292 section 4: the MAC key is the Appendix B KDF with ID=3, over the
            // BMPString password -- not PBKDF2, and not the raw password bytes.
            if (p12Kdf(macHash, bmp.toSpan(), macSalt, uint32_t(macIterations),
                       SByteSpan(macKey, macBytes), 3))
            {
                if (crypto::CHmac::compute(
                        macHash, SReadOnlyByteSpan(macKey, macBytes), authenticated,
                        SByteSpan(actual, macBytes)) == ERET_OK)
                {
                    // CSecure::equals, not memcmp: a comparison that stops at the first differing
                    // byte tells an attacker how much of a forged MAC was right.
                    verified = CSecure::equals(
                        SReadOnlyByteSpan(actual, macBytes), expected);
                }
            }

            CSecure::zero(SByteSpan(macKey, sizeof(macKey)));
            CSecure::zero(SByteSpan(actual, sizeof(actual)));
            CSecure::zero(SByteSpan(bmp.toPtr(), bmp.size()));

            if (!verified) {
                // A wrong password and a tampered container are both this, and the caller cannot
                // tell them apart. See CPfxFormat's own doc comment on why that is the point.
                return ERET_KEY_ERROR;
            }
        }

        // --- AuthenticatedSafe ::= SEQUENCE OF ContentInfo ---
        //
        // Every bag owns a copy of its own value (see SBag), so no decrypted plaintext has to
        // outlive the ContentInfo it came from -- which is what lets each one be wiped as soon as
        // its bags have been read rather than at the end of the method.
        TArray<SBag> bags;
        {
            CReader safeReader(authenticated, EAENC_DER);
            CReader safes;
            if (!safeReader.readSequence(safes)) {
                return ERET_BADREQ;
            }

            while (!safes.atEnd()) {
                CReader info;
                CString infoType;
                if (!safes.readSequence(info) || !info.readOidString(infoType)) {
                    return ERET_BADREQ;
                }

                CTag contentTag;
                SReadOnlyByteSpan content;
                if (!info.readNextElement(contentTag, content)
                    || contentTag.tagClass() != EATAG_CONTEXT_SPECIFIC || contentTag.value() != 0)
                {
                    return ERET_BADREQ;
                }

                if (infoType.compare(OID_PKCS7_DATA) == 0) {
                    SReadOnlyByteSpan safeContents;
                    CReader octet(content, EAENC_DER);
                    if (!octet.readOctetString(safeContents)
                        || !readSafeContents(safeContents, bags))
                    {
                        return ERET_BADREQ;
                    }
                } else if (infoType.compare(OID_PKCS7_ENCRYPTED_DATA) == 0) {
                    // EncryptedData ::= SEQUENCE { version INTEGER,
                    //                              encryptedContentInfo EncryptedContentInfo }
                    CReader encrypted;
                    CReader eci;
                    CString innerType;
                    int64_t encVersion = 0;
                    CReader algo;
                    CString algoOid;
                    {
                        CReader holder(content, EAENC_DER);
                        if (!holder.readSequence(encrypted) || !encrypted.readInteger(encVersion)
                            || !encrypted.readSequence(eci) || !eci.readOidString(innerType)
                            || !eci.readSequence(algo) || !algo.readOidString(algoOid))
                        {
                            return ERET_BADREQ;
                        }
                    }

                    if (algoOid.compare(OID_PBES2) != 0) {
                        return ERET_NOTSUP; // the legacy PKCS#12 PBES1 ciphers land here.
                    }

                    CTag paramsTag;
                    SReadOnlyByteSpan params;
                    if (!algo.readNextElement(paramsTag, params) || paramsTag != CTag::SEQ) {
                        return ERET_BADREQ;
                    }

                    SPbes2 spec;
                    ERetCode parsed = parsePbes2(params, spec);
                    if (parsed != ERET_OK) {
                        return parsed;
                    }

                    // encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL -- implicit, so the
                    // context tag replaces the OCTET STRING's own and the content is the
                    // ciphertext directly. Reading it as a nested OCTET STRING finds garbage.
                    CTag ctTag;
                    SReadOnlyByteSpan ciphertext;
                    if (!eci.readNextElement(ctTag, ciphertext)
                        || ctTag.tagClass() != EATAG_CONTEXT_SPECIFIC || ctTag.value() != 0
                        || ciphertext.size == 0)
                    {
                        return ERET_BADREQ;
                    }

                    CBuffer plain;
                    if (pbes2Transform(false, spec, password, ciphertext, plain) != ERET_OK) {
                        return ERET_KEY_ERROR;
                    }

                    const bool read = readSafeContents(plain.toSpan(), bags);

                    // Wiped whether or not the parse succeeded: an encrypted SafeContents may
                    // hold a plain `keyBag`, and the reason it was encrypted is that its content
                    // is not meant to be lying around.
                    CSecure::zero(SByteSpan(plain.toPtr(), plain.size()));

                    if (!read) {
                        return ERET_BADREQ;
                    }
                } else {
                    // envelopedData: public-key privacy mode, which needs a recipient's key
                    // rather than a password.
                    return ERET_NOTSUP;
                }
            }
        }

        // --- Bags into entries. Certificates first, then keys attached by localKeyId, which is
        // the only thing in the format that pairs the two. ---
        CCertCollection staged;
        ERetCode result = ERET_OK;

        for (size_t i = 0; i < bags.size() && result == ERET_OK; ++i) {
            const SBag& bag = bags[i];
            if (bag.bagId.compare(OID_CERT_BAG) != 0) {
                continue;
            }

            COctet der;
            if (!readCertBag(bag.bagValue.toSpan(), der)) {
                // An SDSI or otherwise unrecognised certBag is skipped rather than fatal: a
                // container may carry one alongside the X.509 ones this library handles.
                continue;
            }

            SCertEntry entry;
            if (entry.cert.importDer(der) != ERET_OK) {
                result = ERET_BADREQ;
                break;
            }

            entry.friendlyName = bag.friendlyName;
            entry.localKeyId = bag.localKeyId;

            size_t index = 0;
            result = staged.add(entry, index);
        }

        for (size_t i = 0; i < bags.size() && result == ERET_OK; ++i) {
            const SBag& bag = bags[i];
            const bool shrouded = bag.bagId.compare(OID_SHROUDED_KEY_BAG) == 0;
            const bool plain = bag.bagId.compare(OID_KEY_BAG) == 0;
            if (!shrouded && !plain) {
                continue;
            }

            crypto::IPrivateKeyPtr key;
            if (shrouded) {
                result = readShroudedKeyBag(bag.bagValue.toSpan(), password, key);
            } else {
                // keyBag: a PKCS#8 PrivateKeyInfo in the clear. Legal, and read, because the
                // container as a whole may still have been encrypted at the SafeContents level --
                // which the pkcs7-encryptedData branch above has already undone by now.
                CReader holder(bag.bagValue.toSpan(), EAENC_DER);
                CTag tag;
                SReadOnlyByteSpan inner;
                if (!holder.readNextElement(tag, inner) || tag != CTag::SEQ) {
                    result = ERET_BADREQ;
                } else {
                    result = CCert::importPkcs8PrivateKey(bag.bagValue.toSpan(), key);
                }
            }

            if (result != ERET_OK) {
                // Including ERET_NOTSUP, for a key whose algorithm this library has no PKCS#8
                // encoding for. Dropping it and keeping the certificates was the other option
                // and is the wrong one: `IChainFormat::load()` promises a collection that is
                // either fully populated or untouched, and a container that quietly came back
                // without its private key is the half-populated case wearing a success code.
                // A caller who wants the certificates anyway can read them from a PEM export.
                break;
            }
            if (!key) {
                continue;
            }

            const size_t index = bag.localKeyId.empty()
                ? CCertCollection::NOT_FOUND
                : staged.findByLocalKeyId(bag.localKeyId.toSpan());

            if (index != CCertCollection::NOT_FOUND) {
                result = staged.attachPrivateKey(index, key);
            } else if (staged.count() == 1) {
                // No localKeyId, or one that matches nothing, but exactly one certificate in the
                // container -- the pairing is unambiguous even without the attribute, and a
                // single-certificate PFX written without one is common enough to be worth
                // handling. With more than one certificate the key is dropped rather than
                // guessed at: attaching it to the wrong certificate would fail at first use,
                // somewhere far away from here.
                result = staged.attachPrivateKey(0, key);
            }
        }

        if (result != ERET_OK) {
            return result;
        }

        // Appended only now, so a failure anywhere above leaves `out` as it was rather than
        // half-populated -- which is what IChainFormat::load() promises.
        for (size_t i = 0; i < staged.count(); ++i) {
            SCertEntry entry;
            if (staged.at(i, entry) != ERET_OK) {
                return ERET_UNKNOWN;
            }

            size_t index = 0;
            const ERetCode added = out.add(entry, index);
            if (added != ERET_OK) {
                return added;
            }
        }

        return ERET_OK;
    }

    /* Writes a collection out as a PFX. */
    ERetCode CPfxFormat::save(
        const CCertCollection& in, const SReadOnlyByteSpan& password, CBuffer& out
    ) const {
        out.clear();

        if (in.empty()) {
            return ERET_BADREQ;
        }
        if (!password.data || password.size == 0) {
            // needsPassword() is true for this format, and an empty password would produce a
            // container with the shape of protection and none of it.
            return ERET_BADREQ;
        }

        // The BMPString form is only needed at the very end, for the MAC key -- but a password
        // with no BMPString form has to fail *before* several hundred thousand PBKDF2 iterations
        // rather than after them. So it is checked here and built again where it is used: that
        // keeps it out of scope across the dozen error returns in between, which is a dozen wipes
        // not written and therefore a dozen that cannot be forgotten when a branch is added.
        {
            CBuffer probe;
            const bool encodable = toBmpPassword(password, probe);
            CSecure::zero(SByteSpan(probe.toPtr(), probe.size()));

            if (!encodable) {
                return ERET_BADREQ;
            }
        }

        // --- The certificate bags, and the key bags, as two SafeContents bodies. ---
        CBuffer certBags, keyBags;
        ERetCode result = ERET_OK;

        for (size_t i = 0; i < in.count() && result == ERET_OK; ++i) {
            SCertEntry entry;
            result = in.at(i, entry);
            if (result != ERET_OK) {
                break;
            }

            COctet der;
            result = entry.cert.exportDer(der);
            if (result != ERET_OK) {
                break;
            }

            // A key with no localKeyId gets one, because the attribute is the only thing that
            // pairs the two bags on the way back in. The certificate's SHA-1 thumbprint is what
            // OpenSSL uses, so a container written here and read there pairs the same way.
            COctet localKeyId = entry.localKeyId;
            if (localKeyId.empty() && entry.hasPrivateKey()) {
                localKeyId = entry.cert.thumbprint();
                if (localKeyId.empty()) {
                    result = ERET_UNKNOWN;
                    break;
                }
            }

            // CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
            CBuffer certValue, certBagBody, certBagSeq;
            if (!CDer::appendTlv(certValue, CTag::STRING_OCTET, der.toSpan())
                || !appendOid(certBagBody, OID_X509_CERTIFICATE)
                || !CDer::appendTlv(certBagBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true),
                                    certValue.toSpan())
                || !CDer::appendSequence(certBagSeq, certBagBody.toSpan())
                || !appendSafeBag(certBags, OID_CERT_BAG, certBagSeq.toSpan(),
                                  entry.friendlyName, localKeyId))
            {
                result = ERET_NOMEM;
                break;
            }

            if (!entry.hasPrivateKey()) {
                continue;
            }

            COctet pkcs8;
            result = CCert::exportPkcs8PrivateKey(entry.privateKey, pkcs8);
            if (result != ERET_OK) {
                break; // ERET_NOTSUP for a key with no PKCS#8 form this library writes.
            }

            SPbes2 spec;
            spec.prf = MAC_HASH;
            spec.iterations = _iterations;
            spec.keyBytes = AES256_KEY_BYTES;

            CBuffer encrypted;
            if (!spec.salt.resize(SALT_BYTES) || !spec.iv.resize(CBC_IV_BYTES)
                || crypto::CRng::fill(spec.salt.toSpan()) != ERET_OK
                || crypto::CRng::fill(spec.iv.toSpan()) != ERET_OK)
            {
                result = ERET_UNKNOWN;
            } else {
                result = pbes2Transform(true, spec, password, pkcs8.toSpan(), encrypted);
            }

            // The PKCS#8 blob is the private key in the clear; wipe it whether or not the
            // encryption succeeded.
            CSecure::zero(SByteSpan(const_cast<uint8_t*>(pkcs8.toPtr()), pkcs8.size()));

            if (result != ERET_OK) {
                break;
            }

            // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgId,
            //                                        encryptedData OCTET STRING }
            CBuffer epkiBody, epkiSeq;
            if (!appendPbes2AlgoId(epkiBody, spec)
                || !CDer::appendTlv(epkiBody, CTag::STRING_OCTET, encrypted.toSpan())
                || !CDer::appendSequence(epkiSeq, epkiBody.toSpan())
                || !appendSafeBag(keyBags, OID_SHROUDED_KEY_BAG, epkiSeq.toSpan(),
                                  entry.friendlyName, localKeyId))
            {
                result = ERET_NOMEM;
                break;
            }
        }

        if (result != ERET_OK) {
            return result;
        }

        // --- AuthenticatedSafe: the certificates as a pkcs7-encryptedData, the keys as
        // pkcs7-data (each key bag carries its own encryption already). ---
        CBuffer authSafeBody;
        {
            CBuffer certContents;
            if (!CDer::appendSequence(certContents, certBags.toSpan())) {
                return ERET_NOMEM;
            }

            SPbes2 spec;
            spec.prf = MAC_HASH;
            spec.iterations = _iterations;
            spec.keyBytes = AES256_KEY_BYTES;

            CBuffer encrypted;
            if (!spec.salt.resize(SALT_BYTES) || !spec.iv.resize(CBC_IV_BYTES)
                || crypto::CRng::fill(spec.salt.toSpan()) != ERET_OK
                || crypto::CRng::fill(spec.iv.toSpan()) != ERET_OK)
            {
                return ERET_UNKNOWN;
            }

            result = pbes2Transform(true, spec, password, certContents.toSpan(), encrypted);
            if (result != ERET_OK) {
                return result;
            }

            // EncryptedContentInfo ::= SEQUENCE { contentType OID,
            //     contentEncryptionAlgorithm AlgId, encryptedContent [0] IMPLICIT OCTET STRING }
            CBuffer eciBody;
            if (!appendOid(eciBody, OID_PKCS7_DATA)
                || !appendPbes2AlgoId(eciBody, spec)
                || !CDer::appendTlv(eciBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, false),
                                    encrypted.toSpan()))
            {
                return ERET_NOMEM;
            }

            CBuffer edBody, edSeq, infoBody;
            if (!appendInteger(edBody, 0)
                || !CDer::appendSequence(edBody, eciBody.toSpan())
                || !CDer::appendSequence(edSeq, edBody.toSpan())
                || !appendOid(infoBody, OID_PKCS7_ENCRYPTED_DATA)
                || !CDer::appendTlv(infoBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), edSeq.toSpan())
                || !CDer::appendSequence(authSafeBody, infoBody.toSpan()))
            {
                return ERET_NOMEM;
            }
        }

        if (keyBags.size() != 0) {
            CBuffer keyContents, octet, infoBody;
            if (!CDer::appendSequence(keyContents, keyBags.toSpan())
                || !CDer::appendTlv(octet, CTag::STRING_OCTET, keyContents.toSpan())
                || !appendOid(infoBody, OID_PKCS7_DATA)
                || !CDer::appendTlv(infoBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), octet.toSpan())
                || !CDer::appendSequence(authSafeBody, infoBody.toSpan()))
            {
                return ERET_NOMEM;
            }
        }

        CBuffer authenticated;
        if (!CDer::appendSequence(authenticated, authSafeBody.toSpan())) {
            return ERET_NOMEM;
        }

        // --- MacData over exactly those bytes. ---
        crypto::IHasherPtr probe;
        if (crypto::IHasher::create(MAC_HASH, probe) != ERET_OK || !probe) {
            return ERET_NOTSUP;
        }

        const size_t macBytes = probe->byteWidth();
        const char* macOid = digestOidOf(MAC_HASH);
        if (macBytes == 0 || macBytes > MAX_DIGEST_BYTES || !macOid) {
            return ERET_NOTSUP;
        }

        uint8_t macSalt[SALT_BYTES];
        uint8_t macKey[MAX_DIGEST_BYTES];
        uint8_t mac[MAX_DIGEST_BYTES];
        bool computed = false;

        // Built here rather than at the top of the method -- see the check up there for why.
        // RFC 7292 section 4: the MAC key is the Appendix B KDF with ID=3 over the BMPString
        // password, where everything above used the raw password bytes through PBES2.
        {
            CBuffer bmp;
            if (crypto::CRng::fill(SByteSpan(macSalt, sizeof(macSalt))) == ERET_OK
                && toBmpPassword(password, bmp)
                && p12Kdf(MAC_HASH, bmp.toSpan(), SReadOnlyByteSpan(macSalt, sizeof(macSalt)),
                          _iterations, SByteSpan(macKey, macBytes), 3))
            {
                computed = crypto::CHmac::compute(
                    MAC_HASH, SReadOnlyByteSpan(macKey, macBytes), authenticated.toSpan(),
                    SByteSpan(mac, macBytes)) == ERET_OK;
            }

            CSecure::zero(SByteSpan(bmp.toPtr(), bmp.size()));
        }

        CSecure::zero(SByteSpan(macKey, sizeof(macKey)));

        if (!computed) {
            CSecure::zero(SByteSpan(mac, sizeof(mac)));
            return ERET_UNKNOWN;
        }

        // --- PFX ::= SEQUENCE { version 3, authSafe ContentInfo, macData MacData } ---
        CBuffer macAlgoNull, macAlgoId, digestInfoBody, digestInfoSeq, macDataBody;
        bool built =
            CDer::appendTlv(macAlgoNull, CTag::NULL_, SReadOnlyByteSpan(nullptr, 0))
            && appendAlgoId(macAlgoId, macOid, macAlgoNull.toSpan())
            && CDer::appendRaw(digestInfoBody, macAlgoId.toSpan())
            && CDer::appendTlv(digestInfoBody, CTag::STRING_OCTET,
                               SReadOnlyByteSpan(mac, macBytes))
            && CDer::appendSequence(digestInfoSeq, digestInfoBody.toSpan())
            && CDer::appendRaw(macDataBody, digestInfoSeq.toSpan())
            && CDer::appendTlv(macDataBody, CTag::STRING_OCTET,
                               SReadOnlyByteSpan(macSalt, sizeof(macSalt)))
            && appendInteger(macDataBody, _iterations);

        CSecure::zero(SByteSpan(mac, sizeof(mac)));

        if (!built) {
            return ERET_NOMEM;
        }

        CBuffer authOctet, authInfoBody, pfxBody;
        if (!CDer::appendTlv(authOctet, CTag::STRING_OCTET, authenticated.toSpan())
            || !appendOid(authInfoBody, OID_PKCS7_DATA)
            || !CDer::appendTlv(authInfoBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true),
                                authOctet.toSpan())
            || !appendInteger(pfxBody, 3)
            || !CDer::appendSequence(pfxBody, authInfoBody.toSpan())
            || !CDer::appendSequence(pfxBody, macDataBody.toSpan())
            || !CDer::appendSequence(out, pfxBody.toSpan()))
        {
            out.clear();
            return ERET_NOMEM;
        }

        return ERET_OK;
    }

} // namespace x509
} // namespace certpp
