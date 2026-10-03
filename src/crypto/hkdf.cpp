#include <certpp/crypto/hkdf.hpp>
#include <certpp/crypto/hmac.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* The largest digest any hash HMAC covers produces (SHA-512, SHA3-512). */
        constexpr size_t MAX_DIGEST_BYTES = 64;

        /* The output length of a hash, without constructing one: HMAC already has to know which
         * hashes it supports, so this asks it first and only then builds an instance. */
        size_t digestBytesOf(EHashers hasherType) {
            if (CHmac::blockBytesOf(hasherType) == 0) {
                return 0;
            }

            IHasherPtr hasher;
            if (IHasher::create(hasherType, hasher) != ERET_OK || !hasher) {
                return 0;
            }

            return hasher->byteWidth();
        }

    } // namespace

    /* HKDF-Extract (RFC 5869 2.2). */
    ERetCode CHkdf::extract(
        EHashers hasherType, const SReadOnlyByteSpan& salt,
        const SReadOnlyByteSpan& inputKey, const SByteSpan& out
    ) {
        const size_t digestBytes = digestBytesOf(hasherType);
        if (digestBytes == 0) {
            return ERET_NOTSUP;
        }
        if (out.size != digestBytes || !out.data) {
            return ERET_NOSPC;
        }
        if (digestBytes > MAX_DIGEST_BYTES) {
            return ERET_NOTSUP;
        }

        // RFC 5869 2.2: "if not provided, [salt] is set to a string of HashLen zeros". An empty
        // span and a span of zeros therefore derive the same key, which is the specified
        // behaviour rather than an accident.
        uint8_t zeroSalt[MAX_DIGEST_BYTES] = { 0 };
        const SReadOnlyByteSpan effectiveSalt = (salt.size == 0)
            ? SReadOnlyByteSpan(zeroSalt, digestBytes)
            : salt;

        // --> The salt is the HMAC *key* and the input keying material is the *message*. That
        // ordering looks inverted, and swapping them produces output that is self-consistent and
        // matches no other implementation -- RFC 5869's own test vectors are the only thing that
        // catches it.
        return CHmac::compute(hasherType, effectiveSalt, inputKey, out);
    }

    /* HKDF-Expand (RFC 5869 2.3). */
    ERetCode CHkdf::expand(
        EHashers hasherType, const SReadOnlyByteSpan& pseudoKey,
        const SReadOnlyByteSpan& info, const SByteSpan& out
    ) {
        const size_t digestBytes = digestBytesOf(hasherType);
        if (digestBytes == 0) {
            return ERET_NOTSUP;
        }
        if (digestBytes > MAX_DIGEST_BYTES) {
            return ERET_NOTSUP;
        }
        if (out.size == 0 || !out.data) {
            return ERET_BADREQ;
        }
        if (out.size > 255 * digestBytes) {
            return ERET_BADREQ; // the counter is one byte, so 255 blocks is the hard ceiling
        }
        if (pseudoKey.size < digestBytes || !pseudoKey.data) {
            return ERET_BADREQ; // RFC 5869 2.3 requires at least HashLen bytes of key
        }
        if (info.size != 0 && !info.data) {
            return ERET_BADREQ;
        }

        // One CHmac for the whole loop: re-keying it with the same algorithm reuses the hasher,
        // so a long expansion does not allocate per block.
        CHmac mac;

        uint8_t previous[MAX_DIGEST_BYTES];
        uint8_t block[MAX_DIGEST_BYTES];
        size_t previousBytes = 0;
        size_t written = 0;
        ERetCode result = ERET_OK;

        for (uint32_t counter = 1; written < out.size; ++counter) {
            result = mac.reset(hasherType, pseudoKey);
            if (result != ERET_OK) {
                break;
            }

            // T(n) = HMAC(prk, T(n-1) || info || n). T(0) is empty, so the first block omits the
            // previous one -- and every block after it chains, which is the detail that makes
            // the output a stream rather than 255 independent digests.
            if (previousBytes != 0
                && mac.push(SReadOnlyByteSpan(previous, previousBytes)) != previousBytes)
            {
                result = ERET_HASH_PIPE;
                break;
            }
            if (info.size != 0 && mac.push(info) != info.size) {
                result = ERET_HASH_PIPE;
                break;
            }

            const uint8_t counterByte = uint8_t(counter);
            if (mac.push(SReadOnlyByteSpan(&counterByte, 1)) != 1) {
                result = ERET_HASH_PIPE;
                break;
            }

            if (!mac.finish(SByteSpan(block, digestBytes))) {
                result = ERET_HASH_PIPE;
                break;
            }

            const size_t take = (out.size - written < digestBytes)
                ? (out.size - written)
                : digestBytes;

            std::memcpy(out.data + written, block, take);
            written += take;

            std::memcpy(previous, block, digestBytes);
            previousBytes = digestBytes;
        }

        // Both hold key-derived material -- `previous` is a full output block, and the last one
        // may have been truncated on the way out, so the untaken bytes exist nowhere else.
        CSecure::zero(SByteSpan(previous, sizeof(previous)));
        CSecure::zero(SByteSpan(block, sizeof(block)));

        return result;
    }

    /* Extract then expand. */
    ERetCode CHkdf::derive(
        EHashers hasherType, const SReadOnlyByteSpan& salt,
        const SReadOnlyByteSpan& inputKey, const SReadOnlyByteSpan& info,
        const SByteSpan& out
    ) {
        const size_t digestBytes = digestBytesOf(hasherType);
        if (digestBytes == 0) {
            return ERET_NOTSUP;
        }
        if (digestBytes > MAX_DIGEST_BYTES) {
            return ERET_NOTSUP;
        }

        uint8_t pseudoKey[MAX_DIGEST_BYTES];

        ERetCode result = extract(
            hasherType, salt, inputKey, SByteSpan(pseudoKey, digestBytes));

        if (result == ERET_OK) {
            result = expand(
                hasherType, SReadOnlyByteSpan(pseudoKey, digestBytes), info, out);
        }

        CSecure::zero(SByteSpan(pseudoKey, sizeof(pseudoKey)));
        return result;
    }

    /* 255 * the hash's output length. */
    size_t CHkdf::maxExpandBytes(EHashers hasherType) {
        const size_t digestBytes = digestBytesOf(hasherType);
        return digestBytes == 0 ? 0 : 255 * digestBytes;
    }

} // namespace crypto
} // namespace certpp
