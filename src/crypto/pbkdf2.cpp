#include <certpp/crypto/pbkdf2.hpp>
#include <certpp/crypto/hmac.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* The largest digest any hash HMAC covers produces (SHA-512, SHA3-512). */
        constexpr size_t MAX_DIGEST_BYTES = 64;

        /* The output length of a hash, without constructing one -- the same two-step lookup
         * src/crypto/hkdf.cpp uses, and for the same reason: HMAC already knows which hashes it
         * covers, so ask it before building an instance. */
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

    /* PBKDF2 (RFC 8018 5.2). */
    ERetCode CPbkdf2::derive(
        EHashers hasherType, const SReadOnlyByteSpan& password,
        const SReadOnlyByteSpan& salt, uint32_t iterations, const SByteSpan& out
    ) {
        const size_t digestBytes = digestBytesOf(hasherType);
        if (digestBytes == 0 || digestBytes > MAX_DIGEST_BYTES) {
            return ERET_NOTSUP;
        }

        // RFC 8018 5.2 defines c as a positive integer. Treating 0 as "skip the stretching"
        // would leave T(i) as the XOR of no values at all, and -- far worse -- would turn a
        // zeroed-out or absent iteration count in a parsed container into a derivation an
        // attacker can run for free.
        if (iterations == 0) {
            return ERET_BADREQ;
        }
        if (out.size == 0 || !out.data) {
            return ERET_BADREQ;
        }
        if (out.size > maxDeriveBytes(hasherType)) {
            // INT(i) is 32 bits. Past this length the counter wraps back to 1 and the output
            // starts repeating itself, so the bound is a correctness requirement and not just a
            // sanity check on an absurd request.
            return ERET_BADREQ;
        }
        if ((password.size != 0 && !password.data) || (salt.size != 0 && !salt.data)) {
            return ERET_BADREQ;
        }

        // One CHmac for the whole derivation: re-keying it with the same algorithm reuses the
        // underlying hasher, which matters here far more than it does for HKDF -- this loop runs
        // `iterations` times per block, and an allocation per iteration would dominate the cost
        // of the hashing it is supposed to be paying for.
        CHmac mac;

        uint8_t accumulator[MAX_DIGEST_BYTES];      // --> T(i), the running XOR.
        uint8_t previous[MAX_DIGEST_BYTES];         // --> U(j), the previous HMAC's output.
        size_t written = 0;
        ERetCode result = ERET_OK;

        for (uint32_t block = 1; written < out.size; ++block) {
            // U(1) = PRF(password, salt || INT(block)), with INT(block) big-endian. Only this
            // first HMAC of the block sees the salt at all.
            result = mac.reset(hasherType, password);
            if (result != ERET_OK) {
                break;
            }

            if (salt.size != 0 && mac.push(salt) != salt.size) {
                result = ERET_HASH_PIPE;
                break;
            }

            const uint8_t counter[4] = {
                uint8_t((block >> 24) & 0xFF), uint8_t((block >> 16) & 0xFF),
                uint8_t((block >> 8) & 0xFF),  uint8_t(block & 0xFF),
            };
            if (mac.push(SReadOnlyByteSpan(counter, sizeof(counter))) != sizeof(counter)) {
                result = ERET_HASH_PIPE;
                break;
            }

            if (!mac.finish(SByteSpan(previous, digestBytes))) {
                result = ERET_HASH_PIPE;
                break;
            }

            std::memcpy(accumulator, previous, digestBytes);

            // U(j) = PRF(password, U(j-1)), accumulated into T(i) by XOR. Keeping only the last
            // U instead of XOR-ing all of them costs exactly the same and matches no other
            // implementation -- RFC 6070's vectors are what catch it.
            for (uint32_t round = 1; round < iterations; ++round) {
                result = mac.reset(hasherType, password);
                if (result != ERET_OK) {
                    break;
                }

                if (mac.push(SReadOnlyByteSpan(previous, digestBytes)) != digestBytes) {
                    result = ERET_HASH_PIPE;
                    break;
                }

                if (!mac.finish(SByteSpan(previous, digestBytes))) {
                    result = ERET_HASH_PIPE;
                    break;
                }

                for (size_t i = 0; i < digestBytes; ++i) {
                    accumulator[i] ^= previous[i];
                }
            }

            if (result != ERET_OK) {
                break;
            }

            const size_t remaining = out.size - written;
            const size_t take = (remaining < digestBytes) ? remaining : digestBytes;

            std::memcpy(out.data + written, accumulator, take);
            written += take;
        }

        // Both hold key material. `accumulator` is a whole block of the derived key, and the
        // final block is usually truncated on the way out, so the bytes not taken exist nowhere
        // else; `previous` is the last U value, from which an attacker who also knows the salt
        // can finish the derivation.
        CSecure::zero(SByteSpan(accumulator, sizeof(accumulator)));
        CSecure::zero(SByteSpan(previous, sizeof(previous)));

        return result;
    }

    /* (2^32 - 1) * hLen, saturated to size_t. */
    size_t CPbkdf2::maxDeriveBytes(EHashers hasherType) {
        const size_t digestBytes = digestBytesOf(hasherType);
        if (digestBytes == 0) {
            return 0;
        }

        // Computed in 64 bits and clamped, because on a 32-bit size_t the real bound does not
        // fit -- and a bound that silently wrapped would be no bound.
        const uint64_t limit = uint64_t(0xFFFFFFFFu) * uint64_t(digestBytes);
        const uint64_t ceiling = uint64_t(size_t(-1));

        return (limit > ceiling) ? size_t(-1) : size_t(limit);
    }

} // namespace crypto
} // namespace certpp
