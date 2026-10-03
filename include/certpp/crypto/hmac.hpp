#ifndef __INCLUDE_CERTPP_CRYPTO_HMAC_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HMAC_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * HMAC (RFC 2104), keyed-hash message authentication over any of this library's fixed-output
     * hashers.
     *
     * `H((K ^ opad) || H((K ^ ipad) || text))`, where the key is hashed down if it is longer than
     * the hash's block size and zero-padded up if shorter. Not an `IHasher`: HMAC is keyed, and
     * `IHasher::create()` has nowhere to put a key.
     *
     * The streaming shape mirrors `IHasher` -- `reset()` to key it, `push()` as often as needed,
     * `finish()` for the tag -- and re-keying an existing instance reuses the underlying hasher
     * rather than allocating a new one, so a loop like HKDF's expand does not allocate per block.
     *
     * **Compare tags with `verify()`, not `finish()` plus `memcmp`.** A MAC comparison that
     * stops at the first differing byte leaks how long a prefix the attacker guessed correctly,
     * which is enough to forge a tag a byte at a time. `verify()` goes through
     * `CSecure::equalsMask`.
     *
     * SHAKE128/SHAKE256 are rejected: they are XOFs with a caller-chosen output length, and RFC
     * 2104 is defined over a fixed-output hash. SHA3-256 and SHA3-512 are accepted, using their
     * sponge rate as the block size -- though for SHA-3, KMAC (SP 800-185) is the construction
     * NIST actually recommends, and HMAC-SHA3 exists here only for completeness.
     *
     * BLAKE2s is accepted too, at its own 64-byte block -- but note that BLAKE2 has a *native*
     * keyed mode (`CBlake2sMac`, crypto/blake2smac.hpp) which is a different function from HMAC
     * over the same hash, and protocols differ about which one they mean. WireGuard, for one, uses
     * both: HMAC-BLAKE2s for its HKDF, the native keyed mode for its `MAC()`.
     *
     * The block sizes live in this class rather than on `IHasher`, which exposes only
     * `byteWidth()`. That is a deliberate trade: adding the block size to `IHasher` would mean
     * changing its constructor and every one of its implementations, and HMAC is currently
     * the only thing that needs it. The cost is that a hasher added later is simply unsupported
     * here until someone extends `blockBytesOf()` -- which fails loudly at `reset()` rather than
     * silently computing a wrong tag. If a second consumer ever needs the block size, it should
     * move onto `IHasher` instead of being duplicated.
     */
    class CERTPP_API CHmac {
    private:
        IHasherPtr _hasher;
        EHashers _algorithm;
        size_t _blockBytes;
        uint8_t _key[136];   // --> the padded key, block-sized; 136 is the largest block (SHA3-256).

    public:
        /** The largest block size any supported hash uses: SHA3-256's 136-byte rate. */
        static constexpr size_t MAX_BLOCK_BYTES = 136;

    public:
        /**
         * Constructs an unkeyed instance; call reset() before pushing anything.
         */
        CHmac();

        /**
         * Destructor; clears the padded key.
         */
        ~CHmac();

        CHmac(const CHmac&) = delete;
        CHmac& operator=(const CHmac&) = delete;

    public:
        /**
         * The block size RFC 2104 uses for a given hash, in bytes.
         * @param hasherType The hash algorithm.
         * @return 64 for MD5/SHA-1/SHA-224/SHA-256 and BLAKE2s, 128 for SHA-384/SHA-512, the
         * sponge rate for SHA3-256 (136) and SHA3-512 (72), and 0 for anything HMAC is not
         * defined over.
         */
        static size_t blockBytesOf(EHashers hasherType);

        /**
         * Keys this instance and starts a fresh message. May be called repeatedly; the
         * underlying hasher is reused when the algorithm is unchanged.
         * @param hasherType The hash to run HMAC over.
         * @param key The key; any length, including empty.
         * @return ERET_OK on success; ERET_NOTSUP if HMAC is not defined over hasherType;
         * another ERetCode on failure.
         */
        ERetCode reset(EHashers hasherType, const SReadOnlyByteSpan& key);

        /**
         * @return The tag length in bytes, which is the hash's own output length; 0 before
         * reset() has succeeded.
         */
        size_t byteWidth() const;

        /**
         * Absorbs message bytes.
         * @param buf The data to authenticate.
         * @return The number of bytes absorbed; 0 if this instance is not keyed.
         */
        size_t push(const SReadOnlyByteSpan& buf);

        /**
         * Finalizes and writes the tag.
         *
         * Like `IHasher::finish()` this is a query -- it works on a copy of the state, so it may
         * be called more than once and absorption can continue afterwards.
         * @param out Exactly byteWidth() bytes.
         * @return true on success.
         */
        bool finish(const SByteSpan& out);

        /**
         * One-shot HMAC.
         * @param hasherType The hash to run HMAC over.
         * @param key The key.
         * @param message The message.
         * @param out Exactly the hash's output length.
         * @return ERET_OK on success.
         */
        static ERetCode compute(
            EHashers hasherType, const SReadOnlyByteSpan& key,
            const SReadOnlyByteSpan& message, const SByteSpan& out
        );

        /**
         * One-shot HMAC verification, comparing in time that depends only on the tag's length.
         *
         * This is the entry point to use when checking a received tag; see this class's doc
         * comment for why a `memcmp` there is a forgery oracle.
         * @param hasherType The hash to run HMAC over.
         * @param key The key.
         * @param message The message.
         * @param tag The tag to check; may be shorter than the full output, in which case only
         * that many leading bytes are compared (RFC 2104 4's truncation).
         * @return true if the tag matches.
         */
        static bool verify(
            EHashers hasherType, const SReadOnlyByteSpan& key,
            const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& tag
        );
    };

} // namespace crypto
} // namespace certpp

#endif
