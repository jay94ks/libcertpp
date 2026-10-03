#ifndef __INCLUDE_CERTPP_CRYPTO_HASHER_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHER_HPP__

#include <certpp/common.hpp>
#include <certpp/io/octet.hpp>

namespace certpp {
namespace crypto {

    /**
     * The hash algorithms this library implements (see crypto/hashers/ for each concrete
     * IHasher). Used to select which hasher IHasher::create() constructs, and to identify a
     * digest algorithm throughout the crypto/x509 modules (e.g. a certificate's own signature
     * digest, or RSASSA-PSS's hash/MGF1 parameters).
     */
    enum EHashers {
        EHASH_UNKNOWN = 0,

        EHASH_MD5,         /**< MD5 hash algorithm */
        EHASH_SHA1,        /**< SHA-1 hash algorithm */
        EHASH_SHA224,      /**< SHA-224 hash algorithm */
        EHASH_SHA256,      /**< SHA-256 hash algorithm */
        EHASH_SHA384,      /**< SHA-384 hash algorithm */
        EHASH_SHA512,      /**< SHA-512 hash algorithm */
        EHASH_SHA3_256,    /**< SHA3-256 hash algorithm (FIPS 202) */
        EHASH_SHA3_512,    /**< SHA3-512 hash algorithm (FIPS 202) */
        EHASH_SHAKE128,    /**< SHAKE-128 hash algorithm */
        EHASH_SHAKE256,    /**< SHAKE-256 hash algorithm */

        // --> New hashers are appended here, never inserted above, even where grouping them with
        // a relative would read better -- MD4 belongs next to MD5 by every measure except the
        // one that counts. This library ships as a shared object and is consumed as an installed
        // package, so these values cross an ABI boundary: inserting MD4 at the top, as it
        // originally was, moved EHASH_SHA256 from 4 to 5, and a caller compiled against the
        // older header would then have gone on passing 4 and silently got SHA-224. Nothing
        // inside this repository persists or casts these numbers, which is what makes the
        // mistake invisible from in here.
        EHASH_MD4,         /**< MD4 hash algorithm (broken; legacy interop only) */

        /** Marker for the maximum value of EHashers. */
        EHASH_MAX
    };

    /**
     * Forward declaration of the hasher interface.
     */
    class IHasher;

    /**
     * Shared pointer type for the hasher interface.
     */
    using IHasherPtr = std::shared_ptr<IHasher>;

    /**
     * Interface for cryptographic hash functions.
     */
    class CERTPP_API IHasher {
    private:
        size_t _byteWidth;

    public:
        /**
         * Constructor for the hasher interface.
         *
         * @param byteWidth The byte width of the hash output.
         */
        IHasher(size_t byteWidth) : _byteWidth(byteWidth) {}

        /**
         * Destructor for the hasher interface.
         */
        virtual ~IHasher() = default;

        /**
         * Creates a hasher instance based on the specified built-in hasher type.
         *
         * @param hasherType The type of the built-in hasher to create.
         * @param out The shared pointer to store the created hasher instance.
         * @return An error code indicating the success or failure of the creation.
         */
        static ERetCode create(EHashers hasherType, IHasherPtr& out);

    public:
        /**
         * Returns the byte width of the hash output.
         *
         * @return The byte width of the hash output.
         */
        inline size_t byteWidth() const { return _byteWidth; }

        /**
         * Resets the hasher to its initial state.
         */
        virtual void reset() = 0;

        /**
         * Pushes data into the hasher.
         *
         * @param buf The data to be hashed.
         * @return The number of bytes successfully pushed.
         */
        virtual size_t push(const SReadOnlyByteSpan& buf) = 0;

        /**
         * Finalizes the hash computation and writes the result to the output buffer.
         *
         * @param out The buffer to store the final hash.
         * @return True if the hash was successfully finalized, false otherwise.
         */
        virtual bool finish(const SByteSpan& out) = 0;
    };

} // namespace crypto
} // namespace certpp

#endif
