#ifndef __INCLUDE_CERTPP_CRYPTO_SYM_HPP__
#define __INCLUDE_CERTPP_CRYPTO_SYM_HPP__

#include <certpp/common.hpp>
#include <certpp/crypto/keys.hpp>
#include <certpp/crypto/transform.hpp>
#include <certpp/io/buffer.hpp>

namespace certpp {
namespace crypto {

    /**
     * How a block cipher mode treats the final, possibly partial, block.
     */
    enum ESymPaddings {
        /**
         * PKCS#7 (RFC 5652 6.3), the default: encrypting always appends a padding block --
         * between 1 and one full block of bytes, every one of them holding that count -- so the
         * ciphertext is always longer than the plaintext and always ends on a block boundary;
         * decrypting locates and strips it, and rejects a ciphertext whose padding is malformed.
         */
        ESYMPAD_PKCS7 = 0,

        /**
         * No padding at all: the plaintext must already be a whole number of blocks, and the
         * ciphertext is exactly as long as it. Finalizing with a partial block left over fails
         * rather than padding it.
         *
         * This is what a protocol that does its own padding needs -- IKEv2 (RFC 7296 3.14)
         * builds its own pad-length-terminated padding into the payload before encrypting, so a
         * PKCS#7 block added underneath it would be a second, unexpected one.
         */
        ESYMPAD_NONE,
    };

    /**
     * Forward declaration of the ISymmetric interface.
     */
    class ISymmetric;

    /**
     * Shared pointer type for the ISymmetric interface.
     */
    using ISymmetricPtr = std::shared_ptr<ISymmetric>;

    /**
     * Forward declaration of the ISymmetricContext interface.
     */
    class ISymmetricContext;

    /**
     * Forward declaration of the ISymmetricTransformer interface.
     */
    class ISymmetricTransformer; 

    /**
     * Shared pointer type for the ISymmetricContext interface.
     */
    using ISymmetricContextPtr = std::shared_ptr<ISymmetricContext>;

    /**
     * Shared pointer type for the ISymmetricTransformer interface.
     */
    using ISymmetricTransformerPtr = std::shared_ptr<ISymmetricTransformer>;

    /**
     * Interface for symmetric cryptographic algorithms.
     */
    class CERTPP_API ISymmetric {
    private:
        TArray<SKeySizeSpec> _keySizes;

    public:
        /**
         * Retrieves a built-in symmetric algorithm instance.
         * @param which The built-in algorithm to retrieve.
         * @return A shared pointer to the requested symmetric algorithm instance, or null if
         * which isn't a known built-in algorithm.
         */
        static ISymmetricPtr builtIn(ESymmetrics which);

    public:
        /**
         * Default constructor.
         */
        ISymmetric() {
        }

        /**
         * Virtual destructor.
         */
        virtual ~ISymmetric() = default;

    protected:
        /**
         * Sets the legal key size specifications for this algorithm.
         * @param keySizes The key size specifications to set.
         */
        inline void keySizes(const TArray<SKeySizeSpec>& keySizes) {
            _keySizes = keySizes;
        }

    public:
        /**
         * @return The legal key size specifications for this algorithm.
         */
        inline const TArray<SKeySizeSpec>& keySizes() const {
            return _keySizes;
        }

        /**
         * Generates a new key for this algorithm with the specified key size.
         *
         * @param out The output parameter to receive the generated key.
         * @param keySize The desired key size specification.
         * @return ERET_OK on success; another ERetCode describing the failure otherwise.
         */
        virtual ERetCode generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const = 0;

        /**
         * Imports raw key material (e.g. supplied by a KDF, read from a file, or a known-answer
         * test vector) as a usable key for this algorithm.
         * @param keyData The raw key bytes; its length must be one of keySizes() (in bytes).
         * @return The imported key, or null if keyData's length isn't a valid size for this
         * algorithm.
         */
        virtual ISymmetricKeyPtr createKey(const SReadOnlyByteSpan& keyData) const = 0;

        /**
         * Imports raw key material. See the SReadOnlyByteSpan overload.
         * @param keyData The raw key bytes.
         * @return The imported key, or null if keyData's length isn't a valid size for this
         * algorithm.
         */
        inline ISymmetricKeyPtr createKey(const COctet& keyData) const {
            return createKey(keyData.toSpan());
        }

        /**
         * Generates a new initialization vector (IV) for the given key.
         *
         * @param key The symmetric key for which to generate the IV.
         * @param out The output parameter to receive the generated IV.
         * @return ERET_OK on success; another ERetCode describing the failure otherwise.
         */
        virtual ERetCode generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const = 0;

        /**
         * Creates a new symmetric cryptographic context for the given key.
         *
         * @param key The symmetric key to use for the context.
         * @return A shared pointer to the created symmetric context.
         */
        virtual ISymmetricContextPtr createContext(const ISymmetricKeyPtr& key) const = 0;
    };

    /**
     * Interface for symmetric cryptographic transformers.
     */
    class CERTPP_API ISymmetricTransformer : public ITransformer {
    private:
        ISymmetricContextPtr _context;     // --> Context this transformer was created from.

    public:
        /**
         * Constructor.
         * @param context The context this transformer was created from.
         */
        ISymmetricTransformer(const ISymmetricContextPtr& context) : _context(context) { }

        /**
         * Virtual destructor.
         */
        virtual ~ISymmetricTransformer() = default;

    public:
        /**
         * @return The context this transformer was created from.
         */
        inline ISymmetricContextPtr context() const {
            return _context;
        }
    };

    /**
     * Interface for symmetric cryptographic contexts.
     */
    class CERTPP_API ISymmetricContext {
    private:
        ISymmetricKeyPtr _key;              // --> Key used by this context.
        CBuffer _iv;                        // --> Initialization vector used by this context.

        size_t _sizeOfBlock;                // --> Size of the block used by this context.
        ESymPaddings _padding;              // --> How the final block is padded; see padding().

    public:
        /**
         * Default constructor.
         */
        ISymmetricContext() {
            _sizeOfBlock = 0;
            _padding = ESYMPAD_PKCS7;
        }

        /**
         * Virtual destructor.
         */
        virtual ~ISymmetricContext() = default;

    protected:
        /**
         * Called whenever the bound key material changes, so a derived class can invalidate/
         * rebuild anything it derives from the bound key(s).
         */
        virtual void onReset() = 0;

        /**
         * @return The key used by this context.
         */
        inline const ISymmetricKeyPtr& key() const {
            return _key;
        }

        /**
         * Sets the block size a derived class's onReset() computed for the newly bound key.
         * @param size The algorithm's block size, in bytes (e.g. 16 for AES, 8 for DES/3DES).
         */
        inline void sizeOfBlock(size_t size) {
            _sizeOfBlock = size;
        }

    public:
        /**
         * Resets the context, clearing the key, initialization vector, and block size,
         * and calls the onReset() method for derived classes to handle additional cleanup.
         */
        inline void reset() {
            _key.reset();
            _iv.clear();

            _sizeOfBlock = 0;

            onReset();
        }

        /**
         * Sets the key and initialization vector for this context.
         * @param key The key to set.
         * @param iv The initialization vector to set.
         */
        inline void key(const ISymmetricKeyPtr& key, const CBuffer& iv) {
            _key = key;
            _iv = iv;

            _sizeOfBlock = 0;

            onReset();
        }

        /**
         * @return The initialization vector used by this context.
         */
        inline const CBuffer& iv() const {
            return _iv;
        }

        /**
         * @return The size of the block used by this context.
         */
        inline size_t sizeOfBlock() const {
            return _sizeOfBlock;
        }

        /**
         * Selects how the final block is padded. The choice is read when
         * createEncrypter()/createDecrypter() builds a transformer, so it applies to every
         * transformer created afterwards and not to any created before.
         *
         * Deliberately *not* cleared by reset() or key(), unlike the key, IV and block size:
         * padding is a mode choice rather than key material, and clearing it would mean
         * `padding(ESYMPAD_NONE)` followed by `key(...)` silently reverting to PKCS#7 -- which
         * would be a particularly quiet way to produce a ciphertext a peer rejects.
         * @param padding The padding mode to use.
         */
        inline void padding(ESymPaddings padding) {
            _padding = padding;
        }

        /**
         * @return This context's padding mode; ESYMPAD_PKCS7 unless padding() changed it.
         */
        inline ESymPaddings padding() const {
            return _padding;
        }


        /**
         * Creates an encrypter transformer for this context.
         * @param out The output parameter to receive the encrypter transformer.
         * @return ERET_OK on success; another ERetCode describing the failure otherwise.
         */
        virtual ERetCode createEncrypter(ISymmetricTransformerPtr& out) = 0;

        /**
         * Creates a decrypter transformer for this context.
         * @param out The output parameter to receive the decrypter transformer.
         * @return ERET_OK on success; another ERetCode describing the failure otherwise.
         */
        virtual ERetCode createDecrypter(ISymmetricTransformerPtr& out) = 0;
    };

} // namespace crypto
} // namespace certpp

#endif
