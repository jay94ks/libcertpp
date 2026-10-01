#ifndef __INCLUDE_CERTPP_CRYPTO_KEM_HPP__
#define __INCLUDE_CERTPP_CRYPTO_KEM_HPP__

#include <certpp/common.hpp>
#include <certpp/crypto/keys.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/octet.hpp>
#include <memory>

namespace certpp {
namespace crypto {

    // --> Forward declaration of the IKemContext interface.
    class IKemContext;

    /* Shared pointer type for the IKemContext interface. */
    using IKemContextPtr = std::shared_ptr<IKemContext>;

    // --> Forward declaration of the IKem interface.
    class IKem;

    /* Shared pointer type for the IKem interface. */
    using IKemPtr = std::shared_ptr<IKem>;

    /**
     * Interface for a key-encapsulation-mechanism (KEM) algorithm. Describes which key sizes it
     * accepts and acts as a factory for keys and contexts; performs no operations itself -- same
     * shape as IAsymmetric (crypto/asym.hpp), deliberately: see EKems's own doc comment
     * (crypto/keys.hpp) for why a KEM gets its own interface/key family instead of folding into
     * IAsymmetric, rather than repeating that reasoning on every mirrored member here.
     */
    class CERTPP_API IKem {
    private:
        TArray<SKeySizeSpec> _keySizes;

    public:
        /**
         * Retrieves a built-in KEM algorithm instance.
         * @param which The built-in algorithm to retrieve.
         * @return A shared pointer to the requested KEM algorithm instance.
         */
        static IKemPtr builtIn(EKems which);

    public:
        /**
         * Default constructor.
         */
        IKem() {
        }

        /**
         * Virtual destructor.
         */
        virtual ~IKem() = default;

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

    public:
        /**
         * Generates a new encapsulation/decapsulation key pair, validating it via
         * checkPrivateKey() before returning it. Unlike a direct checkPrivateKey() call, a
         * validation failure here is reported as ERET_AGAIN specifically (never
         * checkPrivateKey()'s own diagnostic code) -- generation is expected to be retried by
         * simply calling this again, so the caller only needs a "try again" signal, not *why*
         * the candidate was rejected. Mirrors IAsymmetric::generateKeyPair() exactly.
         *
         * @param keySize The key size to generate the pair at; must be one of keySizes().
         * @param out Receives the new key pair; left empty (see SKemKeyPair::empty()) on failure.
         * @return ERET_OK on success; ERET_AGAIN if the freshly generated key failed
         * checkPrivateKey()'s validation (the caller should simply call this again); another
         * ERetCode describing any other failure.
         */
        virtual ERetCode generateKeyPair(SKeySize keySize, SKemKeyPair& out) = 0;

        /**
         * Validates a private key's structure -- e.g., for a lattice-based algorithm, that its
         * stored public key is consistent with its private seed/secret and that every encoded
         * component falls within its algorithm-defined valid range. Called both internally by
         * generateKeyPair() (see its own doc comment for how it reports a failure here) and
         * directly by a caller that deserialized a key via createPrivateKey() and wants to
         * validate it before use. Mirrors IAsymmetric::checkPrivateKey() exactly.
         *
         * @param key The private key to validate; must have been created by this same algorithm
         * instance (via generateKeyPair() or createPrivateKey()).
         * @return ERET_OK if key is valid; ERET_KEY_FORMAT if key wasn't created by this
         * algorithm instance (wrong concrete type); ERET_KEY_ERROR if key is internally
         * inconsistent (e.g. its linked public key is missing or of the wrong type);
         * ERET_KEY_PARAM if key's own parameters/derived values fail a structural check.
         */
        virtual ERetCode checkPrivateKey(const IKemPrivateKeyPtr& key) const = 0;

        /**
         * Parses encapsulation-key material into a usable public key.
         * @param keyData The public key material, in an algorithm-defined encoding.
         * @return The parsed public key, or null if keyData wasn't a valid encoding.
         */
        virtual IKemPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const = 0;

        /**
         * Parses encapsulation-key material into a usable public key.
         * @param keyData The public key material, in an algorithm-defined encoding.
         * @return The parsed public key, or null if keyData wasn't a valid encoding.
         */
        inline IKemPublicKeyPtr createPublicKey(const COctet& keyData) const {
            return createPublicKey(keyData.toSpan());
        }

        /**
         * Parses decapsulation-key material into a usable private key.
         * @param keyData The private key material, in an algorithm-defined encoding.
         * @return The parsed private key, or null if keyData wasn't a valid encoding.
         */
        virtual IKemPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const = 0;

        /**
         * Parses decapsulation-key material into a usable private key.
         * @param keyData The private key material, in an algorithm-defined encoding.
         * @return The parsed private key, or null if keyData wasn't a valid encoding.
         */
        inline IKemPrivateKeyPtr createPrivateKey(const COctet& keyData) const {
            return createPrivateKey(keyData.toSpan());
        }

        /**
         * Creates a context for this algorithm's operations. Holds no key material until
         * IKemContext::keyPair()/keyPair() is called on it.
         * @return A new, key-less context.
         */
        virtual IKemContextPtr createContext() const = 0;
    };

    /**
     * Interface for a KEM algorithm's operations, bound to a key pair (or a lone public/private
     * half) via keyPair(). Produced by IKem::createContext(), never constructed directly.
     * encapsulate()/decapsulate() act on whichever bound key they need, the same way
     * IAsymmetricContext::sign()/verify() do rather than taking one as a parameter:
     * encapsulate() needs the peer's public key (bind it via keyPair(peerPublicKey, nullptr),
     * the same pattern IAsymmetricContext's own doc comment describes for verify()-only use);
     * decapsulate() needs this side's private key.
     */
    class CERTPP_API IKemContext {
    private:
        IKemPublicKeyPtr _publicKey;
        IKemPrivateKeyPtr _privateKey;

        size_t _sizeOfCiphertext;      // --> size of the ciphertext encapsulate() produces.
        size_t _sizeOfSharedSecret;    // --> size of the shared secret encapsulate()/decapsulate() produce.

    public:
        /**
         * Default constructor.
         */
        IKemContext() : _sizeOfCiphertext(0), _sizeOfSharedSecret(0) { }

        /**
         * Virtual destructor.
         */
        virtual ~IKemContext() = default;

    protected:
        /**
         * Called whenever the bound key material changes, so a derived class can invalidate/
         * rebuild anything it derives from the bound key(s).
         */
        virtual void onReset() = 0;

        /**
         * @return The currently bound public key, or null if none is bound.
         */
        inline const IKemPublicKeyPtr& publicKey() const {
            return _publicKey;
        }

        /**
         * @return The currently bound private key, or null if none is bound.
         */
        inline const IKemPrivateKeyPtr& privateKey() const {
            return _privateKey;
        }

    public:
        /**
         * Discards any bound key material.
         */
        inline void reset() {
            _publicKey.reset();
            _privateKey.reset();

            _sizeOfCiphertext = 0;
            _sizeOfSharedSecret = 0;

            onReset();
        }

        /**
         * Binds a key pair to this context.
         * @param keyPair The key pair to bind.
         */
        inline void keyPair(const SKemKeyPair& keyPair) {
            _publicKey = keyPair.publicKey;
            _privateKey = keyPair.privateKey;

            _sizeOfCiphertext = 0;
            _sizeOfSharedSecret = 0;

            onReset();
        }

        /**
         * Binds a public and/or private key individually, rather than as a matched SKemKeyPair
         * (e.g. a peer's public key with no corresponding private key, to encapsulate to them).
         *
         * @param publicKey The public key to bind.
         * @param privateKey The private key to bind.
         */
        inline void keyPair(const IKemPublicKeyPtr& publicKey, const IKemPrivateKeyPtr& privateKey) {
            _publicKey = publicKey;
            _privateKey = privateKey;

            _sizeOfCiphertext = 0;
            _sizeOfSharedSecret = 0;

            onReset();
        }

        /**
         * @return The size, in bytes, of the ciphertext encapsulate() produces for this
         * context's bound key.
         */
        inline size_t sizeOfCiphertext() const {
            return _sizeOfCiphertext;
        }

        /**
         * @return The size, in bytes, of the shared secret encapsulate()/decapsulate() produce
         * for this context's bound key.
         */
        inline size_t sizeOfSharedSecret() const {
            return _sizeOfSharedSecret;
        }

    protected:
        /**
         * Sets the ciphertext size a derived class's onReset() computed for the newly bound key.
         * @param size The number of bytes encapsulate() produces as ciphertext for the bound key.
         */
        inline void sizeOfCiphertext(size_t size) {
            _sizeOfCiphertext = size;
        }

        /**
         * Sets the shared-secret size a derived class's onReset() computed for the newly bound
         * key.
         * @param size The number of bytes encapsulate()/decapsulate() produce as the shared
         * secret for the bound key.
         */
        inline void sizeOfSharedSecret(size_t size) {
            _sizeOfSharedSecret = size;
        }

    public:
        /**
         * Encapsulates a fresh shared secret to this context's bound public key: generates a
         * random shared secret and the ciphertext that only the matching private key can recover
         * it from, writing both out. The shared secret is produced by this call, not chosen by
         * the caller -- there is no plaintext to supply, unlike IAsymmetricTransformer's
         * encrypt().
         *
         * @param ciphertext The destination buffer to receive the ciphertext (at least
         * sizeOfCiphertext() bytes); truncated to the number of bytes actually written.
         * @param sharedSecret The destination buffer to receive the shared secret (at least
         * sizeOfSharedSecret() bytes); truncated to the number of bytes actually written.
         * @return ERET_OK on success; ERET_KEY_EMPTY if no public key is bound; another
         * ERetCode describing any other failure.
         */
        virtual ERetCode encapsulate(SByteSpan& ciphertext, SByteSpan& sharedSecret) = 0;

        /**
         * Recovers the shared secret this context's bound private key's matching public key was
         * last encapsulated to. An invalid/corrupted ciphertext must not be observably
         * distinguishable (in timing or in the returned ERetCode) from a valid one that simply
         * decapsulates to a different secret -- see docs/pqc-review.md's "What's genuinely hard"
         * section on the Fujisaki-Okamoto implicit-rejection requirement this implies for any
         * concrete IKemContext implementation.
         *
         * @param ciphertext The ciphertext produced by the peer's encapsulate() call.
         * @param sharedSecret The destination buffer to receive the shared secret (at least
         * sizeOfSharedSecret() bytes); truncated to the number of bytes actually written.
         * @return ERET_OK on success; ERET_KEY_EMPTY if no private key is bound; another
         * ERetCode describing any other failure.
         */
        virtual ERetCode decapsulate(const SReadOnlyByteSpan& ciphertext, SByteSpan& sharedSecret) = 0;
    };

} // namespace crypto
} // namespace certpp

#endif
