#ifndef __INCLUDE_CERTPP_CRYPTO_KEM_HPP__
#define __INCLUDE_CERTPP_CRYPTO_KEM_HPP__

#include <certpp/common.hpp>
#include <certpp/crypto/keys.hpp>
#include <certpp/crypto/rng.hpp>
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
        virtual ERetCode generateKeyPair(SKeySize keySize, SKemKeyPair& out);

        /**
         * Generates a new encapsulation/decapsulation key pair using the provided random number
         * generator, validating it via checkPrivateKey() before returning it. Unlike a direct
         * checkPrivateKey() call, a
         * validation failure here is reported as ERET_AGAIN specifically (never
         * checkPrivateKey()'s own diagnostic code) -- generation is expected to be retried by
         * simply calling this again, so the caller only needs a "try again" signal, not *why*
         * the candidate was rejected. Mirrors IAsymmetric::generateKeyPair() exactly.
         *
         * @param rng The random number generator to use for key generation.
         * @param keySize The key size to generate the pair at; must be one of keySizes().
         * @param out Receives the new key pair; left empty (see SKemKeyPair::empty()) on failure.
         * @return ERET_OK on success; ERET_AGAIN if the freshly generated key failed
         * checkPrivateKey()'s validation (the caller should simply call this again); another
         * ERetCode describing any other failure.
         */
        virtual ERetCode generateKeyPair(
            const IRng& rng, SKeySize keySize, SKemKeyPair& out) = 0;

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
         * @param out Receives the parsed key and is reset on failure.
         * @param keyData The public key material, in an algorithm-defined encoding.
         * @return ERET_OK on success; ERET_KEY_SIZE for an invalid encoded length;
         * ERET_KEY_FORMAT for malformed or noncanonical input; ERET_NOTSUP for an unsupported
         * parameter set; ERET_NOMEM if allocation failed; another ERetCode otherwise.
         */
        virtual ERetCode createPublicKey(
            IKemPublicKeyPtr& out, const SReadOnlyByteSpan& keyData) const = 0;

        /** Backward-compatible pointer-returning encapsulation-key parser. */
        inline IKemPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const {
            IKemPublicKeyPtr out;
            return createPublicKey(out, keyData) == ERET_OK ? out : nullptr;
        }

        /**
         * Parses encapsulation-key material into a usable public key.
         * @param keyData The public key material, in an algorithm-defined encoding.
         * @return The parsed public key, or null if keyData wasn't a valid encoding.
         */
        inline IKemPublicKeyPtr createPublicKey(const COctet& keyData) const {
            return createPublicKey(keyData.toSpan());
        }

        /** Error-reporting encapsulation-key parser for owning input. */
        inline ERetCode createPublicKey(IKemPublicKeyPtr& out, const COctet& keyData) const {
            return createPublicKey(out, keyData.toSpan());
        }

        /**
         * Parses decapsulation-key material into a usable private key.
         * @param out Receives the parsed key and is reset on failure.
         * @param keyData The private key material, in an algorithm-defined encoding.
         * @return ERET_OK on success; ERET_KEY_SIZE for an invalid encoded length;
         * ERET_KEY_FORMAT for malformed, noncanonical, or internally inconsistent input;
         * ERET_NOTSUP for an unsupported parameter set; ERET_NOMEM if allocation failed;
         * another ERetCode otherwise.
         */
        virtual ERetCode createPrivateKey(
            IKemPrivateKeyPtr& out, const SReadOnlyByteSpan& keyData) const = 0;

        /** Backward-compatible pointer-returning decapsulation-key parser. */
        inline IKemPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const {
            IKemPrivateKeyPtr out;
            return createPrivateKey(out, keyData) == ERET_OK ? out : nullptr;
        }

        /**
         * Parses decapsulation-key material into a usable private key.
         * @param keyData The private key material, in an algorithm-defined encoding.
         * @return The parsed private key, or null if keyData wasn't a valid encoding.
         */
        inline IKemPrivateKeyPtr createPrivateKey(const COctet& keyData) const {
            return createPrivateKey(keyData.toSpan());
        }

        /** Error-reporting decapsulation-key parser for owning input. */
        inline ERetCode createPrivateKey(IKemPrivateKeyPtr& out, const COctet& keyData) const {
            return createPrivateKey(out, keyData.toSpan());
        }

        /**
         * Creates a context for this algorithm's operations. Holds no key material until
         * IKemContext::keyPair()/keyPair() is called on it.
         * @param out Receives the new key-less context and is reset on failure.
         * @return ERET_OK on success; ERET_NOMEM if allocation failed; another code otherwise.
         */
        inline ERetCode createContext(IKemContextPtr& out) const {
            CRng rng;
            return createContext(out, rng);
        }

        /** Backward-compatible pointer-returning context factory. */
        inline IKemContextPtr createContext() const {
            IKemContextPtr out;
            return createContext(out) == ERET_OK ? out : nullptr;
        }

        /**
         * Creates a context that owns the supplied random generator for encapsulation.
         * @param out Receives the new key-less context and is reset on failure.
         * @param rng The generator to retain. Must not be null.
         * @return ERET_OK on success; ERET_BADREQ if rng is null; ERET_NOMEM if allocation
         *         failed; another code otherwise.
         */
        virtual ERetCode createContext(
            IKemContextPtr& out, const std::shared_ptr<IRng>& rng) const = 0;

        /** Backward-compatible pointer-returning context factory with shared RNG ownership. */
        inline IKemContextPtr createContext(const std::shared_ptr<IRng>& rng) const {
            IKemContextPtr out;
            return createContext(out, rng) == ERET_OK ? out : nullptr;
        }

        /**
         * Creates a context from a clone of rng, so the context never retains a reference to
         * caller-owned storage.
         * @param out Receives the new key-less context and is reset on failure.
         * @param rng The generator to clone and retain.
         * @return ERET_OK on success; the clone or context creation error otherwise.
         */
        ERetCode createContext(IKemContextPtr& out, const IRng& rng) const;

        /** Backward-compatible pointer-returning factory that clones rng. */
        inline IKemContextPtr createContext(const IRng& rng) const {
            IKemContextPtr out;
            return createContext(out, rng) == ERET_OK ? out : nullptr;
        }
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
        const std::shared_ptr<IRng> _rng;

        size_t _sizeOfCiphertext;      // --> size of the ciphertext encapsulate() produces.
        size_t _sizeOfSharedSecret;    // --> size of the shared secret encapsulate()/decapsulate() produce.

    public:
        /**
         * Constructor. The generator is retained for the whole context lifetime and cannot be
         * replaced after construction.
         * @param rng The non-null generator this context owns.
         */
        explicit IKemContext(const std::shared_ptr<IRng>& rng);

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

        /** @return The generator owned by this context. */
        const IRng& randomGenerator() const;

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

        /** Allocating encapsulation overload sized from the bound key. */
        inline ERetCode encapsulate(COctet& ciphertext, COctet& sharedSecret) {
            TArray<uint8_t> ciphertextBuffer;
            TArray<uint8_t> secretBuffer;
            if (sizeOfCiphertext() == 0 || sizeOfSharedSecret() == 0) {
                ciphertext.clear();
                sharedSecret.clear();
                return ERET_KEY_EMPTY;
            }
            if (!ciphertextBuffer.resize(sizeOfCiphertext())
                || !secretBuffer.resize(sizeOfSharedSecret()))
            {
                ciphertext.clear();
                sharedSecret.clear();
                return ERET_NOMEM;
            }

            SByteSpan ciphertextSpan(ciphertextBuffer.begin(), ciphertextBuffer.size());
            SByteSpan secretSpan(secretBuffer.begin(), secretBuffer.size());
            const ERetCode result = encapsulate(ciphertextSpan, secretSpan);
            if (result != ERET_OK
                || !ciphertext.store(ciphertextSpan.data, ciphertextSpan.size)
                || !sharedSecret.store(secretSpan.data, secretSpan.size))
            {
                ciphertext.clear();
                sharedSecret.clear();
                return result == ERET_OK ? ERET_NOMEM : result;
            }
            return ERET_OK;
        }

        /**
         * Recovers the shared secret that was encapsulated to this context's bound private
         * key's matching public key. Nothing about the encapsulating side is remembered here --
         * the result is a function of the ciphertext and the bound private key, which is why a
         * receiver can decapsulate a ciphertext produced by a peer it has never spoken to.
         * An invalid/corrupted ciphertext must not be observably
         * distinguishable (in timing or in the returned ERetCode) from a valid one that simply
         * decapsulates to a different secret -- see docs/pqc/engineering.md on the
         * Fujisaki-Okamoto implicit-rejection requirement this implies for any
         * concrete IKemContext implementation.
         *
         * @param ciphertext The ciphertext produced by the peer's encapsulate() call.
         * @param sharedSecret The destination buffer to receive the shared secret (at least
         * sizeOfSharedSecret() bytes); truncated to the number of bytes actually written.
         * @return ERET_OK on success; ERET_KEY_EMPTY if no private key is bound; another
         * ERetCode describing any other failure.
         */
        virtual ERetCode decapsulate(const SReadOnlyByteSpan& ciphertext, SByteSpan& sharedSecret) = 0;

        /** Allocating decapsulation overload sized from the bound key. */
        inline ERetCode decapsulate(
            const SReadOnlyByteSpan& ciphertext, COctet& sharedSecret
        ) {
            TArray<uint8_t> buffer;
            if (sizeOfSharedSecret() == 0) {
                sharedSecret.clear();
                return ERET_KEY_EMPTY;
            }
            if (!buffer.resize(sizeOfSharedSecret())) {
                sharedSecret.clear();
                return ERET_NOMEM;
            }
            SByteSpan written(buffer.begin(), buffer.size());
            const ERetCode result = decapsulate(ciphertext, written);
            if (result != ERET_OK) {
                sharedSecret.clear();
                return result;
            }
            if (!sharedSecret.store(written.data, written.size)) {
                sharedSecret.clear();
                return ERET_NOMEM;
            }
            return ERET_OK;
        }

        inline ERetCode decapsulate(const COctet& ciphertext, COctet& sharedSecret) {
            return decapsulate(ciphertext.toSpan(), sharedSecret);
        }
    };

} // namespace crypto
} // namespace certpp

#endif
