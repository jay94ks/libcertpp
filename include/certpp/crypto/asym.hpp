#ifndef __INCLUDE_CERTPP_CRYPTO_ASYM_HPP__
#define __INCLUDE_CERTPP_CRYPTO_ASYM_HPP__

#include <certpp/common.hpp>
#include <certpp/crypto/keys.hpp>
#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/transform.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/stream.hpp>
#include <memory>

namespace certpp {
namespace crypto {

    // --> Forward declaration of the IAsymmetricContext interface.
    class IAsymmetricContext;

    /* Shared pointer type for the IAsymmetricContext interface. */
    using IAsymmetricContextPtr = std::shared_ptr<IAsymmetricContext>;

    // --> Forward declaration of the IAsymmetric interface.
    class IAsymmetric;

    /* Shared pointer type for the IAsymmetric interface. */
    using IAsymmetricPtr = std::shared_ptr<IAsymmetric>;

    /**
     * Interface for an asymmetric cryptographic algorithm. Describes which key sizes it accepts
     * and acts as a factory for keys and contexts; performs no operations itself.
     */
    class CERTPP_API IAsymmetric {
    private:
        TArray<SKeySizeSpec> _keySizes;

    public:
        /**
         * Retrieves a built-in asymmetric algorithm instance.
         * @param which The built-in algorithm to retrieve.
         * @return A shared pointer to the requested asymmetric algorithm instance.
         */
        static IAsymmetricPtr builtIn(EAsymmetrics which);

    public:
        /**
         * Default constructor.
         */
        IAsymmetric() {
        }

        /**
         * Virtual destructor.
         */
        virtual ~IAsymmetric() = default;

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
         * Generates a new key pair, validating it via checkPrivateKey() before returning it.
         * Unlike a direct checkPrivateKey() call, a validation failure here is reported as
         * ERET_AGAIN specifically (never checkPrivateKey()'s own diagnostic code) -- generation
         * is expected to be retried by simply calling this again, so the caller only needs a
         * "try again" signal, not *why* the candidate was rejected.
         * @param keySize The key size to generate the pair at; must be one of keySizes().
         * @param out Receives the new key pair; left empty (see SKeyPair::empty()) on failure.
         * @return ERET_OK on success; ERET_AGAIN if the freshly generated key failed
         * checkPrivateKey()'s validation (the caller should simply call this again); another
         * ERetCode describing any other failure.
         */
        virtual ERetCode generateKeyPair(SKeySize keySize, SKeyPair& out) = 0;

        /**
         * Validates a private key's structure -- e.g., for an elliptic-curve algorithm, that its
         * derived public point isn't the point at infinity, has coordinates within the field,
         * satisfies the curve equation, and belongs to the correct-order subgroup; for RSA/DSA,
         * the algorithm's own analogous domain-parameter/key consistency checks. Called both
         * internally by generateKeyPair() (see its own doc comment for how it reports a failure
         * here) and directly by a caller that deserialized a key via createPrivateKey() and
         * wants to validate it before use -- unlike generateKeyPair(), retrying isn't a coherent
         * response to a deserialized key failing validation, so this method reports *why* it
         * failed rather than ERET_AGAIN.
         *
         * @param key The private key to validate; must have been created by this same algorithm
         * instance (via generateKeyPair() or createPrivateKey()).
         * @return ERET_OK if key is valid; ERET_KEY_FORMAT if key wasn't created by this
         * algorithm instance (wrong concrete type); ERET_KEY_ERROR if key is internally
         * inconsistent (e.g. its linked public key is missing or of the wrong type);
         * ERET_KEY_PARAM if key's own parameters/derived values fail a structural check (e.g.
         * an out-of-range scalar, an off-curve or wrong-subgroup public point, an RSA/DSA
         * domain-parameter mismatch).
         */
        virtual ERetCode checkPrivateKey(const IPrivateKeyPtr& key) const = 0;

        /**
         * Parses public key material into a usable public key.
         * @param keyData The public key material, in an algorithm-defined encoding.
         * @return The parsed public key, or null if keyData wasn't a valid encoding.
         */
        virtual IPublicKeyPtr createPublicKey(const SReadOnlyByteSpan& keyData) const = 0;

        /**
         * Parses public key material into a usable public key.
         * @param keyData The public key material, in an algorithm-defined encoding.
         * @return The parsed public key, or null if keyData wasn't a valid encoding.
         */
        inline IPublicKeyPtr createPublicKey(const COctet& keyData) const {
            return createPublicKey(keyData.toSpan());
        }

        /**
         * Parses private key material into a usable private key.
         * @param keyData The private key material, in an algorithm-defined encoding.
         * @return The parsed private key, or null if keyData wasn't a valid encoding.
         */
        virtual IPrivateKeyPtr createPrivateKey(const SReadOnlyByteSpan& keyData) const = 0;

        /**
         * Parses private key material into a usable private key.
         * @param keyData The private key material, in an algorithm-defined encoding.
         * @return The parsed private key, or null if keyData wasn't a valid encoding.
         */
        inline IPrivateKeyPtr createPrivateKey(const COctet& keyData) const {
            return createPrivateKey(keyData.toSpan());
        }

        /**
         * Creates a context for this algorithm's operations. Holds no key material until
         * IAsymmetricContext::keyPair() is called on it.
         * @return A new, key-less context.
         */
        virtual IAsymmetricContextPtr createContext() const = 0;
    };

    // --> Forward declaration of the IAsymmetricTransformer interface.
    class IAsymmetricTransformer;

    /* Shared pointer type for the IAsymmetricTransformer interface. */
    using IAsymmetricTransformerPtr = std::shared_ptr<IAsymmetricTransformer>;

    /**
     * Interface for an asymmetric encryption/decryption operation in progress, produced by
     * IAsymmetricContext::createEncrypter()/createDecrypter(); never constructed directly.
     * Asymmetric encryption only ever operates on one block at a time, so encrypting/decrypting
     * is a transform()-repeatedly-then-transformFinal() session rather than a single call.
     */
    class CERTPP_API IAsymmetricTransformer : public ITransformer {
    private:
        IAsymmetricContextPtr _context;     // --> Context this transformer was created from.

    public:
        /**
         * Constructor.
         * @param context The context this transformer was created from.
         */
        IAsymmetricTransformer(const IAsymmetricContextPtr& context) : _context(context) { }

        /**
         * Virtual destructor.
         */
        virtual ~IAsymmetricTransformer() = default;

        /**
         * @return The context this transformer was created from.
         */
        inline IAsymmetricContextPtr context() const {
            return _context;
        }
    };

    /**
     * Interface for an asymmetric algorithm's operations, bound to a key pair via keyPair().
     * Produced by IAsymmetric::createContext(), never constructed directly. sign()/verify() and
     * createEncrypter()/createDecrypter() act on whichever bound key they need (signing/
     * decrypting: private; verifying/encrypting: public) rather than taking one as a parameter.
     */
    class CERTPP_API IAsymmetricContext {
    private:
        IPublicKeyPtr _publicKey;
        IPrivateKeyPtr _privateKey;

        size_t _sizeOfSign;         // --> maximum size of a signature.
        size_t _sizeOfDigest;       // --> maximum size of a digest.

    public:
        /**
         * Default constructor.
         */
        IAsymmetricContext() : _sizeOfSign(0), _sizeOfDigest(0) { }

        /**
         * Virtual destructor.
         */
        virtual ~IAsymmetricContext() = default;

    protected:
        /**
         * Called whenever the bound key material changes, so a derived class can invalidate/
         * rebuild anything it derives from the bound key(s).
         */
        virtual void onReset() = 0;

        /**
         * @return The currently bound public key, or null if none is bound.
         */
        inline const IPublicKeyPtr& publicKey() const {
            return _publicKey;
        }

        /**
         * @return The currently bound private key, or null if none is bound.
         */
        inline const IPrivateKeyPtr& privateKey() const {
            return _privateKey;
        }

    public:
        /**
         * Discards any bound key material.
         */
        inline void reset() {
            _publicKey.reset();
            _privateKey.reset();

            _sizeOfSign = 0;
            _sizeOfDigest = 0;

            onReset();
        }

        /**
         * Binds a key pair to this context.
         * @param keyPair The key pair to bind.
         */
        inline void keyPair(const SKeyPair& keyPair) {
            _publicKey = keyPair.publicKey;
            _privateKey = keyPair.privateKey;

            _sizeOfSign = 0;
            _sizeOfDigest = 0;

            onReset();
        }

        /**
         * Binds a public and/or private key individually, rather than as a matched SKeyPair
         * (e.g. a public key with no corresponding private key, to verify someone else's
         * signature).
         *
         * @param publicKey The public key to bind.
         * @param privateKey The private key to bind.
         */
        inline void keyPair(const IPublicKeyPtr& publicKey, const IPrivateKeyPtr& privateKey) {
            _publicKey = publicKey;
            _privateKey = privateKey;

            _sizeOfSign = 0;
            _sizeOfDigest = 0;

            onReset();
        }

        /**
         * @return The largest signature this context's bound private key can produce -- a buffer
         *         size, not a length. An ECDSA signature is DER and so varies in length between
         *         signatures over the same key; sign() narrows its output span to the real
         *         length, and that narrowed size is what a caller must carry forward.
         */
        inline size_t sizeOfSign() const {
            return _sizeOfSign;
        }

        /**
         * @return The size of the message digest expected by this context's bound private key.
         */
        inline size_t sizeOfDigest() const {
            return _sizeOfDigest;
        }

    protected:
        /**
         * Sets the signature size a derived class's onReset() computed for the newly bound key.
         * @param size The maximum number of bytes sign() can produce for the bound key.
         */
        inline void sizeOfSign(size_t size) {
            _sizeOfSign = size;
        }

        /**
         * Sets the digest size a derived class's onReset() computed for the newly bound key.
         * @param size The largest digest length this key's algorithm meaningfully consumes.
         */
        inline void sizeOfDigest(size_t size) {
            _sizeOfDigest = size;
        }

    public:
        /**
         * Signs a message digest with the bound private key. Not every algorithm supports
         * signing; the default implementation reports ERET_NOTSUP.
         *
         * @param digest The message digest to sign, normally produced by an IHasher.
         * @param out The destination array to receive the signature.
         * @return ERET_OK on success; ERET_NOTSUP if unsupported; another ERetCode otherwise.
         */
        virtual ERetCode sign(const SReadOnlyByteSpan& digest, SByteSpan& out) {
            return ERET_NOTSUP;
        }

        /**
         * Signs a message digest with the bound private key.
         * @param digest The message digest to sign, normally produced by an IHasher.
         * @param out The destination array to receive the signature.
         * @return ERET_OK on success; ERET_NOTSUP if unsupported; another ERetCode otherwise.
         */
        inline ERetCode sign(const COctet& digest, SByteSpan& out) {
            return sign(digest.toSpan(), out);
        }

        /**
         * Verifies a signature over a message digest with the bound public key. Not every
         * algorithm supports verification; the default implementation reports ERET_NOTSUP.
         *
         * @param digest The message digest that was signed, normally produced by an IHasher.
         * @param signature The signature to verify.
         * @return ERET_OK if signature is valid; ERET_NOTSUP if unsupported; another ERetCode
         * otherwise (e.g. the signature doesn't match).
         */
        virtual ERetCode verify(const SReadOnlyByteSpan& digest, const SReadOnlyByteSpan& signature) {
            return ERET_NOTSUP;
        }

        /**
         * Verifies a signature over a message digest with the bound public key.
         * @param digest The message digest that was signed, normally produced by an IHasher.
         * @param signature The signature to verify.
         * @return ERET_OK if signature is valid; ERET_NOTSUP if unsupported; another ERetCode
         * otherwise (e.g. the signature doesn't match).
         */
        inline ERetCode verify(const COctet& digest, const COctet& signature) {
            return verify(digest.toSpan(), signature.toSpan());
        }

        /**
         * Signs a message digest with the bound private key using RSASSA-PSS (RFC 8017 9.1)
         * instead of EMSA-PKCS1-v1_5 -- an algorithm-specific capability, not every algorithm
         * supports it (only RSA does); the default implementation reports ERET_NOTSUP.
         *
         * @param digest The message digest to sign, whose length must equal
         * hashAlg's own digest length (the digest hashAlg would itself produce).
         * @param hashAlg The hash algorithm digest was produced with -- also used for PSS's own
         * MGF1 mask generation and encoded into the signature's AlgorithmIdentifier parameters.
         * @param saltLen The length, in bytes, of the random salt to embed in the PSS encoding.
         * @param out The destination array to receive the signature.
         * @return ERET_OK on success; ERET_NOTSUP if unsupported; another ERetCode otherwise.
         */
        virtual ERetCode signPss(
            const SReadOnlyByteSpan& digest, EHashers hashAlg, size_t saltLen, SByteSpan& out
        ) {
            return ERET_NOTSUP;
        }

        /**
         * Verifies an RSASSA-PSS signature (RFC 8017 9.1) over a message digest with the bound
         * public key. Not every algorithm supports it (only RSA does); the default
         * implementation reports ERET_NOTSUP.
         *
         * @param digest The message digest that was signed, whose length must equal hashAlg's
         * own digest length.
         * @param hashAlg The hash algorithm digest was produced with, and PSS was signed with.
         * @param saltLen The length, in bytes, of the random salt embedded in the PSS encoding.
         * @param signature The signature to verify.
         * @return ERET_OK if signature is valid; ERET_NOTSUP if unsupported; another ERetCode
         * otherwise (e.g. the signature doesn't match).
         */
        virtual ERetCode verifyPss(
            const SReadOnlyByteSpan& digest, EHashers hashAlg, size_t saltLen,
            const SReadOnlyByteSpan& signature
        ) {
            return ERET_NOTSUP;
        }

        /**
         * Derives a shared secret from this context's bound private key and a peer's public
         * key (Diffie-Hellman-style key agreement). Not every algorithm supports key agreement;
         * the default implementation reports ERET_NOTSUP.
         *
         * @param peerPublicKey The other party's public key.
         * @param out The destination array to receive the shared secret.
         * @return ERET_OK on success; ERET_NOTSUP if unsupported; another ERetCode otherwise.
         */
        virtual ERetCode deriveSharedSecret(const IPublicKeyPtr& peerPublicKey, SByteSpan& out) {
            return ERET_NOTSUP;
        }

        /**
         * Creates a transformer for encrypting with the bound public key. Not every algorithm
         * supports encryption; an implementation that doesn't should report ERET_NOTSUP.
         *
         * @param out Receives the new encrypter, bound to the same key material as this context.
         * @return ERET_OK on success; ERET_NOTSUP if unsupported; another ERetCode otherwise.
         */
        virtual ERetCode createEncrypter(IAsymmetricTransformerPtr& out) = 0;

        /**
         * Creates a transformer for decrypting with the bound private key. Not every algorithm
         * supports decryption; an implementation that doesn't should report ERET_NOTSUP.
         *
         * @param out Receives the new decrypter, bound to the same key material as this context.
         * @return ERET_OK on success; ERET_NOTSUP if unsupported; another ERetCode otherwise.
         */
        virtual ERetCode createDecrypter(IAsymmetricTransformerPtr& out) = 0;
    };

} // namespace crypto
} // namespace certpp

#endif
