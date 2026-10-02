#ifndef __INCLUDE_CERTPP_CRYPTO_KEYS_HPP__
#define __INCLUDE_CERTPP_CRYPTO_KEYS_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/octet.hpp>
#include <memory>

namespace certpp {
namespace crypto {

    /**
     * The asymmetric algorithms this library implements (see crypto/asyms/ for each concrete
     * IAsymmetric): RSA, DSA, Ed25519/Ed448 (EdDSA), X25519 (Diffie-Hellman key agreement), and
     * every prime-field/binary-field elliptic curve CEcdsa/CEcdsa2 supports. Lives here (rather
     * than asym.hpp, where it's used far more -- IAsymmetric::builtIn(), etc.) because
     * IKeyBase::algorithm() needs it too, and asym.hpp already includes this header (not the
     * other way around).
     */
    enum EAsymmetrics {
        EASYM_RSA = 0,         /**< RSA algorithm */
        EASYM_DSA,             /**< DSA algorithm */
        EASYM_ED25519,         /**< Ed25519 algorithm */
        EASYM_ED448,           /**< Ed448 algorithm */
        EASYM_P192,            /**< P-192 algorithm */
        EASYM_P224,            /**< P-224 algorithm */
        EASYM_P256,            /**< P-256 algorithm */
        EASYM_P384,            /**< P-384 algorithm */
        EASYM_P521,            /**< P-521 algorithm */
        EASYM_SECP256K1,       /**< secp256k1 algorithm */
        EASYM_BPOOL160R1,      /**< Brainpool-160r1 algorithm */
        EASYM_BPOOL192R1,      /**< Brainpool-192r1 algorithm */
        EASYM_BPOOL224R1,      /**< Brainpool-224r1 algorithm */
        EASYM_BPOOL256R1,      /**< Brainpool-256r1 algorithm */
        EASYM_BPOOL320R1,      /**< Brainpool-320r1 algorithm */
        EASYM_BPOOL384R1,      /**< Brainpool-384r1 algorithm */
        EASYM_BPOOL512R1,      /**< Brainpool-512r1 algorithm */
        EASYM_BPOOL160T1,      /**< Brainpool-160t1 algorithm */
        EASYM_BPOOL192T1,      /**< Brainpool-192t1 algorithm */
        EASYM_BPOOL224T1,      /**< Brainpool-224t1 algorithm */
        EASYM_BPOOL256T1,      /**< Brainpool-256t1 algorithm */
        EASYM_BPOOL320T1,      /**< Brainpool-320t1 algorithm */
        EASYM_BPOOL384T1,      /**< Brainpool-384t1 algorithm */
        EASYM_BPOOL512T1,      /**< Brainpool-512t1 algorithm */
        EASYM_X25519,          /**< X25519 algorithm */
        EASYM_B163,            /**< B-163 algorithm */
        EASYM_K163,            /**< K-163 algorithm */
        EASYM_B233,            /**< B-233 algorithm */
        EASYM_K233,            /**< K-233 algorithm */
        EASYM_B283,            /**< B-283 algorithm */
        EASYM_K283,            /**< K-283 algorithm */
        EASYM_B409,            /**< B-409 algorithm */
        EASYM_K409,            /**< K-409 algorithm */
        EASYM_B571,            /**< B-571 algorithm */
        EASYM_K571,            /**< K-571 algorithm */

        /**< Marker for the maximum value of EAsymmetrics. */
        EASYM_MAX,
        EASYM_UNKNOWN = 0xffffu, /**< Unknown algorithm */
    };

    /**
     * The type used for key size values.
     */
    using SKeySize = size_t;

    /**
     * The valid key sizes for a cryptographic algorithm.
     */
    struct CERTPP_API SKeySizeSpec {
        SKeySize minSize; /**< Minimum key size in bits. */
        SKeySize maxSize; /**< Maximum key size in bits. */
        SKeySize step;    /**< Increment step for valid key sizes in bits. */

        /**
         * Default constructor; all fields zero.
         */
        constexpr SKeySizeSpec() : minSize(0), maxSize(0), step(0) {}

        /**
         * Constructs a spec accepting a single size.
         * @param size The key size in bits.
         */
        constexpr SKeySizeSpec(SKeySize size)
            : minSize(size), maxSize(size), step(0) {}

        /**
         * @param minSize Minimum key size in bits.
         * @param maxSize Maximum key size in bits.
         * @param step Increment step for valid key sizes in bits.
         */
        constexpr SKeySizeSpec(SKeySize minSize, SKeySize maxSize, SKeySize step)
            : minSize(minSize), maxSize(maxSize), step(step) {}

        /**
         * @return true if minSize, maxSize, and step are all zero.
         */
        inline bool empty() const {
            return minSize == 0 && maxSize == 0 && step == 0;
        }

        /**
         * @return true if this specification is not empty.
         */
        inline operator bool() const {
            return !empty();
        }

        /**
         * @return true if this specification is empty.
         */
        inline bool operator!() const {
            return empty();
        }

        /**
         * Checks if a given key size is included in the valid key sizes.
         * @param size The key size in bits to check.
         * @return true if size is valid according to this specification.
         */
        inline bool includes(SKeySize size) const {
            if (empty()) {
                return false;
            }

            if (size < minSize || size > maxSize) {
                return false;
            }

            if (step == 0) {
                return size == minSize;
            }

            return (size - minSize) % step == 0;
        }

        /**
         * @param other The other key size specification to compare with.
         * @return A negative value if this is less than other, zero if equal, positive if greater.
         */
        int32_t compare(const SKeySizeSpec& other) const;

        /**
         * @return true if this specification is less than the other specification.
         */
        inline bool operator<(const SKeySizeSpec& other) const {
            return compare(other) < 0;
        }

        /**
         * @return true if this specification is less than or equal to the other specification.
         */
        inline bool operator<=(const SKeySizeSpec& other) const {
            return compare(other) <= 0;
        }

        /**
         * @return true if this specification is greater than the other specification.
         */
        inline bool operator>(const SKeySizeSpec& other) const {
            return compare(other) > 0;
        }

        /**
         * @return true if this specification is greater than or equal to the other specification.
         */
        inline bool operator>=(const SKeySizeSpec& other) const {
            return compare(other) >= 0;
        }

        /**
         * @return true if this specification is equal to the other specification.
         */
        inline bool operator==(const SKeySizeSpec& other) const {
            return compare(other) == 0;
        }

        /**
         * @return true if this specification is not equal to the other specification.
         */
        inline bool operator!=(const SKeySizeSpec& other) const {
            return compare(other) != 0;
        }
    };

    // --> Forward declaration of the IKeyBase interface.
    class IKeyBase;

    /* Shared pointer type for the IKeyBase interface. */
    using IKeyBasePtr = std::shared_ptr<IKeyBase>;

    /**
     * Common interface for symmetric and asymmetric cryptographic keys: every key has a size
     * and can be serialized to bytes. IPublicKey/IPrivateKey extend this for the asymmetric
     * case; a future symmetric key interface would extend it the same way.
     */
    class CERTPP_API IKeyBase {
    public:
        /**
         * Virtual destructor.
         */
        virtual ~IKeyBase() = default;

    public:
        /**
         * Serializes this key to its algorithm-defined byte encoding.
         *
         * @param out The buffer to receive the serialized key.
         * @return ERET_OK on success; another ERetCode describing the failure otherwise.
         */
        virtual ERetCode serialize(COctet& out) const = 0;

        /**
         * Compares this key with another key.
         *
         * @param other The other key to compare with.
         * @return A negative value if this is less than other, zero if equal, positive if greater.
         */
        virtual int32_t compare(const IKeyBasePtr& other) const = 0;
    };

    // --> Forward declaration of the IAsymmetricKeyBase interface.
    class IAsymmetricKeyBase;

    /* Shared pointer type for the IAsymmetricKeyBase interface. */
    using IAsymmetricKeyBasePtr = std::shared_ptr<IAsymmetricKeyBase>;

    /**
     * Key base for asymmetric algorithms.
     */
    class CERTPP_API IAsymmetricKeyBase : public IKeyBase {
    private:
        EAsymmetrics _algorithm;

    protected:
        /**
         * Sets the asymmetric algorithm of this key.
         * @param algorithm The asymmetric algorithm to set.
         */
        inline void algorithm(EAsymmetrics algorithm) {
            _algorithm = algorithm;
        }

    public:
        IAsymmetricKeyBase() {
            _algorithm = EASYM_UNKNOWN;
        }

        /**
         * Virtual destructor.
         */
        virtual ~IAsymmetricKeyBase() = default;

        /**
         * @return The key size, in the algorithm's natural unit (typically bits).
         */
        virtual SKeySize keySize() const = 0;

        /**
         * @return Which built-in algorithm produced this key -- e.g. to pick the right
         * SubjectPublicKeyInfo/signature OID when embedding it in a certificate, without the
         * caller having to separately track which IAsymmetric it came from.
         */
        inline EAsymmetrics algorithm() const {
            return _algorithm;
        }
    };

    /**
     * Enumeration of supported symmetric cryptographic algorithms.
     */
    enum ESymmetrics {
        ESYM_AES = 0,   /**< Advanced Encryption Standard */
        ESYM_DES,       /**< Data Encryption Standard */
        ESYM_3DES,      /**< Triple Data Encryption Standard */
        ESYM_CHACHA20,  /**< ChaCha20 stream cipher */

        ESYM_MAX,       /**< Maximum value for the enumeration */
        ESYM_UNKNOWN = 0xffffu, /**< Unknown algorithm */
    };

    // --> Forward declaration of the ISymmetricKeyBase interface.
    class ISymmetricKey;

    /* Shared pointer type for the ISymmetricKeyBase interface. */
    using ISymmetricKeyPtr = std::shared_ptr<ISymmetricKey>;

    /**
     * Key base for symmetric algorithms.
     */
    class CERTPP_API ISymmetricKey {
    private:
        COctet _keyData;
        ESymmetrics _algorithm;

    protected:
        /**
         * Sets the key data.
         * @param rawKey The key data to set.
         */
        inline void keyData(const COctet& keyData) {
            _keyData = keyData;
        }

        /**
         * Sets the symmetric algorithm of this key.
         * @param algorithm The symmetric algorithm to set.
         */
        inline void algorithm(ESymmetrics algorithm) {
            _algorithm = algorithm;
        }

    public:
        /**
         * Virtual destructor.
         */
        virtual ~ISymmetricKey() = default;

        /**
         * @return The key size, in bytes.
         */
        virtual size_t keySize() const = 0;

        /**
         * @return The symmetric algorithm of this key.
         */
        inline ESymmetrics algorithm() const {
            return _algorithm;
        }

        /**
         * @return The key data.
         */
        inline const COctet& keyData() const {
            return _keyData;
        }
    };

    // --> Forward declaration of the IPublicKey interface.
    class IPublicKey;

    /* Shared pointer type for the IPublicKey interface. */
    using IPublicKeyPtr = std::shared_ptr<IPublicKey>;

    /**
     * An asymmetric algorithm's public key. Produced by IAsymmetric::createPublicKey() or
     * SKeyPair::publicKey; never constructed directly.
     */
    class CERTPP_API IPublicKey : public IAsymmetricKeyBase {
    public:
        /**
         * Virtual destructor.
         */
        virtual ~IPublicKey() = default;
    };

    // --> Forward declaration of the IPrivateKey interface.
    class IPrivateKey;

    /* Shared pointer type for the IPrivateKey interface. */
    using IPrivateKeyPtr = std::shared_ptr<IPrivateKey>;

    /**
     * An asymmetric algorithm's private key. Produced by IAsymmetric::createPrivateKey() or
     * SKeyPair::privateKey; never constructed directly.
     */
    class CERTPP_API IPrivateKey : public IAsymmetricKeyBase {
    public:
        /**
         * Virtual destructor.
         */
        virtual ~IPrivateKey() = default;

        /**
         * @return This key's corresponding public key.
         */
        virtual IPublicKeyPtr publicKey() const = 0;
    };

    /**
     * A matched public/private key pair, as produced by IAsymmetric::generateKeyPair(). Each
     * half is used independently (via publicKey/privateKey), same as a key imported on its own
     * through IAsymmetric::createPublicKey()/createPrivateKey().
     */
    struct SKeyPair {
        IPublicKeyPtr publicKey;
        IPrivateKeyPtr privateKey;

        /**
         * Default constructor; both halves null.
         */
        SKeyPair() = default;

        /**
         * @param publicKey The public half.
         * @param privateKey The private half.
         */
        SKeyPair(IPublicKeyPtr publicKey, IPrivateKeyPtr privateKey)
            : publicKey(std::move(publicKey)), privateKey(std::move(privateKey)) {}

        /**
         * @return true if either half is null.
         */
        inline bool empty() const {
            return !publicKey || !privateKey;
        }

        inline operator bool() const {
            return !empty();
        }

        inline bool operator!() const {
            return empty();
        }

        /**
         * Compares this key pair with another key pair.
         *
         * @param other The other key pair to compare with.
         * @return A negative value if this is less than other, zero if equal, positive if greater.
         */
        inline int32_t compare(const SKeyPair& other) const {
            if (publicKey) {
                if (!other.publicKey) {
                    return 1;
                }

                int32_t dV = publicKey->compare(other.publicKey);
                if (dV != 0) {
                    return dV;
                }
            }

            else if (other.publicKey) {
                return -1;
            }

            if (privateKey) {
                if (!other.privateKey) {
                    return 1;
                }

                int32_t dV = privateKey->compare(other.privateKey);
                if (dV != 0) {
                    return dV;
                }
            }

            else if (other.privateKey) {
                return -1;
            }

            return 0;
        }

        /**
         * Equality operator for key pairs.
         *
         * @param other The other key pair to compare with.
         * @return true if both the public and private keys are equal, false otherwise.
         */
        inline bool operator==(const SKeyPair& other) const {
            return compare(other) == 0;
        }

        /**
         * Inequality operator for key pairs.
         *
         * @param other The other key pair to compare with.
         * @return true if either the public or private keys are not equal, false otherwise.
         */
        inline bool operator!=(const SKeyPair& other) const {
            return !(*this == other);
        }
    };

    /**
     * The key-encapsulation-mechanism (KEM) algorithms this library implements (see crypto/kems/
     * for each concrete IKem). A KEM is neither a signature algorithm (no sign()/verify()) nor
     * Diffie-Hellman-style key agreement (no deriveSharedSecret() between two independently
     * generated key pairs) -- it's IKem::encapsulate()/decapsulate(), see kem.hpp -- so it gets
     * its own key family here rather than reusing EAsymmetrics/IAsymmetricKeyBase, the same way
     * ESymmetrics/ISymmetricKey above don't reuse them either. Currently empty (no concrete IKem
     * exists yet -- see docs/pqc-review.md); the first entries will be ML-KEM's three parameter
     * sets.
     */
    enum EKems {
        EKEM_MAX = 0,   /**< Marker for the maximum value of EKems -- currently also 0, since no
                             concrete algorithm has been added yet. */
        EKEM_UNKNOWN = 0xffffu, /**< Unknown algorithm */
    };

    // --> Forward declaration of the IKemKeyBase interface.
    class IKemKeyBase;

    /* Shared pointer type for the IKemKeyBase interface. */
    using IKemKeyBasePtr = std::shared_ptr<IKemKeyBase>;

    /**
     * Key base for KEM algorithms (see EKems's own doc comment for why this doesn't reuse
     * IAsymmetricKeyBase).
     */
    class CERTPP_API IKemKeyBase : public IKeyBase {
    private:
        EKems _algorithm;

    protected:
        /**
         * Sets the KEM algorithm of this key.
         * @param algorithm The KEM algorithm to set.
         */
        inline void algorithm(EKems algorithm) {
            _algorithm = algorithm;
        }

    public:
        IKemKeyBase() {
            _algorithm = EKEM_UNKNOWN;
        }

        /**
         * Virtual destructor.
         */
        virtual ~IKemKeyBase() = default;

        /**
         * @return The key size, in the algorithm's natural unit -- for a fixed-parameter-set
         * algorithm like ML-KEM, its nominal parameter-set label (e.g. 512/768/1024), the same
         * way ESYM_AES's keySize() reports 128/192/256 rather than a continuously variable size.
         */
        virtual SKeySize keySize() const = 0;

        /**
         * @return Which built-in algorithm produced this key -- e.g. to pick the right
         * SubjectPublicKeyInfo/ciphertext OID when embedding it in a certificate/CMS structure,
         * without the caller having to separately track which IKem it came from.
         */
        inline EKems algorithm() const {
            return _algorithm;
        }
    };

    // --> Forward declaration of the IKemPublicKey interface.
    class IKemPublicKey;

    /* Shared pointer type for the IKemPublicKey interface. */
    using IKemPublicKeyPtr = std::shared_ptr<IKemPublicKey>;

    /**
     * A KEM algorithm's public (encapsulation) key. Produced by IKem::createPublicKey() or
     * SKemKeyPair::publicKey; never constructed directly.
     */
    class CERTPP_API IKemPublicKey : public IKemKeyBase {
    public:
        /**
         * Virtual destructor.
         */
        virtual ~IKemPublicKey() = default;
    };

    // --> Forward declaration of the IKemPrivateKey interface.
    class IKemPrivateKey;

    /* Shared pointer type for the IKemPrivateKey interface. */
    using IKemPrivateKeyPtr = std::shared_ptr<IKemPrivateKey>;

    /**
     * A KEM algorithm's private (decapsulation) key. Produced by IKem::createPrivateKey() or
     * SKemKeyPair::privateKey; never constructed directly.
     */
    class CERTPP_API IKemPrivateKey : public IKemKeyBase {
    public:
        /**
         * Virtual destructor.
         */
        virtual ~IKemPrivateKey() = default;

        /**
         * @return This key's corresponding public key.
         */
        virtual IKemPublicKeyPtr publicKey() const = 0;
    };

    /**
     * A matched encapsulation/decapsulation key pair, as produced by IKem::generateKeyPair().
     * Mirrors SKeyPair exactly, for the KEM key family instead of the asymmetric one.
     */
    struct SKemKeyPair {
        IKemPublicKeyPtr publicKey;
        IKemPrivateKeyPtr privateKey;

        /**
         * Default constructor; both halves null.
         */
        SKemKeyPair() = default;

        /**
         * @param publicKey The public half.
         * @param privateKey The private half.
         */
        SKemKeyPair(IKemPublicKeyPtr publicKey, IKemPrivateKeyPtr privateKey)
            : publicKey(std::move(publicKey)), privateKey(std::move(privateKey)) {}

        /**
         * @return true if either half is null.
         */
        inline bool empty() const {
            return !publicKey || !privateKey;
        }

        inline operator bool() const {
            return !empty();
        }

        inline bool operator!() const {
            return empty();
        }

        /**
         * Compares this key pair with another key pair.
         *
         * @param other The other key pair to compare with.
         * @return A negative value if this is less than other, zero if equal, positive if greater.
         */
        inline int32_t compare(const SKemKeyPair& other) const {
            if (publicKey) {
                if (!other.publicKey) {
                    return 1;
                }

                int32_t dV = publicKey->compare(other.publicKey);
                if (dV != 0) {
                    return dV;
                }
            }

            else if (other.publicKey) {
                return -1;
            }

            if (privateKey) {
                if (!other.privateKey) {
                    return 1;
                }

                int32_t dV = privateKey->compare(other.privateKey);
                if (dV != 0) {
                    return dV;
                }
            }

            else if (other.privateKey) {
                return -1;
            }

            return 0;
        }

        /**
         * Equality operator for key pairs.
         *
         * @param other The other key pair to compare with.
         * @return true if both the public and private keys are equal, false otherwise.
         */
        inline bool operator==(const SKemKeyPair& other) const {
            return compare(other) == 0;
        }

        /**
         * Inequality operator for key pairs.
         *
         * @param other The other key pair to compare with.
         * @return true if either the public or private keys are not equal, false otherwise.
         */
        inline bool operator!=(const SKemKeyPair& other) const {
            return !(*this == other);
        }
    };

} // namespace crypto
} // namespace certpp

#endif
