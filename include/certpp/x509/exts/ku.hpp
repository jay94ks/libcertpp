#ifndef __INCLUDE_CERTPP_X509_EXTS_KU_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_KU_HPP__

#include <certpp/x509/ext.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief Enumeration of key usages for X.509 certificates (RFC 5280 4.2.1.3's KeyUsage
     * BIT STRING). Note this enum's bit positions do not follow the BIT STRING's own named-bit
     * numbering (0 = digitalSignature ... 8 = decipherOnly) directly -- see
     * CKeyUsagesExtension's decoding, which maps between the two.
     */
    enum EKeyUsages : uint16_t {
        EKUSE_NONE = 0,
        EKUSE_ENCIPHER_ONLY         = (1u << 0),
        EKUSE_CRL_SIGN              = (1u << 1),
        EKUSE_KEY_CERT_SIGN         = (1u << 2),
        EKUSE_KEY_AGREEMENT         = (1u << 3),
        EKUSE_DATA_ENCIPHERMENT     = (1u << 4),
        EKUSE_KEY_ENCIPHERMENT      = (1u << 5),
        EKUSE_NON_REPUDIATION       = (1u << 6),
        EKUSE_DIGITAL_SIGNATURE     = (1u << 7),
        EKUSE_DECIPHER_ONLY         = (1u << 8),
    };

    /**
     * @brief KeyUsage (RFC 5280 4.2.1.3, OID 2.5.29.15): the purposes this certificate's public
     * key may be used for.
     */
    class CERTPP_API CKeyUsagesExtension : public IExtension {
    public:
        static constexpr const char* OID = "2.5.29.15"; // --> id-ce-keyUsage

    private:
        uint16_t _bits = EKUSE_NONE;

    public:
        /**
         * @brief Parses a KeyUsage extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CKeyUsagesExtension(const COctet& value);

        /**
         * @brief The decoded key usages: a bitwise combination of EKeyUsages flags. EKUSE_NONE
         * if value didn't decode as a BIT STRING.
         * @return The key usages.
         */
        inline uint16_t bits() const { return _bits; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds a KeyUsage extension (see CKeyUsagesExtension).
     */
    class CERTPP_API CKeyUsagesExtensionBuilder : public IExtensionBuilder {
    private:
        uint16_t _bits = EKUSE_NONE;

    public:
        /**
         * @brief Sets the key usages.
         * @param bits A bitwise combination of EKeyUsages flags.
         * @return A reference to this builder, for chaining.
         */
        inline CKeyUsagesExtensionBuilder& setBits(uint16_t bits) {
            _bits = bits;
            return *this;
        }

        /* Builds the KeyUsage extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
