#ifndef __INCLUDE_CERTPP_X509_EXTS_NC_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_NC_HPP__

#include <certpp/x509/ext.hpp>
#include <certpp/x509/generalname.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief NameConstraints (RFC 5280 4.2.1.10, OID 2.5.29.30): restricts the namespace a CA
     * (this extension only has meaning on a CA certificate) is permitted or excluded from
     * certifying subordinate certificates for.
     */
    class CERTPP_API CNameConstraintsExtension : public IExtension {
    public:
        static constexpr const char* OID = "2.5.29.30"; // --> id-ce-nameConstraints

    private:
        TArray<CGeneralSubtree> _permittedSubtrees;
        TArray<CGeneralSubtree> _excludedSubtrees;

        /* Decodes a GeneralSubtrees (SEQUENCE OF GeneralSubtree) from its own SEQUENCE's content
         * octets. */
        static void decodeGeneralSubtrees(SReadOnlyByteSpan content, TArray<CGeneralSubtree>& out);

    public:
        /**
         * @brief Parses a NameConstraints extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CNameConstraintsExtension(const COctet& value);

        /**
         * @brief The namespace subordinate certificates are permitted to be issued within.
         * Empty if absent.
         * @return The permitted subtrees.
         */
        inline const TArray<CGeneralSubtree>& permittedSubtrees() const { return _permittedSubtrees; }

        /**
         * @brief The namespace subordinate certificates are excluded from being issued within
         * (takes precedence over permittedSubtrees() on overlap). Empty if absent.
         * @return The excluded subtrees.
         */
        inline const TArray<CGeneralSubtree>& excludedSubtrees() const { return _excludedSubtrees; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds a NameConstraints extension (see CNameConstraintsExtension).
     */
    class CERTPP_API CNameConstraintsExtensionBuilder : public IExtensionBuilder {
    private:
        TArray<CGeneralSubtree> _permittedSubtrees;
        TArray<CGeneralSubtree> _excludedSubtrees;

        /* Encodes a GeneralSubtrees (SEQUENCE OF GeneralSubtree) list, appending each element's
         * own SEQUENCE TLV to out -- the inverse of CNameConstraintsExtension::decodeGeneralSubtrees(). */
        static bool encodeGeneralSubtrees(const TArray<CGeneralSubtree>& subtrees, CBuffer& out);

    public:
        /**
         * @brief Adds a permitted subtree.
         * @param subtree The subtree to add.
         * @return A reference to this builder, for chaining.
         */
        inline CNameConstraintsExtensionBuilder& addPermittedSubtree(const CGeneralSubtree& subtree) {
            _permittedSubtrees.add(subtree);
            return *this;
        }

        /**
         * @brief Adds an excluded subtree.
         * @param subtree The subtree to add.
         * @return A reference to this builder, for chaining.
         */
        inline CNameConstraintsExtensionBuilder& addExcludedSubtree(const CGeneralSubtree& subtree) {
            _excludedSubtrees.add(subtree);
            return *this;
        }

        /* Builds the NameConstraints extension. */
        IExtensionPtr build() const override;
    };

}
}

#endif
