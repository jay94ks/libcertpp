#ifndef __INCLUDE_CERTPP_X509_EXTS_BC_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_BC_HPP__

#include <certpp/x509/ext.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief BasicConstraints (RFC 5280 4.2.1.9, OID 2.5.29.19): whether this certificate may
     * act as a CA, and (only meaningful when it can) how many further intermediate CAs may
     * follow it in a certification path.
     */
    class CERTPP_API CBasicConstraintsExtension : public IExtension {
    public:
        static constexpr const char* OID = "2.5.29.19"; // --> id-ce-basicConstraints

    private:
        bool _isCa = false;
        bool _hasPathLenConstraint = false;
        int64_t _pathLenConstraint = 0;

    public:
        /**
         * @brief Parses a BasicConstraints extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CBasicConstraintsExtension(const COctet& value);

        /**
         * @brief Whether this certificate may act as a CA. False (the DER default) if absent or
         * malformed.
         * @return true if this certificate may act as a CA.
         */
        inline bool isCa() const { return _isCa; }

        /**
         * @brief Whether pathLenConstraint() is present. Only meaningful when isCa() is true.
         * @return true if pathLenConstraint() is present.
         */
        inline bool hasPathLenConstraint() const { return _hasPathLenConstraint; }

        /**
         * @brief The maximum number of non-self-issued intermediate CA certificates that may
         * follow this one in a valid certification path. Only meaningful when
         * hasPathLenConstraint() is true.
         * @return The path length constraint.
         */
        inline int64_t pathLenConstraint() const { return _pathLenConstraint; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds a BasicConstraints extension (see CBasicConstraintsExtension).
     */
    class CERTPP_API CBasicConstraintsExtensionBuilder : public IExtensionBuilder {
    private:
        bool _isCa = false;
        bool _hasPathLenConstraint = false;
        int64_t _pathLenConstraint = 0;

    public:
        /**
         * @brief Sets whether this certificate may act as a CA.
         * @param isCa true if this certificate may act as a CA.
         * @return A reference to this builder, for chaining.
         */
        inline CBasicConstraintsExtensionBuilder& setIsCa(bool isCa) {
            _isCa = isCa;
            return *this;
        }

        /**
         * @brief Sets the path length constraint. Only meaningful when isCa() is true.
         * @param pathLenConstraint The maximum number of non-self-issued intermediate CA
         * certificates that may follow this one in a valid certification path.
         * @return A reference to this builder, for chaining.
         */
        inline CBasicConstraintsExtensionBuilder& setPathLenConstraint(int64_t pathLenConstraint) {
            _hasPathLenConstraint = true;
            _pathLenConstraint = pathLenConstraint;
            return *this;
        }

        /**
         * @brief Removes a previously-set path length constraint.
         * @return A reference to this builder, for chaining.
         */
        inline CBasicConstraintsExtensionBuilder& clearPathLenConstraint() {
            _hasPathLenConstraint = false;
            _pathLenConstraint = 0;
            return *this;
        }

        /* Builds the BasicConstraints extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
