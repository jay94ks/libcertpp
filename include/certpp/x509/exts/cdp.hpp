#ifndef __INCLUDE_CERTPP_X509_EXTS_CDP_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_CDP_HPP__

#include <certpp/x509/ext.hpp>
#include <certpp/x509/access.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief CRLDistributionPoints (RFC 5280 4.2.1.13, OID 2.5.29.31): where to find the
     * certificate revocation list(s) covering this certificate.
     */
    class CERTPP_API CCdpExtension : public IExtension {
    public:
        static constexpr const char* OID = "2.5.29.31"; // --> id-ce-cRLDistributionPoints

    private:
        TArray<CDistributionPoint> _points;

    public:
        /**
         * @brief Parses a CRLDistributionPoints extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CCdpExtension(const COctet& value);

        /**
         * @brief The decoded distribution points. Empty if value didn't decode as a SEQUENCE OF
         * DistributionPoint.
         * @return The distribution points.
         */
        inline const TArray<CDistributionPoint>& points() const { return _points; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds a CRLDistributionPoints extension (see CCdpExtension).
     */
    class CERTPP_API CCdpExtensionBuilder : public IExtensionBuilder {
    private:
        TArray<CDistributionPoint> _points;

    public:
        /**
         * @brief Adds a distribution point.
         * @param point The distribution point to add.
         * @return A reference to this builder, for chaining.
         */
        inline CCdpExtensionBuilder& addPoint(const CDistributionPoint& point) {
            _points.add(point);
            return *this;
        }

        /* Builds the CRLDistributionPoints extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
