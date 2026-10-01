#ifndef __SRC_X509_CRLREASON_HPP__
#define __SRC_X509_CRLREASON_HPP__

#include <certpp/x509/access.hpp>

namespace certpp {
namespace x509 {

    /**
     * Converts between CRLReason (RFC 5280 5.3.1)'s ENUMERATED wire value and ECrlReasons'
     * single-bit flag representation. Shared by CCrlRevokationInfo's own reasonCode extension
     * (RFC 5280 5.3.1) and COcspEntry's RevokedInfo.revocationReason (RFC 6960 4.2.1), which are
     * defined over the identical CRLReason type.
     *
     * Deliberately NOT a uniform bit-shift: ReasonFlags (the BIT STRING
     * CDistributionPoint::reasons() represents) and CRLReason (this single-value ENUMERATED)
     * number privilegeWithdrawn/aACompromise differently -- ReasonFlags bit positions 7/8 vs
     * CRLReason's ENUMERATED values 9/10 (see ECrlReasons' own definition in access.hpp, and
     * access.cpp's analogous bit-position table for ReasonFlags). ENUMERATED value 8
     * (removeFromCRL, a delta-CRL-only "this entry no longer applies" marker) has no
     * corresponding ECrlReasons bit at all -- a known, accepted gap, since delta CRLs aren't
     * otherwise supported by CCrlRevokationInfo/COcspEntry.
     */
    class CrlReasonCodec {
    private:
        struct SMap {
            uint32_t enumValue;
            ECrlReasons flag;
        };

        static const SMap TABLE[];

    public:
        /**
         * Converts a CRLReason ENUMERATED value to its ECrlReasons flag.
         * @param value The CRLReason ENUMERATED value, as decoded from the wire.
         * @return The corresponding flag, or ECRLR_NONE if value has no corresponding flag.
         */
        static ECrlReasons toFlag(uint32_t value);

        /**
         * Converts an ECrlReasons flag to its CRLReason ENUMERATED value.
         * @param flag The flag to convert.
         * @param outValue Receives the ENUMERATED value on success.
         * @return true if flag has a defined ENUMERATED value; false otherwise.
         */
        static bool toEnumValue(ECrlReasons flag, uint32_t& outValue);
    };

} // namespace x509
} // namespace certpp

#endif
