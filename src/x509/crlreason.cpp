#include "crlreason.hpp"

namespace certpp {
namespace x509 {

    const CrlReasonCodec::SMap CrlReasonCodec::TABLE[] = {
        { 1, ECRLR_KEY_COMPROMISE },
        { 2, ECRLR_CA_COMPROMISE },
        { 3, ECRLR_AFFILIATION_CHANGED },
        { 4, ECRLR_SUPERSEDED },
        { 5, ECRLR_CESSATION_OF_OPERATION },
        { 6, ECRLR_CERTIFICATE_HOLD },
        { 9, ECRLR_PRIVILEGE_WITHDRAWN },
        { 10, ECRLR_AA_COMPROMISE },
    };

    /* Converts a CRLReason ENUMERATED value to its ECrlReasons flag. */
    ECrlReasons CrlReasonCodec::toFlag(uint32_t value) {
        for (const SMap& m : TABLE) {
            if (m.enumValue == value) {
                return m.flag;
            }
        }
        return ECRLR_NONE;
    }

    /* Converts an ECrlReasons flag to its CRLReason ENUMERATED value. */
    bool CrlReasonCodec::toEnumValue(ECrlReasons flag, uint32_t& outValue) {
        for (const SMap& m : TABLE) {
            if (m.flag == flag) {
                outValue = m.enumValue;
                return true;
            }
        }
        return false;
    }

} // namespace x509
} // namespace certpp
