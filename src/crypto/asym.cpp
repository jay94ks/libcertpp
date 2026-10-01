#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/asyms/rsa.hpp>
#include <certpp/crypto/asyms/dsa.hpp>
#include <certpp/crypto/asyms/ecdsa.hpp>
#include <certpp/crypto/asyms/ed25519.hpp>
#include <certpp/crypto/asyms/ed448.hpp>
#include <certpp/crypto/asyms/x25519.hpp>
#include <certpp/crypto/asyms/ecdsa2.hpp>

namespace certpp {
namespace crypto {

    IAsymmetricPtr IAsymmetric::builtIn(EAsymmetrics which) {
        switch (which) {
            case EASYM_RSA:
                return std::make_shared<RSA>();

            case EASYM_DSA:
                return std::make_shared<DSA>();

            case EASYM_ED25519:
                return std::make_shared<Ed25519>();

            case EASYM_ED448:
                return std::make_shared<Ed448>();

            case EASYM_P192:
                return std::make_shared<CEcdsa>(ECURVE_P192);

            case EASYM_P224:
                return std::make_shared<CEcdsa>(ECURVE_P224);

            case EASYM_P256:
                return std::make_shared<CEcdsa>(ECURVE_P256);

            case EASYM_P384:
                return std::make_shared<CEcdsa>(ECURVE_P384);

            case EASYM_P521:
                return std::make_shared<CEcdsa>(ECURVE_P521);

            case EASYM_SECP256K1:
                return std::make_shared<CEcdsa>(ECURVE_SECP256K1);

            case EASYM_BPOOL160R1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL160R1);

            case EASYM_BPOOL192R1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL192R1);

            case EASYM_BPOOL224R1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL224R1);

            case EASYM_BPOOL256R1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL256R1);

            case EASYM_BPOOL320R1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL320R1);

            case EASYM_BPOOL384R1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL384R1);

            case EASYM_BPOOL512R1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL512R1);

            case EASYM_BPOOL160T1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL160T1);

            case EASYM_BPOOL192T1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL192T1);

            case EASYM_BPOOL224T1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL224T1);

            case EASYM_BPOOL256T1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL256T1);

            case EASYM_BPOOL320T1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL320T1);

            case EASYM_BPOOL384T1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL384T1);

            case EASYM_BPOOL512T1:
                return std::make_shared<CEcdsa>(ECURVE_BPOOL512T1);

            case EASYM_X25519:
                return std::make_shared<X25519>();

            case EASYM_B163:
                return std::make_shared<CEcdsa2>(ECURVE2_B163);

            case EASYM_K163:
                return std::make_shared<CEcdsa2>(ECURVE2_K163);

            case EASYM_B233:
                return std::make_shared<CEcdsa2>(ECURVE2_B233);

            case EASYM_K233:
                return std::make_shared<CEcdsa2>(ECURVE2_K233);

            case EASYM_B283:
                return std::make_shared<CEcdsa2>(ECURVE2_B283);

            case EASYM_K283:
                return std::make_shared<CEcdsa2>(ECURVE2_K283);

            case EASYM_B409:
                return std::make_shared<CEcdsa2>(ECURVE2_B409);

            case EASYM_K409:
                return std::make_shared<CEcdsa2>(ECURVE2_K409);

            case EASYM_B571:
                return std::make_shared<CEcdsa2>(ECURVE2_B571);

            case EASYM_K571:
                return std::make_shared<CEcdsa2>(ECURVE2_K571);

            default:
                return nullptr;
        }
    }

} // namespace crypto
} // namespace certpp
