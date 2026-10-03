#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/hashers/md5.hpp>
#include <certpp/crypto/hashers/sha1.hpp>
#include <certpp/crypto/hashers/sha224.hpp>
#include <certpp/crypto/hashers/sha256.hpp>
#include <certpp/crypto/hashers/sha384.hpp>
#include <certpp/crypto/hashers/sha512.hpp>
#include <certpp/crypto/hashers/sha3_256.hpp>
#include <certpp/crypto/hashers/sha3_512.hpp>
#include <certpp/crypto/hashers/shake128.hpp>
#include <certpp/crypto/hashers/shake256.hpp>
#include <certpp/crypto/hashers/streebog256.hpp>
#include <certpp/crypto/hashers/streebog512.hpp>

namespace certpp {
namespace crypto {

    /* Creates a hasher instance based on the specified built-in hasher type. */
    ERetCode IHasher::create(EHashers hasherType, IHasherPtr& out) {
        switch (hasherType) {
            case EHASH_MD5:
                out = std::make_shared<MD5>();
                return ERET_OK;

            case EHASH_SHA1:
                out = std::make_shared<SHA1>();
                return ERET_OK;

            case EHASH_SHA224:
                out = std::make_shared<SHA224>();
                return ERET_OK;

            case EHASH_SHA256:
                out = std::make_shared<SHA256>();
                return ERET_OK;

            case EHASH_SHA384:
                out = std::make_shared<SHA384>();
                return ERET_OK;

            case EHASH_SHA512:
                out = std::make_shared<SHA512>();
                return ERET_OK;

            case EHASH_SHA3_256: out = std::make_shared<SHA3_256>(); return ERET_OK;

            case EHASH_SHA3_512: out = std::make_shared<SHA3_512>(); return ERET_OK;

            case EHASH_SHAKE128:
                out = std::make_shared<SHAKE128>();
                return ERET_OK;

            case EHASH_SHAKE256:
                out = std::make_shared<SHAKE256>();
                return ERET_OK;

            case EHASH_STREEBOG256:
                out = std::make_shared<Streebog256>();
                return ERET_OK;

            case EHASH_STREEBOG512:
                out = std::make_shared<Streebog512>();
                return ERET_OK;

            default:
                return ERET_NOTIMPL;
        }
    }

} // namespace crypto
} // namespace certpp
