#include <certpp/crypto/hashers/sha3_256.hpp>
#include "sha3core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    void SHA3_256::reset() {
        std::memset(_ctx.state, 0, sizeof(_ctx.state));
        std::memset(_ctx.buffer, 0, sizeof(_ctx.buffer));
        _ctx.bufferLen = 0;
    }

    size_t SHA3_256::push(const SReadOnlyByteSpan& buf) {
        return Sha3Core::absorb(_ctx.state, _ctx.buffer, _ctx.bufferLen, RATE, buf);
    }

    bool SHA3_256::finish(const SByteSpan& out) {
        if (out.size < DIGEST_BYTES || !out.data) {
            return false;
        }

        Sha3Core::digest(_ctx.state, _ctx.buffer, _ctx.bufferLen, RATE, out.data, DIGEST_BYTES);
        return true;
    }

} // namespace crypto
} // namespace certpp
