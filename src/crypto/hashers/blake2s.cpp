#include <certpp/crypto/hashers/blake2s.hpp>
#include "blake2score.hpp"

namespace certpp {
namespace crypto {

    /* Resets the BLAKE2s context to its initial state. */
    void BLAKE2s::reset() {
        // --> The digest length is part of the parameter block, so it has to be re-folded into the
        // state on every reset, not just at construction.
        Blake2sCore::init(
            _ctx.state, _ctx.buffer, _ctx.bufferLen, _ctx.counter,
            byteWidth(), SReadOnlyByteSpan(nullptr, 0)
        );
    }

    /* Pushes data into the BLAKE2s context for hashing. */
    size_t BLAKE2s::push(const SReadOnlyByteSpan& buf) {
        return Blake2sCore::absorb(
            _ctx.state, _ctx.buffer, _ctx.bufferLen, _ctx.counter, buf);
    }

    /* Finalizes the BLAKE2s hash computation and writes the result. */
    bool BLAKE2s::finish(const SByteSpan& out) {
        if (out.size < byteWidth() || !out.data) {
            return false;
        }

        Blake2sCore::digest(
            _ctx.state, _ctx.buffer, _ctx.bufferLen, _ctx.counter, out.data, byteWidth());

        return true;
    }

} // namespace crypto
} // namespace certpp
