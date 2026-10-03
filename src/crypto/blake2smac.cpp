#include <certpp/crypto/blake2smac.hpp>
#include <certpp/utils/secure.hpp>
#include "hashers/blake2score.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    /* Constructs an unkeyed instance. */
    CBlake2sMac::CBlake2sMac() : _buffered(0), _counter(0), _tagBytes(0) {
        std::memset(_state, 0, sizeof(_state));
        std::memset(_buffer, 0, sizeof(_buffer));
    }

    /* Clears the state and the buffered key block. */
    CBlake2sMac::~CBlake2sMac() {
        // --> The key sits in _buffer until the first full block is compressed, and the state is
        // key-derived from the very first compression onwards, so both have to go.
        CSecure::zero(SByteSpan(_buffer, sizeof(_buffer)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_state), sizeof(_state)));
    }

    /* Keys this instance and starts a fresh message. */
    bool CBlake2sMac::reset(const SReadOnlyByteSpan& key, size_t tagBytes) {
        if (tagBytes == 0 || tagBytes > MAX_TAG_BYTES) {
            return false;
        }
        if (key.size > MAX_KEY_BYTES) {
            return false;
        }
        if (key.size != 0 && !key.data) {
            return false;
        }

        Blake2sCore::init(_state, _buffer, _buffered, _counter, tagBytes, key);
        _tagBytes = tagBytes;

        return true;
    }

    /* The tag length. */
    size_t CBlake2sMac::byteWidth() const {
        return _tagBytes;
    }

    /* Absorbs message bytes. */
    size_t CBlake2sMac::push(const SReadOnlyByteSpan& buf) {
        if (_tagBytes == 0) {
            return 0;
        }

        return Blake2sCore::absorb(_state, _buffer, _buffered, _counter, buf);
    }

    /* Finalizes and writes the tag. */
    bool CBlake2sMac::finish(const SByteSpan& out) {
        if (_tagBytes == 0) {
            return false;
        }
        if (out.size < _tagBytes || !out.data) {
            return false;
        }

        Blake2sCore::digest(_state, _buffer, _buffered, _counter, out.data, _tagBytes);
        return true;
    }

    /* One-shot keyed BLAKE2s. */
    bool CBlake2sMac::compute(
        const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message,
        const SByteSpan& out
    ) {
        if (out.size == 0 || out.size > MAX_TAG_BYTES || !out.data) {
            return false;
        }

        CBlake2sMac mac;
        if (!mac.reset(key, out.size)) {
            return false;
        }
        if (message.size != 0 && mac.push(message) != message.size) {
            return false;
        }

        return mac.finish(out);
    }

    /* One-shot verification, in constant time with respect to the tag's contents. */
    bool CBlake2sMac::verify(
        const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message,
        const SReadOnlyByteSpan& tag
    ) {
        if (tag.size == 0 || tag.size > MAX_TAG_BYTES || !tag.data) {
            return false;
        }

        // --> The tag length is part of the parameter block, so the sender's choice of length is
        // recomputed rather than a full-length tag being truncated: a 16-byte keyed BLAKE2s is
        // not the first 16 bytes of the 32-byte one.
        uint8_t expected[MAX_TAG_BYTES];
        if (!compute(key, message, SByteSpan(expected, tag.size))) {
            return false;
        }

        // Never memcmp: a comparison that stops at the first difference tells an attacker how long
        // a prefix they guessed, which is enough to forge a tag one byte at a time.
        const bool equal = CSecure::equals(
            SReadOnlyByteSpan(expected, tag.size), tag);

        CSecure::zero(SByteSpan(expected, sizeof(expected)));
        return equal;
    }

} // namespace crypto
} // namespace certpp
