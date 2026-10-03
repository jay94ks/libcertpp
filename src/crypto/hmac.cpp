#include <certpp/crypto/hmac.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        constexpr uint8_t IPAD = 0x36;
        constexpr uint8_t OPAD = 0x5C;

        /* The largest digest any hash HMAC is defined over here produces: SHA-512, SHA3-512 and
         * Streebog-512 all at 64 bytes. Named so the stack buffers below state what bounds them. */
        constexpr size_t MAX_DIGEST_BYTES = 64;

    } // namespace

    /* Constructs an unkeyed instance. */
    CHmac::CHmac() : _algorithm(EHASH_UNKNOWN), _blockBytes(0) {
        std::memset(_key, 0, sizeof(_key));
    }

    /* Clears the padded key. */
    CHmac::~CHmac() {
        CSecure::zero(SByteSpan(_key, sizeof(_key)));
    }

    /* The block size RFC 2104 uses for a given hash. */
    size_t CHmac::blockBytesOf(EHashers hasherType) {
        switch (hasherType) {
            case EHASH_MD5:
            case EHASH_SHA1:
            case EHASH_SHA224:
            case EHASH_SHA256:
                return 64;

            case EHASH_SHA384:
            case EHASH_SHA512:
                return 128;

            // --> SHA-3's "block size" for HMAC's purposes is its sponge rate, which differs per
            // output length rather than being shared the way SHA-2's is.
            case EHASH_SHA3_256:
                return 136;

            case EHASH_SHA3_512:
                return 72;

            // --> Streebog's compression function takes a 512-bit block, and RFC 7836
            // sections 4.1.1/4.1.2 fix B = 64 for both digest lengths -- unlike SHA-2, the
            // 512-bit variant does not get a wider block.
            case EHASH_STREEBOG256:
            case EHASH_STREEBOG512:
                return 64;

            // SHAKE is an XOF with a caller-chosen output length; RFC 2104 is defined over a
            // fixed-output hash, so HMAC-SHAKE is not a thing and is refused rather than guessed.
            default:
                return 0;
        }
    }

    /* Keys this instance and starts a fresh message. */
    ERetCode CHmac::reset(EHashers hasherType, const SReadOnlyByteSpan& key) {
        const size_t blockBytes = blockBytesOf(hasherType);
        if (blockBytes == 0) {
            return ERET_NOTSUP;
        }
        if (blockBytes > sizeof(_key)) {
            return ERET_NOTSUP; // MAX_BLOCK_BYTES is out of step with blockBytesOf()
        }
        if (key.size != 0 && !key.data) {
            return ERET_BADREQ;
        }

        // Reuse the hasher when the algorithm has not changed -- re-keying in HKDF's expand loop
        // happens once per output block, and allocating there would be pointless churn.
        if (!_hasher || _algorithm != hasherType) {
            IHasherPtr hasher;
            const ERetCode rc = IHasher::create(hasherType, hasher);
            if (rc != ERET_OK) {
                return rc;
            }

            _hasher = hasher;
            _algorithm = hasherType;
        }

        _blockBytes = blockBytes;

        // RFC 2104 2: a key longer than the block is replaced by its own hash; a shorter one is
        // zero-padded up. Note the long-key case hashes to byteWidth() bytes, which is always
        // less than the block size, so it then takes the padding path too.
        CSecure::zero(SByteSpan(_key, sizeof(_key)));

        if (key.size > blockBytes) {
            _hasher->reset();
            if (key.size != 0 && _hasher->push(key) != key.size) {
                return ERET_HASH_PIPE;
            }
            if (!_hasher->finish(SByteSpan(_key, _hasher->byteWidth()))) {
                return ERET_HASH_PIPE;
            }
        }
        else if (key.size != 0) {
            std::memcpy(_key, key.data, key.size);
        }

        // Start the inner hash: H((K ^ ipad) || ...
        uint8_t pad[MAX_BLOCK_BYTES];
        for (size_t i = 0; i < blockBytes; ++i) {
            pad[i] = uint8_t(_key[i] ^ IPAD);
        }

        _hasher->reset();
        const bool pushed = _hasher->push(SReadOnlyByteSpan(pad, blockBytes)) == blockBytes;

        // The padded key XORed with ipad is key-derived, so it does not outlive this call.
        CSecure::zero(SByteSpan(pad, sizeof(pad)));

        return pushed ? ERET_OK : ERET_HASH_PIPE;
    }

    /* The tag length. */
    size_t CHmac::byteWidth() const {
        return _hasher ? _hasher->byteWidth() : 0;
    }

    /* Absorbs message bytes. */
    size_t CHmac::push(const SReadOnlyByteSpan& buf) {
        if (!_hasher || _blockBytes == 0) {
            return 0;
        }
        if (buf.size == 0) {
            return 0;
        }

        return _hasher->push(buf);
    }

    /* Finalizes and writes the tag. */
    bool CHmac::finish(const SByteSpan& out) {
        if (!_hasher || _blockBytes == 0) {
            return false;
        }

        const size_t width = _hasher->byteWidth();
        if (out.size != width || !out.data) {
            return false;
        }

        // IHasher::finish() is a query that leaves the sponge/state alone, so the inner digest
        // can be taken without disturbing the message absorbed so far -- which is what lets this
        // whole function be a query too, matching IHasher's own contract.
        uint8_t inner[MAX_DIGEST_BYTES];
        if (width > sizeof(inner)) {
            return false;
        }
        if (!_hasher->finish(SByteSpan(inner, width))) {
            return false;
        }

        uint8_t pad[MAX_BLOCK_BYTES];
        for (size_t i = 0; i < _blockBytes; ++i) {
            pad[i] = uint8_t(_key[i] ^ OPAD);
        }

        // The outer hash runs on a scratch instance so this instance's absorbed message survives
        // -- otherwise finish() could only be called once, unlike every IHasher here.
        IHasherPtr outer;
        bool ok = IHasher::create(_algorithm, outer) == ERET_OK && outer;

        if (ok) {
            ok = outer->push(SReadOnlyByteSpan(pad, _blockBytes)) == _blockBytes
              && outer->push(SReadOnlyByteSpan(inner, width)) == width
              && outer->finish(out);
        }

        CSecure::zero(SByteSpan(pad, sizeof(pad)));
        CSecure::zero(SByteSpan(inner, sizeof(inner)));

        return ok;
    }

    /* One-shot HMAC. */
    ERetCode CHmac::compute(
        EHashers hasherType, const SReadOnlyByteSpan& key,
        const SReadOnlyByteSpan& message, const SByteSpan& out
    ) {
        CHmac mac;

        const ERetCode rc = mac.reset(hasherType, key);
        if (rc != ERET_OK) {
            return rc;
        }

        if (message.size != 0 && mac.push(message) != message.size) {
            return ERET_HASH_PIPE;
        }

        return mac.finish(out) ? ERET_OK : ERET_NOSPC;
    }

    /* One-shot HMAC verification, in constant time with respect to the tag's contents. */
    bool CHmac::verify(
        EHashers hasherType, const SReadOnlyByteSpan& key,
        const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& tag
    ) {
        if (tag.size == 0 || !tag.data) {
            return false;
        }

        uint8_t expected[MAX_DIGEST_BYTES];

        CHmac mac;
        if (mac.reset(hasherType, key) != ERET_OK) {
            return false;
        }

        const size_t full = mac.byteWidth();
        if (full == 0 || full > sizeof(expected) || tag.size > full) {
            return false;
        }

        if (message.size != 0 && mac.push(message) != message.size) {
            return false;
        }
        if (!mac.finish(SByteSpan(expected, full))) {
            return false;
        }

        // RFC 2104 4 allows a truncated tag, so only the bytes the caller presented are
        // compared -- but through equalsMask, never memcmp: a comparison that stops at the first
        // difference tells an attacker how long a prefix they guessed, which is enough to forge
        // a tag one byte at a time.
        const bool equal = CSecure::equals(
            SReadOnlyByteSpan(expected, tag.size), tag);

        CSecure::zero(SByteSpan(expected, sizeof(expected)));
        return equal;
    }

} // namespace crypto
} // namespace certpp
