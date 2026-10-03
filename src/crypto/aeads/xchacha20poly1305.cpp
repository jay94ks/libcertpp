#include <certpp/crypto/aeads/xchacha20poly1305.hpp>
#include <certpp/crypto/aeads/chacha20poly1305.hpp>
#include <certpp/utils/secure.hpp>
#include "../syms/chacha20core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* The inner context for one record: the subkey HChaCha20 derives from the first 16 nonce
         * bytes, keying an ordinary RFC 8439 ChaCha20-Poly1305, plus the 96-bit nonce that AEAD is
         * then given.
         *
         * It is a stack object rather than a cached member because the subkey depends on the
         * nonce, so there is nothing a reused context could keep: every record derives its own.
         * That costs one ChaCha20 permutation and some eighty bytes of stack per call, and no
         * allocation -- which is the contract CChaCha20Poly1305 sets and this has to match. The
         * destructor clears the subkey; the AEAD's own destructor clears the copy it took. */
        struct Inner {
            CChaCha20Poly1305 aead;
            uint8_t nonce[CChaCha20Poly1305::NONCE_BYTES];
            uint8_t subkey[ChaCha20Core::SUBKEY_BYTES];

            ~Inner() {
                CSecure::zero(SByteSpan(subkey, sizeof(subkey)));
            }

            /* false if the subkey could not key the inner AEAD, which cannot happen for a
             * 32-byte subkey but is checked rather than assumed. */
            bool prepare(const uint8_t key[ChaCha20Core::KEY_BYTES], const uint8_t* nonce24) {
                ChaCha20Core::hchacha20(key, nonce24, subkey);

                // --> Four zero bytes *first*, then the nonce's last eight. The reverse order
                // produces a working AEAD that no other implementation can read, and nothing but
                // a published vector will say so.
                std::memset(nonce, 0, 4);
                std::memcpy(nonce + 4, nonce24 + ChaCha20Core::HNONCE_BYTES, 8);

                return aead.reset(SReadOnlyByteSpan(subkey, sizeof(subkey)));
            }
        };

    } // namespace

    /* Constructs an unkeyed context. */
    CXChaCha20Poly1305::CXChaCha20Poly1305() : _keyed(false) {
        std::memset(_key, 0, sizeof(_key));
    }

    /* Clears the key. */
    CXChaCha20Poly1305::~CXChaCha20Poly1305() {
        CSecure::zero(SByteSpan(_key, sizeof(_key)));
    }

    /* Keys this context. */
    bool CXChaCha20Poly1305::reset(const SReadOnlyByteSpan& key) {
        if (key.size != KEY_BYTES || !key.data) {
            return false;
        }

        std::memcpy(_key, key.data, KEY_BYTES);
        _keyed = true;
        return true;
    }

    /* Whether a key is held. */
    bool CXChaCha20Poly1305::keyed() const {
        return _keyed;
    }

    /* The per-nonce subkey, HChaCha20(key, nonce[0:16]). */
    bool CXChaCha20Poly1305::deriveSubkey(
        const SReadOnlyByteSpan& nonce, const SByteSpan& out
    ) const {
        if (!_keyed || nonce.size != NONCE_BYTES || !nonce.data) {
            return false;
        }
        if (out.size != SUBKEY_BYTES || !out.data) {
            return false;
        }

        ChaCha20Core::hchacha20(_key, nonce.data, out.data);
        return true;
    }

    /* Encrypts and authenticates. */
    bool CXChaCha20Poly1305::seal(
        const SReadOnlyByteSpan& nonce, const SReadOnlyByteSpan& aad,
        const SReadOnlyByteSpan& in, const SByteSpan& out, const SByteSpan& tag
    ) const {
        if (!_keyed || nonce.size != NONCE_BYTES || !nonce.data) {
            return false;
        }

        // Everything else -- the sizes, the null checks, the aliasing, the counter-1 start -- is
        // the inner AEAD's, which is the point of expressing this as a wrapper rather than a
        // second copy of RFC 8439 2.8.
        Inner inner;
        if (!inner.prepare(_key, nonce.data)) {
            return false;
        }

        return inner.aead.seal(
            SReadOnlyByteSpan(inner.nonce, sizeof(inner.nonce)), aad, in, out, tag);
    }

    /* Verifies and decrypts. */
    bool CXChaCha20Poly1305::open(
        const SReadOnlyByteSpan& nonce, const SReadOnlyByteSpan& aad,
        const SReadOnlyByteSpan& in, const SReadOnlyByteSpan& tag, const SByteSpan& out
    ) const {
        if (!_keyed || nonce.size != NONCE_BYTES || !nonce.data) {
            return false;
        }

        Inner inner;
        if (!inner.prepare(_key, nonce.data)) {
            return false;
        }

        // The constant-time tag comparison and the verify-before-write ordering that keeps a
        // rejected record's buffer intact are inherited from here, not reimplemented.
        return inner.aead.open(
            SReadOnlyByteSpan(inner.nonce, sizeof(inner.nonce)), aad, in, tag, out);
    }

} // namespace crypto
} // namespace certpp
