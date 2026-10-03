#ifndef __INCLUDE_CERTPP_DNSSEC_KEYS_HPP__
#define __INCLUDE_CERTPP_DNSSEC_KEYS_HPP__

#include <certpp/common.hpp>
#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/keys.hpp>
#include <certpp/dnssec/records.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace dnssec {

    /**
     * Converts between the encodings DNSSEC puts on the wire and the ones this library's
     * `crypto` module uses.
     *
     * DNSSEC does not reuse any of the usual encodings. Where X.509 carries a public key as a
     * SubjectPublicKeyInfo and an ECDSA signature as a DER `SEQUENCE { r, s }`, DNSSEC writes
     * the bare key material and the bare concatenation `r | s` -- so a DNSKEY cannot be handed
     * to `IAsymmetric::createPublicKey()` directly, and an RRSIG signature cannot be handed to
     * `verify()` directly. Specifically:
     *
     * - **RSA** (RFC 3110): DNS writes an exponent length, then the exponent, then the modulus.
     *   This library wants a DER `SEQUENCE { INTEGER modulus, INTEGER exponent }` -- note that
     *   the two even appear in the opposite order.
     * - **ECDSA** (RFC 6605): DNS writes `x | y`. This library wants the SEC1 uncompressed point,
     *   which is the same bytes behind an `0x04` prefix.
     * - **EdDSA** (RFC 8080): DNS writes the raw key and the raw signature, which is already
     *   what this library wants. These two are pass-throughs, and are handled explicitly rather
     *   than by falling through a default, so that an algorithm nobody has implemented yet is
     *   rejected instead of being silently treated as raw.
     *
     * Every conversion here is purely a re-encoding: nothing is signed, verified or derived, and
     * no key is generated. What it does do is reject material whose length disagrees with its
     * algorithm, since a short ECDSA coordinate pair silently reinterpreted as a different split
     * of x and y would produce a key that verifies nothing.
     */
    class CERTPP_API CDnssecKeys {
    public:
        /**
         * Returns the algorithm enumerator this library uses for a DNSSEC algorithm number.
         * @param which The DNSSEC algorithm number.
         * @param out Receives the corresponding `crypto::EAsymmetrics`.
         * @return True if the algorithm is one this library implements.
         */
        static bool asymmetricOf(EDnsAlgorithms which, crypto::EAsymmetrics& out);

        /**
         * Returns the hash this DNSSEC algorithm number signs with, which RFC 5702/6605/8080
         * bind to the algorithm rather than leaving for the signer to choose.
         * @param which The DNSSEC algorithm number.
         * @param out Receives the corresponding `crypto::EHashers`; `EHASH_UNKNOWN` for Ed25519
         *            and Ed448, which hash internally and take the message whole.
         * @return True if the algorithm is one this library implements.
         */
        static bool hasherOf(EDnsAlgorithms which, crypto::EHashers& out);

        /**
         * Converts a DNSKEY record into a usable public key.
         * @param key The DNSKEY record.
         * @param out Receives the public key.
         * @return True on success; false if the algorithm is unsupported or the key material is
         *         malformed or the wrong length for its algorithm.
         */
        static bool toPublicKey(const SDnskey& key, crypto::IPublicKeyPtr& out);

        /**
         * Converts a public key into a DNSKEY record.
         *
         * The algorithm has to be given rather than inferred: several DNSSEC algorithm numbers
         * share one key type (RSA/SHA-1, RSA/SHA-256 and RSA/SHA-512 all carry the same RSA key,
         * and differ only in the hash), so a key alone does not determine its DNSSEC number.
         * @param publicKey The public key.
         * @param algorithm The DNSSEC algorithm number to record.
         * @param flags The flags field to record, e.g. `SDnskey::FLAG_ZONE_KEY`.
         * @param out Receives the DNSKEY record.
         * @return True on success; false if the algorithm is unsupported or the key does not
         *         belong to it.
         */
        static bool fromPublicKey(
            const crypto::IPublicKeyPtr& publicKey, EDnsAlgorithms algorithm,
            uint16_t flags, SDnskey& out
        );

        /**
         * Converts an RRSIG signature into the encoding this library's `verify()` expects.
         *
         * For ECDSA this turns `r | s` into a DER `SEQUENCE { INTEGER r, INTEGER s }`; for RSA
         * and EdDSA the bytes are already right and are copied through.
         * @param algorithm The DNSSEC algorithm number.
         * @param signature The signature as it appears in RRSIG RDATA.
         * @param out Receives the converted signature; cleared first.
         * @return True on success; false if the algorithm is unsupported or the signature is the
         *         wrong length for it.
         */
        static bool signatureToNative(
            EDnsAlgorithms algorithm, const SReadOnlyByteSpan& signature, TArray<uint8_t>& out
        );

        /**
         * Converts a signature this library produced into the encoding RRSIG RDATA expects.
         *
         * For ECDSA this turns a DER `SEQUENCE { INTEGER r, INTEGER s }` into `r | s`, with each
         * integer left-padded to the curve's field size -- the padding matters, because a DER
         * INTEGER drops leading zero octets and RFC 6605 requires a fixed width.
         * @param algorithm The DNSSEC algorithm number.
         * @param signature The signature as this library produced it.
         * @param out Receives the converted signature; cleared first.
         * @return True on success; false if the algorithm is unsupported or the signature is
         *         malformed.
         */
        static bool signatureFromNative(
            EDnsAlgorithms algorithm, const SReadOnlyByteSpan& signature, TArray<uint8_t>& out
        );
    };

}
}

#endif
