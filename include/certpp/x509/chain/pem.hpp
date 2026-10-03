#ifndef __INCLUDE_CERTPP_X509_CHAIN_PEM_HPP__
#define __INCLUDE_CERTPP_X509_CHAIN_PEM_HPP__

#include <certpp/common.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/span.hpp>
#include <certpp/string.hpp>
#include <certpp/x509/cert.hpp>
#include <certpp/x509/chain.hpp>

namespace certpp {
namespace x509 {

    /**
     * The PEM container format (RFC 7468): a `CCertCollection` written as, and read back from,
     * concatenated textual blocks -- `-----BEGIN CERTIFICATE-----`, base64, `-----END
     * CERTIFICATE-----`, one after another, optionally interleaved with private-key blocks.
     *
     * This class is the whole of this library's PEM handling: block scanning, encapsulation
     * boundaries, labels, base64 framing and "this file also carries a private key" are
     * container concerns, so they live here rather than in `CCert`, whose own native form is
     * DER. `CCert::importPem()`/`exportPem()` are thin delegations to this class, kept because
     * a single certificate in a file is the common case, not because they do the work.
     *
     * **PEM has no password and no encryption, and that is not a detail this class can soften.**
     * `needsPassword()` returns false, and the `password` argument of `load()`/`save()` is
     * ignored outright: it is not checked, not compared, not used to derive anything, and
     * nothing in a file this class writes is protected by it. Passing one buys exactly nothing.
     * A private key written out by `save()` lands on disk as base64 of its plaintext DER --
     * anyone who can read the file has the key. When a key has to rest on disk or cross a
     * network, that is what `ECHAINFMT_PFX` is for.
     *
     * Because of that, writing keys is opt-in: `save()` writes certificates only unless the
     * format was constructed with `withPrivateKeys` true, and `IChainFormat::builtIn()` hands
     * back the certificates-only form. A caller who wants a key in the clear can say so in one
     * argument; a caller who did not ask cannot get one by surprise.
     */
    class CERTPP_API CPemChainFormat : public IChainFormat {
    private:
        /* Whether save() writes a private key alongside each certificate that has one -- see
         * this class's own doc comment on why this is off unless a caller asks for it. */
        bool _withPrivateKeys;

    private:
        /* Unwraps a PKCS#8 PrivateKeyInfo (SEQUENCE { version INTEGER, AlgorithmIdentifier,
         * privateKey OCTET STRING, ... }), used by tryAttachPrivateKey()'s "PRIVATE KEY" block
         * handling, to reach the algorithm-specific key blob inside -- the AlgorithmIdentifier
         * itself isn't inspected (only whether the resulting blob happens to parse under the
         * certificate's own algorithm matters). For RSA this blob is the final PKCS#1
         * RSAPrivateKey directly; for Ed25519/Ed448/X25519 (RFC 8410) it's itself a further
         * DER-encoded OCTET STRING wrapping the raw seed -- see unwrapOctetString(). */
        static bool unwrapPkcs8PrivateKey(const COctet& data, COctet& outInner);

        /* Unwraps one OCTET STRING TLV, giving back its content. Used by tryAttachPrivateKey()
         * for RFC 8410's double-OCTET-STRING PKCS#8 encoding: unwrapPkcs8PrivateKey() reaches
         * the outer "privateKey OCTET STRING" field, and for Ed25519/Ed448/X25519 that field's
         * own content is itself a separately DER-encoded OCTET STRING (CurvePrivateKey) wrapping
         * the raw seed -- one more unwrapOctetString() call reaches that. */
        static bool unwrapOctetString(const COctet& data, COctet& outContent);

        /* Parses a standard SEC1 ECPrivateKey (RFC 5915) blob -- e.g. from a PEM "EC PRIVATE
         * KEY" block produced by openssl or another tool, not just buildSec1PrivateKey()'s own
         * output -- back into this library's own native EC private-key wire format
         * (CCert::rawPrivateKey()'s own shape, see its doc comment), for tryAttachPrivateKey()
         * to hand to IAsymmetric::createPrivateKey(). False if data isn't a well-formed SEC1
         * key, or is missing its OPTIONAL publicKey field (this library's own format has no such
         * optionality, so there's nothing to fall back to without re-deriving the public point,
         * which this method doesn't attempt). */
        static bool convertSec1ToNative(const COctet& data, COctet& outNative);

        /* Converts a PKCS#8-wrapped DSA private key's inner blob (a bare INTEGER x -- PKCS#8's
         * own DSA convention, unlike RSA's, whose inner blob is already the complete traditional
         * key) into this library's own traditional DSAPrivateKey wire format (version, p, q, g,
         * y, x -- see CCert::rawPrivateKey()'s doc comment), reusing the certificate's own
         * already-known p/q/g (CCert::keyAlgoParams()) and y (CCert::rawPublicKey()) rather than
         * separately parsing PKCS#8's own AlgorithmIdentifier parameters, which would just be
         * the same p/q/g again. */
        static bool convertPkcs8DsaInnerToNative(
            const COctet& innerX, const COctet& keyAlgoParams, const COctet& rawPublicKey,
            COctet& outNative
        );

        /* Tries candidate as cert's own private key, attempting every shape a PEM key block
         * might be in, in order, until one both parses under cert's own algorithm and matches
         * its public key: as-is (RSA PKCS#1, DSA's OpenSSL-traditional format, or this library's
         * own native EC format), traditional SEC1 (a non-PKCS#8 "EC PRIVATE KEY" block), and
         * PKCS#8, trying its inner blob four ways in turn -- directly (RSA), further unwrapped as
         * an OCTET STRING (RFC 8410 Ed25519/Ed448/X25519), as SEC1 (EC's usual PKCS#8 form, e.g.
         * `openssl req -newkey ec ...`, which wraps a SEC1 ECPrivateKey rather than a raw
         * scalar), and via convertPkcs8DsaInnerToNative() (DSA's usual PKCS#8 form, whose inner
         * blob is a bare x, not the traditional format directly). A candidate that matches none
         * of these -- an encrypted key, or simply a different key entirely -- just isn't
         * attached. Delegates to CCert::privateKey(IPrivateKeyPtr&) for the actual attach, so a
         * candidate that parses but isn't this certificate's own key pair is still rejected,
         * which is what makes load()'s pairing of keys to certificates exact rather than
         * positional. */
        static bool tryAttachPrivateKey(CCert& cert, const COctet& candidate);

        /* Builds a standards-compliant SEC1 ECPrivateKey (RFC 5915) DER blob from cert's own EC
         * private scalar (CCert::rawPrivateKey()) and public point (CCert::rawPublicKey())/curve
         * OID (CCert::keyAlgoParams()) -- used by save() so its "EC PRIVATE KEY" block
         * round-trips through any standard tool, unlike rawPrivateKey()'s own internal wire
         * format (see its doc comment). The inverse of convertSec1ToNative(). False if cert
         * isn't an EC certificate with both halves available. */
        static bool buildSec1PrivateKey(const CCert& cert, COctet& out);

        /* Builds a standards-compliant PKCS#8 PrivateKeyInfo (RFC 8410) DER blob wrapping
         * CCert::rawPrivateKey()'s raw seed/scalar bytes -- used by save() so its "PRIVATE KEY"
         * block round-trips through any standard tool for Ed25519/Ed448/X25519, which have no
         * traditional-format PEM encoding of their own. The OID is looked up from CCert's own
         * KEY_ALGOS table by CCert::keyAlgo()'s name, so the two can't disagree. False if the
         * certificate's algorithm isn't one that table names, or rawPrivateKey() is empty. */
        static bool buildPkcs8PrivateKey(const CCert& cert, COctet& out);

        /* Appends cert's attached private key (CCert::rawPrivateKey()) to text as one PEM block,
         * picking the label and encoding its algorithm actually has a standard for: "RSA PRIVATE
         * KEY" (PKCS#1) and "DSA PRIVATE KEY" (OpenSSL's traditional format) are rawPrivateKey()'s
         * own bytes directly, "EC PRIVATE KEY" goes through buildSec1PrivateKey(), and "PRIVATE
         * KEY" through buildPkcs8PrivateKey(). An algorithm none of those fit leaves the key out
         * entirely rather than writing a non-standard block -- the behaviour CCert::exportPem()
         * has always had and which save() therefore keeps. False only on an allocation failure. */
        static bool appendPrivateKeyBlock(CString& text, const CCert& cert);

    public:
        /**
         * Constructs the PEM format.
         * @param withPrivateKeys True to have `save()` write each entry's private key, **in the
         *        clear**, alongside its certificate. False -- the default, and what
         *        `IChainFormat::builtIn()` returns -- writes certificates only.
         */
        explicit CPemChainFormat(bool withPrivateKeys = false);

        /**
         * Destroys the format object. It holds no key material of its own.
         */
        ~CPemChainFormat() override = default;

    public:
        /**
         * Returns which format this implementation handles.
         * @return Always `ECHAINFMT_PEM`.
         */
        EChainFormats format() const override;

        /**
         * Reports whether this format requires a password.
         *
         * Always false, and that is a warning rather than a convenience: PEM has no
         * confidentiality whatsoever. A password handed to `load()` or `save()` is ignored, and
         * a private key `save()` writes is readable by anyone who can read the file.
         * @return Always false.
         */
        bool needsPassword() const override;

        /**
         * Reports whether `save()` writes private keys.
         * @return True if this format object was constructed to write private keys in the clear.
         */
        bool includesPrivateKeys() const;

        /**
         * Reads concatenated PEM blocks into a collection, appending one entry per `CERTIFICATE`
         * block, in the order the file lists them.
         *
         * Everything outside the `-----BEGIN`/`-----END` boundaries is explanatory text, which
         * RFC 7468 permits and this reader skips -- except that the text immediately preceding a
         * `CERTIFICATE` block is scanned for openssl's own `Bag Attributes` header
         * (`friendlyName:`/`localKeyID:`, what `openssl pkcs12 -nokeys` emits), so the PKCS#9
         * attributes an `SCertEntry` carries survive a PFX -> PEM -> PFX trip. Note that
         * `IChainFormat::detect()` sniffs only the container's first bytes, so a file that opens
         * with such text is not recognised there even though it loads perfectly well here.
         *
         * A block whose label is not `CERTIFICATE` is treated as a candidate private key and
         * tried against every certificate in the file, in file order, until one accepts it;
         * acceptance is `CCert::privateKey(IPrivateKeyPtr&)`'s own public-key comparison, so a
         * key is paired with the certificate it actually belongs to rather than with whichever
         * one it happens to sit next to. A key block that pairs with nothing is dropped, which is
         * the only way to read a file that carries somebody else's key alongside a certificate.
         *
         * A certificate whose algorithm this library does not implement is **loaded**, not
         * rejected: `CCert::importDer()` parses it fully and leaves `keyAlgo()`/`signAlgo()` as
         * raw OID text, and dropping such an entry would lose a certificate the file genuinely
         * contains and that the collection's name-based lookups still work on. What cannot be
         * done with it is anything needing its key -- `publicKey()` is null, so no private key
         * ever pairs with it and `verifyLinks()` reports it as unsupported.
         *
         * Nothing is added to `out` until every block has been read, so a file that goes wrong
         * half way through leaves the collection exactly as it was.
         * @param data The container's bytes.
         * @param password Ignored entirely -- PEM has no password. See this class's doc comment.
         * @param out Receives the entries, appended.
         * @return ERET_OK; ERET_BADREQ for empty input, a file with no `CERTIFICATE` block, a
         *         structurally broken block (a missing `-----END`, a body that is not base64) or
         *         a `CERTIFICATE` block that is not a well-formed X.509 certificate; ERET_NOTSUP
         *         for a password-encrypted key block (an `ENCRYPTED PRIVATE KEY` label, or RFC
         *         1421's `Proc-Type: 4,ENCRYPTED` header), which this format cannot decrypt
         *         because it has no password to decrypt it with.
         */
        ERetCode load(
            const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& password,
            CCertCollection& out
        ) const override;

        /**
         * Writes a collection out as concatenated PEM blocks: one `CERTIFICATE` block per entry,
         * in collection order, each preceded by a `Bag Attributes` header when the entry carries
         * a PKCS#9 `friendlyName` or `localKeyId`.
         *
         * A private key is written only when this format object was constructed with
         * `withPrivateKeys` true, and then **in the clear** -- see this class's doc comment. A
         * key whose algorithm has no standard PEM encoding this library can build is left out
         * rather than written as something non-standard, which is what `CCert::exportPem()` has
         * always done.
         * @param in The collection; must not be empty.
         * @param password Ignored entirely -- PEM has no password, so there is nothing for one to
         *        protect.
         * @param out Receives the PEM text's bytes, replacing any content it held.
         * @return ERET_OK; ERET_BADREQ if the collection is empty or an entry's `friendlyName`
         *         contains a line break (which this one-line header cannot represent, and
         *         silently dropping it would lose data the caller set); ERET_INVAL if an entry's
         *         certificate is empty; ERET_KEY_ERROR if key writing is on and an entry's
         *         private key is not its certificate's own; ERET_NOMEM on allocation failure.
         */
        ERetCode save(
            const CCertCollection& in, const SReadOnlyByteSpan& password, CBuffer& out
        ) const override;
    };

} // namespace x509
} // namespace certpp

#endif
