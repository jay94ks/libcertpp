#ifndef __INCLUDE_CERTPP_X509_CHAIN_PFX_HPP__
#define __INCLUDE_CERTPP_X509_CHAIN_PFX_HPP__

#include <certpp/common.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/io/span.hpp>
#include <certpp/x509/chain.hpp>

namespace certpp {
namespace x509 {

    /**
     * PKCS#12/PFX (RFC 7292), the password-protected container format, as an `IChainFormat`.
     *
     * Reached through `IChainFormat::builtIn(ECHAINFMT_PFX)`; constructed directly only to
     * override the iteration count, which is the one parameter worth varying.
     *
     * ## What this writes
     *
     * A v3 PFX whose `authSafe` is a `pkcs7-data` ContentInfo wrapping an AuthenticatedSafe of
     * two parts: the certificate bags, as a `pkcs7-encryptedData` under PBES2, and the key bags,
     * as `pkcs7-data` holding one `pkcs8ShroudedKeyBag` per private key, each an
     * `EncryptedPrivateKeyInfo` under PBES2 of its own. Integrity is the `MacData` HMAC over the
     * whole AuthenticatedSafe.
     *
     * - **Encryption is PBES2** (RFC 8018 6.2) throughout: PBKDF2-HMAC-SHA256 for the key,
     *   AES-256-CBC with PKCS#7 padding for the data, a fresh 16-byte salt and a fresh random IV
     *   per encrypted part. The legacy PKCS#12 ciphers (RC2-40-CBC, 3DES under PBES1) are **not**
     *   written and **not** read; a container using one is reported `ERET_NOTSUP` rather than
     *   decrypted with a broken cipher. This matches what OpenSSL 3 produces by default, so it is
     *   the interoperable choice as well as the sound one.
     * - **Integrity is HMAC-SHA-256.** RFC 7292's own examples use SHA-1, and so did every tool
     *   until recently; SHA-256 is chosen because HMAC-SHA-1's security rests entirely on HMAC
     *   papering over SHA-1's collisions, and because OpenSSL 3's default is already SHA-256, so
     *   nothing is lost by it. SHA-1 MACs are still *verified* on read, since files written
     *   before about 2021 all have them.
     * - **The MAC key comes from RFC 7292 Appendix B's own KDF, not PBKDF2**, and this is not a
     *   choice -- RFC 7292 section 4 specifies that derivation for `MacData` and every real file
     *   uses it, so reading one requires it. Its use is confined to exactly that: the MAC key,
     *   with the purpose byte 3. No PBES1 key or IV is ever derived with it. (RFC 9579's PBMAC1,
     *   which does let PBKDF2 derive the MAC key, is not implemented.)
     * - **The password is encoded differently for the two of them**, which is the single
     *   likeliest way to produce a file no other tool reads. PBES2 is PKCS#5 and takes the
     *   password as bytes exactly as given. Appendix B's KDF is PKCS#12's own and takes it as a
     *   BMPString: UTF-16, big-endian, with a terminating two-byte NUL. This class interprets the
     *   `password` span as UTF-8 to make that conversion; for an ASCII password -- which is to
     *   say almost all of them -- the two agree.
     *
     * ## What it refuses
     *
     * **The MAC is verified before anything inside the container is decrypted or trusted**, which
     * is the whole reason a PFX has one. Until it passes, the AuthenticatedSafe is attacker-
     * controlled bytes; decrypting first would turn this class into a padding oracle, and parsing
     * first would expose the ASN.1 reader to input no one has vouched for. A container with no
     * `MacData` at all is refused for the same reason: unauthenticated is unauthenticated,
     * whether the MAC is wrong or missing.
     *
     * The MAC is compared with `CSecure::equals()`, and a wrong password, a corrupt file and a
     * missing MAC all return the same `ERET_KEY_ERROR`. That is deliberate and is not laziness
     * about error reporting: an implementation that distinguishes "your password is wrong" from
     * "this file is damaged" has told an attacker which of the two to keep trying.
     *
     * `save()` refuses an empty password with `ERET_BADREQ`. There is no such thing as a PFX
     * encrypted under no password -- the structure would be there and the protection would not.
     */
    class CERTPP_API CPfxFormat : public IChainFormat {
    private:
        uint32_t _iterations;

    public:
        /**
         * The PBKDF2 and MAC iteration count `save()` uses unless told otherwise: 600,000.
         *
         * This is OWASP's 2023 figure for PBKDF2-HMAC-SHA256, and it costs about 0.3 s per
         * derivation in a release build of this library -- which is the actual argument for it.
         * The number that wants justifying is not this one but the alternatives: RFC 7292's own
         * examples say 1024, OpenSSL still defaults to 2048, and a 2048-iteration PBKDF2 over a
         * human password is a few seconds of GPU time per guess. A container is written once and
         * attacked for years, so the cost belongs on the writing side.
         *
         * Not a floor on *reading*: a container someone else wrote is read with whatever count it
         * carries, since refusing a weak one would just mean refusing most existing files.
         */
        static constexpr uint32_t DEFAULT_ITERATIONS = 600000;

        /** The salt length `save()` generates for PBKDF2 and for the MAC, in bytes. */
        static constexpr size_t SALT_BYTES = 16;

        /**
         * The largest container `load()` will accept, in bytes: 16 MiB.
         *
         * `load()` works entirely in spans over the buffer it is given, and the one place it
         * allocates proportionally -- the plaintext for each decrypted part -- is sized from a
         * span inside that buffer. So bounding the input bounds every allocation, and the point
         * of the bound is that all of this happens on bytes nobody has authenticated yet: the
         * MAC cannot be checked until the container has been walked far enough to find it. Real
         * containers are kilobytes.
         */
        static constexpr size_t MAX_CONTAINER_BYTES = 16u * 1024u * 1024u;

        /**
         * The largest `MacData` iteration count `load()` will honour: 10,000,000.
         *
         * This is the one piece of work `load()` does on input nobody has authenticated yet, and
         * so the one place an iteration count is an attacker's parameter rather than the writer's:
         * the MAC key has to be derived before the MAC can be checked, and the count comes out of
         * the container. Without a cap, a 200-byte file claiming two billion iterations is minutes
         * of CPU for whoever opens it.
         *
         * Deliberately far above anything real -- RFC 7292's examples use 1024, OpenSSL 2048, and
         * `DEFAULT_ITERATIONS` here is 600,000 -- so the cap costs no interoperability. It is a
         * ceiling on damage, not a judgement about strength; `load()` places no *lower* bound on
         * the counts in a container it is reading.
         */
        static constexpr uint32_t MAX_MAC_ITERATIONS = 10000000u;

    public:
        /**
         * Constructs the format handler.
         * @param iterations The PBKDF2 and MAC iteration count for `save()`; must be at least 1,
         * and a lower value than `DEFAULT_ITERATIONS` should be passed only where the cost is the
         * point, as in a test. Ignored by `load()`, which uses the count in the container.
         */
        explicit CPfxFormat(uint32_t iterations = DEFAULT_ITERATIONS);

        /**
         * Destroys the format handler.
         */
        ~CPfxFormat() override;

        /**
         * Returns the iteration count `save()` will use.
         * @return The iteration count.
         */
        uint32_t iterations() const;

    public:
        /**
         * Returns `ECHAINFMT_PFX`.
         * @return The format this implementation handles.
         */
        EChainFormats format() const override;

        /**
         * Returns true: a PFX without a password is not a PFX.
         * @return True.
         */
        bool needsPassword() const override;

        /**
         * Reads a PFX into a collection, verifying its MAC before anything else.
         *
         * Entries are appended. A failure leaves `out` exactly as it was, which is why the
         * entries are assembled separately and merged only once every bag has been read -- and
         * why a key whose algorithm this library cannot encode as PKCS#8 fails the whole load
         * rather than being dropped from it. A container that came back quietly missing its
         * private key would be the half-populated case wearing a success code.
         * @param data The container's bytes.
         * @param password The password; must not be empty.
         * @param out Receives the entries, appended.
         * @return ERET_OK; ERET_BADREQ for a malformed container, an empty password or one over
         * `MAX_CONTAINER_BYTES`; ERET_KEY_ERROR for a wrong password, a failed MAC or a missing
         * one, which are deliberately indistinguishable; or ERET_NOTSUP for a container using an
         * algorithm this class does not implement, including the legacy PKCS#12 ciphers.
         */
        ERetCode load(
            const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& password,
            CCertCollection& out
        ) const override;

        /**
         * Writes a collection out as a PFX.
         *
         * An entry that holds a private key but no `localKeyId` is given one -- the SHA-1 digest
         * of its own certificate, which is what OpenSSL uses -- because `localKeyId` is the only
         * thing that pairs a key bag back to its certificate bag on the way in. Without it a
         * reader gets the right key and cannot tell which certificate it belongs to.
         * @param in The collection; must not be empty.
         * @param password The password; must not be empty.
         * @param out Receives the container's bytes, replacing any content it held.
         * @return ERET_OK; ERET_BADREQ if the collection is empty or the password is empty; or
         * ERET_NOTSUP if an entry holds a key with no PKCS#8 encoding this library writes.
         */
        ERetCode save(
            const CCertCollection& in, const SReadOnlyByteSpan& password, CBuffer& out
        ) const override;
    };

} // namespace x509
} // namespace certpp

#endif
