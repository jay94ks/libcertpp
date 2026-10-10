// Example 5: measure this library's own throughput, on this machine.
//
// Unlike examples 01-04 this one is standalone -- it reads and writes nothing under
// examples/output/ and can be run on its own, in any order. It exists because the figures in
// README.md and docs/roadmap.md are otherwise unverifiable claims: a reader who wants to know
// what libcertpp costs on *their* hardware should be able to run the same harness that produced
// them rather than take a number on trust.
//
// Methodology, and why it is shaped this way: every figure is the fastest of OUTER batches of
// ITERS iterations. The fastest rather than the mean, because a benchmark on a machine with
// other work running measures the scheduler as much as the code, and the quickest batch is the
// one least contaminated by it. Run the whole thing two or three times and take the best; a
// spread of 20-30% between runs on a loaded laptop is normal, and nothing smaller than that is
// a result.
//
// These are not microbenchmarks of primitives in isolation. Each signature figure includes the
// per-call allocation and context bookkeeping a real caller pays for, because that is what a
// caller actually experiences.

#include "common.hpp"

#include <chrono>
#include <functional>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    constexpr int OUTER = 3;
    constexpr int ITERS = 20;
    constexpr size_t BULK_BYTES = 64 * 1024;

    /* Runs body() iters times, outer times over, and returns the fastest batch's per-call time
     * in milliseconds. */
    double fastestMs(int outer, int iters, const std::function<void()>& body) {
        double best = 0.0;

        for (int o = 0; o < outer; ++o) {
            const auto started = std::chrono::steady_clock::now();
            for (int i = 0; i < iters; ++i) {
                body();
            }
            const auto ended = std::chrono::steady_clock::now();

            const double ms =
                std::chrono::duration<double, std::milli>(ended - started).count() / iters;

            if (o == 0 || ms < best) {
                best = ms;
            }
        }

        return best;
    }

    void printMs(const char* label, int iters, const std::function<void()>& body) {
        printf("  %-26s %9.3f ms\n", label, fastestMs(OUTER, iters, body));
    }

    /* Same min-of-min shape as printMs(), at the scale a small record lives at: a 64 B seal() is
     * hundreds of nanoseconds, which ms renders as a column of zeros. */
    void printNs(const char* label, int iters, const std::function<void()>& body) {
        printf("  %-26s %9.0f ns\n", label, fastestMs(OUTER, iters, body) * 1000000.0);
    }

    void printThroughput(const char* label, size_t bytes, const std::function<void()>& body) {
        const double ms = fastestMs(OUTER, ITERS, body);
        printf("  %-26s %9.1f MiB/s\n", label,
            (double(bytes) / (1024.0 * 1024.0)) / (ms / 1000.0));
    }

    /* Signs and verifies one fixed input. digestBytes of 0 means the scheme hashes the message
     * itself (Ed25519/Ed448/ML-DSA), where the parameter carries the message rather than a
     * digest -- see IAsymmetricContext::sign()'s own doc comment. */
    void benchSignVerify(
        const char* name, EAsymmetrics algo, SKeySize keySize, size_t digestBytes, int iters
    ) {
        IAsymmetricPtr algorithm = IAsymmetric::builtIn(algo);
        SKeyPair pair;

        if (!algorithm || algorithm->generateKeyPair(keySize, pair) != ERET_OK || !pair) {
            printf("  %-26s (unavailable)\n", name);
            return;
        }

        IAsymmetricContextPtr ctx = algorithm->createContext();
        ctx->keyPair(pair);

        const std::vector<uint8_t> message(digestBytes ? digestBytes : 32, 0x5a);
        const SReadOnlyByteSpan messageSpan(message.data(), message.size());

        std::vector<uint8_t> scratch(ctx->sizeOfSign());
        SByteSpan signature(scratch.data(), scratch.size());
        if (ctx->sign(messageSpan, signature) != ERET_OK) {
            printf("  %-26s (sign failed)\n", name);
            return;
        }

        const std::vector<uint8_t> fixedSig(signature.data, signature.data + signature.size);
        const SReadOnlyByteSpan sigSpan(fixedSig.data(), fixedSig.size());

        char label[96];
        snprintf(label, sizeof(label), "%s sign", name);
        printMs(label, iters, [&] {
            std::vector<uint8_t> out(ctx->sizeOfSign());
            SByteSpan span(out.data(), out.size());
            ctx->sign(messageSpan, span);
        });

        snprintf(label, sizeof(label), "%s verify", name);
        printMs(label, iters, [&] { ctx->verify(messageSpan, sigSpan); });
    }

    /* Key generation and one shared-secret derivation against a second key pair. */
    void benchAgreement(const char* name, EAsymmetrics algo, SKeySize keySize, int iters) {
        IAsymmetricPtr algorithm = IAsymmetric::builtIn(algo);
        SKeyPair mine, peer;

        if (!algorithm || algorithm->generateKeyPair(keySize, mine) != ERET_OK
            || algorithm->generateKeyPair(keySize, peer) != ERET_OK) {
            printf("  %-26s (unavailable)\n", name);
            return;
        }

        IAsymmetricContextPtr ctx = algorithm->createContext();
        ctx->keyPair(mine);

        std::vector<uint8_t> probe(256);
        SByteSpan probeSpan(probe.data(), probe.size());
        if (ctx->deriveSharedSecret(peer.publicKey, probeSpan) != ERET_OK) {
            printf("  %-26s (agreement unsupported)\n", name);
            return;
        }

        char label[96];
        snprintf(label, sizeof(label), "%s keygen", name);
        printMs(label, iters, [&] {
            SKeyPair fresh;
            algorithm->generateKeyPair(keySize, fresh);
        });

        snprintf(label, sizeof(label), "%s derive", name);
        printMs(label, iters, [&] {
            std::vector<uint8_t> out(256);
            SByteSpan span(out.data(), out.size());
            ctx->deriveSharedSecret(peer.publicKey, span);
        });
    }

    void benchHash(const char* name, EHashers which, const std::vector<uint8_t>& data) {
        IHasherPtr hasher;
        if (IHasher::create(which, hasher) != ERET_OK || !hasher) {
            printf("  %-26s (unavailable)\n", name);
            return;
        }

        std::vector<uint8_t> digest(hasher->byteWidth() ? hasher->byteWidth() : 64);
        printThroughput(name, data.size(), [&] {
            hasher->reset();
            hasher->push(SReadOnlyByteSpan(data.data(), data.size()));
            hasher->finish(SByteSpan(digest.data(), digest.size()));
        });
    }

    /* All three ML-KEM parameter sets, since FIPS 203 defines three and a reader comparing
     * them against each other has no other way to get the numbers. */
    void benchKem() {
        struct Spec {
            const char* name;
            EKems which;
            SKeySize bits;
        };

        const Spec specs[] = {
            { "ML-KEM-512", EKEM_MLKEM512, 512 },
            { "ML-KEM-768", EKEM_MLKEM768, 768 },
            { "ML-KEM-1024", EKEM_MLKEM1024, 1024 },
        };

        for (const Spec& s : specs) {
            IKemPtr kem = IKem::builtIn(s.which);
            SKemKeyPair pair;

            if (!kem || kem->generateKeyPair(s.bits, pair) != ERET_OK || !pair.publicKey) {
                printf("  %-26s (unavailable)\n", s.name);
                continue;
            }

            IKemContextPtr encap = kem->createContext();
            IKemContextPtr decap = kem->createContext();
            encap->keyPair(pair.publicKey, nullptr);
            decap->keyPair(nullptr, pair.privateKey);

            std::vector<uint8_t> ct(encap->sizeOfCiphertext());
            std::vector<uint8_t> ss(encap->sizeOfSharedSecret());
            SByteSpan ctSpan(ct.data(), ct.size());
            SByteSpan ssSpan(ss.data(), ss.size());

            if (encap->encapsulate(ctSpan, ssSpan) != ERET_OK) {
                printf("  %-26s (encapsulate failed)\n", s.name);
                continue;
            }

            // --> decapsulate() needs one fixed ciphertext to work against; a fresh one per
            // call would measure encapsulate() as well.
            const std::vector<uint8_t> fixedCt(ct.begin(), ct.begin() + ctSpan.size);

            // --> generateKeyPair() above is setup, not a measurement: it produces the pair
            // both contexts are keyed with. Timed separately so the keygen column carries a
            // number instead of a dash.
            char label[96];

            snprintf(label, sizeof(label), "%s keygen", s.name);
            printMs(label, 50, [&] {
                SKemKeyPair fresh;
                kem->generateKeyPair(s.bits, fresh);
            });

            snprintf(label, sizeof(label), "%s encapsulate", s.name);
            printMs(label, 50, [&] {
                std::vector<uint8_t> c(encap->sizeOfCiphertext());
                std::vector<uint8_t> sh(encap->sizeOfSharedSecret());
                SByteSpan cs(c.data(), c.size());
                SByteSpan sp(sh.data(), sh.size());
                encap->encapsulate(cs, sp);
            });

            snprintf(label, sizeof(label), "%s decapsulate", s.name);
            printMs(label, 50, [&] {
                std::vector<uint8_t> sh(decap->sizeOfSharedSecret());
                SByteSpan sp(sh.data(), sh.size());
                decap->decapsulate(SReadOnlyByteSpan(fixedCt.data(), fixedCt.size()), sp);
            });
        }
    }

    /* Block ciphers through the ISymmetric surface, which every one of them shares: CBC
     * with PKCS#7, the same mode and padding AES gets. A figure here is the block cipher's
     * own cost plus CBC's chaining, which is *not* the same number as the AEAD rows above --
     * AES-256-GCM is the AEAD, AES-256-CBC is the cipher underneath a mode. Both are worth
     * having, and labelling them the same would be the easy mistake.
     *
     * ChaCha20 is deliberately absent: it is a stream cipher, so createEncrypter() refuses
     * the IV a CBC context demands, and its cost is already measured above as
     * ChaCha20-Poly1305 and XChaCha20-Poly1305. */
    void benchBlockCiphers(const std::vector<uint8_t>& bulk) {
        struct Spec {
            const char* name;
            ESymmetrics algo;
            size_t keyBytes;
        };

        const Spec specs[] = {
            { "AES-128-CBC", ESYM_AES, 16 },
            { "AES-192-CBC", ESYM_AES, 24 },
            { "AES-256-CBC", ESYM_AES, 32 },
            { "DES-CBC", ESYM_DES, 8 },
            { "3DES-CBC", ESYM_3DES, 16 },
            { "ARIA-128-CBC", ESYM_ARIA, 16 },
            { "ARIA-192-CBC", ESYM_ARIA, 24 },
            { "ARIA-256-CBC", ESYM_ARIA, 32 },
        };

        for (const Spec& s : specs) {
            ISymmetricPtr sym = ISymmetric::builtIn(s.algo);
            if (!sym) {
                printf("  %-26s (unavailable)\n", s.name);
                continue;
            }

            uint8_t raw[32] = { 0 };
            for (size_t i = 0; i < s.keyBytes; ++i) {
                raw[i] = uint8_t(i * 7 + 1);
            }

            ISymmetricKeyPtr key = sym->createKey(SReadOnlyByteSpan(raw, s.keyBytes));
            if (!key) {
                printf("  %-26s (key rejected)\n", s.name);
                continue;
            }

            ISymmetricContextPtr ctx = sym->createContext(key);
            if (!ctx) {
                printf("  %-26s (no context)\n", s.name);
                continue;
            }

            // sizeOfBlock() is only meaningful once a key is bound, hence after createContext().
            const size_t block = ctx->sizeOfBlock() ? ctx->sizeOfBlock() : 16;
            std::vector<uint8_t> iv(block, 0);
            ctx->key(key, CBuffer(iv.data(), iv.size()));
            ctx->padding(ESYMPAD_PKCS7);

            std::vector<uint8_t> out(bulk.size() + block * 2);

            ISymmetricTransformerPtr enc;
            if (ctx->createEncrypter(enc) != ERET_OK) {
                printf("  %-26s (encrypter failed)\n", s.name);
                continue;
            }

            printThroughput(s.name, bulk.size(), [&] {
                SByteSpan span(out.data(), out.size());
                enc->transform(SReadOnlyByteSpan(bulk.data(), bulk.size()), span);
            });
        }
    }

    void benchAeads(const std::vector<uint8_t>& bulk) {
        const std::vector<uint8_t> key(32, 0x01);
        const std::vector<uint8_t> nonce12(12, 0x02);
        const std::vector<uint8_t> nonce24(24, 0x03);
        std::vector<uint8_t> out(bulk.size());
        std::vector<uint8_t> tag(16);

        const SReadOnlyByteSpan keySpan(key.data(), key.size());
        const SReadOnlyByteSpan plain(bulk.data(), bulk.size());
        const SReadOnlyByteSpan noAad(nullptr, 0);
        const SByteSpan outSpan(out.data(), out.size());
        const SByteSpan tagSpan(tag.data(), tag.size());

        CChaCha20Poly1305 chacha;
        if (chacha.reset(keySpan)) {
            printThroughput("ChaCha20-Poly1305", bulk.size(), [&] {
                chacha.seal(SReadOnlyByteSpan(nonce12.data(), nonce12.size()),
                    noAad, plain, outSpan, tagSpan);
            });
        }

        CXChaCha20Poly1305 xchacha;
        if (xchacha.reset(keySpan)) {
            printThroughput("XChaCha20-Poly1305", bulk.size(), [&] {
                xchacha.seal(SReadOnlyByteSpan(nonce24.data(), nonce24.size()),
                    noAad, plain, outSpan, tagSpan);
            });
        }

        // --> AES-256-GCM lands *below* ChaCha20-Poly1305 here despite AES-NI, because GHASH is
        // the bottleneck rather than the cipher, and the two compose as 1/total = 1/cipher +
        // 1/mac. See docs/changelog.md's AES-GCM entry.
        CAesGcm gcm;
        if (gcm.reset(keySpan)) {
            printThroughput("AES-256-GCM", bulk.size(), [&] {
                gcm.seal(SReadOnlyByteSpan(nonce12.data(), nonce12.size()),
                    noAad, plain, outSpan, tagSpan);
            });
        }
    }

    /* The per-call cost a small record actually pays, which the 64 KiB numbers above average away.
     * docs/roadmap.md's small-record target (150 ns for a 64 B seal()) is written against this, and
     * until now nothing in this harness measured it.
     *
     * --> Reusing one key and one nonce is not flattering the result: CChaCha20Poly1305::seal()
     * re-derives the one-time key through ChaCha20Core::block() on every call and builds a new
     * CPoly1305 for the tag, so there is no cross-call state for a loop to warm. What it does hold
     * constant is the key, which a caller re-keying per record would not. */
    void benchSmallRecord() {
        const std::vector<uint8_t> key(32, 0x01);
        const std::vector<uint8_t> nonce12(12, 0x02);
        const std::vector<uint8_t> nonce24(24, 0x03);
        const std::vector<uint8_t> plain(64, 0x5a);
        std::vector<uint8_t> out(plain.size());
        std::vector<uint8_t> tag(16);

        const SReadOnlyByteSpan keySpan(key.data(), key.size());
        const SReadOnlyByteSpan plainSpan(plain.data(), plain.size());
        const SReadOnlyByteSpan noAad(nullptr, 0);
        const SByteSpan outSpan(out.data(), out.size());
        const SByteSpan tagSpan(tag.data(), tag.size());

        CChaCha20Poly1305 chacha;
        if (chacha.reset(keySpan)) {
            printNs("ChaCha20-Poly1305", ITERS, [&] {
                chacha.seal(SReadOnlyByteSpan(nonce12.data(), nonce12.size()),
                    noAad, plainSpan, outSpan, tagSpan);
            });
        }

        CXChaCha20Poly1305 xchacha;
        if (xchacha.reset(keySpan)) {
            printNs("XChaCha20-Poly1305", ITERS, [&] {
                xchacha.seal(SReadOnlyByteSpan(nonce24.data(), nonce24.size()),
                    noAad, plainSpan, outSpan, tagSpan);
            });
        }

        CAesGcm gcm;
        if (gcm.reset(keySpan)) {
            printNs("AES-256-GCM", ITERS, [&] {
                gcm.seal(SReadOnlyByteSpan(nonce12.data(), nonce12.size()),
                    noAad, plainSpan, outSpan, tagSpan);
            });
        }
    }
}

int main() {
    printf("libcertpp benchmark -- fastest of %d batches of %d iterations\n\n", OUTER, ITERS);

    printf("= Signatures =\n");
    benchSignVerify("RSA-2048", EASYM_RSA, 2048, 32, ITERS);
    benchSignVerify("DSA-2048", EASYM_DSA, 2048, 32, ITERS);
    benchSignVerify("Ed25519", EASYM_ED25519, 256, 0, ITERS);
    benchSignVerify("Ed448", EASYM_ED448, 456, 0, ITERS);

    printf("  -- prime curves --\n");
    benchSignVerify("ECDSA P-192", EASYM_P192, 192, 24, ITERS);
    benchSignVerify("ECDSA P-224", EASYM_P224, 224, 28, ITERS);
    benchSignVerify("ECDSA P-256", EASYM_P256, 256, 32, ITERS);
    benchSignVerify("ECDSA P-384", EASYM_P384, 384, 48, ITERS);
    benchSignVerify("ECDSA P-521", EASYM_P521, 521, 64, ITERS);
    benchSignVerify("ECDSA secp256k1", EASYM_SECP256K1, 256, 32, ITERS);

    printf("  -- Brainpool, r and t --\n");
    benchSignVerify("Brainpool-160r1", EASYM_BPOOL160R1, 160, 20, ITERS);
    benchSignVerify("Brainpool-192r1", EASYM_BPOOL192R1, 192, 24, ITERS);
    benchSignVerify("Brainpool-224r1", EASYM_BPOOL224R1, 224, 28, ITERS);
    benchSignVerify("Brainpool-256r1", EASYM_BPOOL256R1, 256, 32, ITERS);
    benchSignVerify("Brainpool-320r1", EASYM_BPOOL320R1, 320, 40, ITERS);
    benchSignVerify("Brainpool-384r1", EASYM_BPOOL384R1, 384, 48, ITERS);
    benchSignVerify("Brainpool-512r1", EASYM_BPOOL512R1, 512, 64, ITERS);
    benchSignVerify("Brainpool-160t1", EASYM_BPOOL160T1, 160, 20, ITERS);
    benchSignVerify("Brainpool-192t1", EASYM_BPOOL192T1, 192, 24, ITERS);
    benchSignVerify("Brainpool-224t1", EASYM_BPOOL224T1, 224, 28, ITERS);
    benchSignVerify("Brainpool-256t1", EASYM_BPOOL256T1, 256, 32, ITERS);
    benchSignVerify("Brainpool-320t1", EASYM_BPOOL320T1, 320, 40, ITERS);
    benchSignVerify("Brainpool-384t1", EASYM_BPOOL384T1, 384, 48, ITERS);
    benchSignVerify("Brainpool-512t1", EASYM_BPOOL512T1, 512, 64, ITERS);

    printf("  -- GF(2^m), NIST B and K --\n");
    benchSignVerify("ECDSA B-163", EASYM_B163, 163, 21, ITERS);
    benchSignVerify("ECDSA K-163", EASYM_K163, 163, 21, ITERS);
    benchSignVerify("ECDSA B-233", EASYM_B233, 233, 30, ITERS);
    benchSignVerify("ECDSA K-233", EASYM_K233, 233, 30, ITERS);
    benchSignVerify("ECDSA B-283", EASYM_B283, 283, 36, ITERS);
    benchSignVerify("ECDSA K-283", EASYM_K283, 283, 36, ITERS);
    benchSignVerify("ECDSA B-409", EASYM_B409, 409, 52, ITERS);
    benchSignVerify("ECDSA K-409", EASYM_K409, 409, 52, ITERS);
    benchSignVerify("ECDSA B-571", EASYM_B571, 571, 72, ITERS);
    benchSignVerify("ECDSA K-571", EASYM_K571, 571, 72, ITERS);

    printf("  -- GOST R 34.10-2012 --\n");
    benchSignVerify("GOST-256 Test", EASYM_GOST256TEST, 256, 32, ITERS);
    benchSignVerify("GOST-256 A", EASYM_GOST256A, 256, 32, ITERS);
    benchSignVerify("GOST-256 B", EASYM_GOST256B, 256, 32, ITERS);
    benchSignVerify("GOST-256 C", EASYM_GOST256C, 256, 32, ITERS);
    benchSignVerify("GOST-256 D", EASYM_GOST256D, 256, 32, ITERS);
    benchSignVerify("GOST-512 Test", EASYM_GOST512TEST, 512, 64, ITERS);
    benchSignVerify("GOST-512 A", EASYM_GOST512A, 512, 64, ITERS);
    benchSignVerify("GOST-512 B", EASYM_GOST512B, 512, 64, ITERS);
    benchSignVerify("GOST-512 C", EASYM_GOST512C, 512, 64, ITERS);

    printf("  -- ML-DSA (FIPS 204) --\n");
    benchSignVerify("ML-DSA-44", EASYM_MLDSA44, 44, 0, ITERS);
    benchSignVerify("ML-DSA-65", EASYM_MLDSA65, 65, 0, ITERS);
    benchSignVerify("ML-DSA-87", EASYM_MLDSA87, 87, 0, ITERS);

    printf("\n= Key agreement and encapsulation =\n");
    benchAgreement("X25519", EASYM_X25519, 256, ITERS);

    printf("  -- ECDH over prime curves --\n");
    // --> ECDH over a prime curve is the slowest thing here and runs fewer iterations for it.
    benchAgreement("ECDH P-192", EASYM_P192, 192, 10);
    benchAgreement("ECDH P-224", EASYM_P224, 224, 10);
    benchAgreement("ECDH P-256", EASYM_P256, 256, 10);
    benchAgreement("ECDH P-384", EASYM_P384, 384, 5);
    benchAgreement("ECDH P-521", EASYM_P521, 521, 5);
    benchAgreement("ECDH secp256k1", EASYM_SECP256K1, 256, 10);

    printf("  -- ECDH over Brainpool --\n");
    benchAgreement("ECDH bp160r1", EASYM_BPOOL160R1, 160, 10);
    benchAgreement("ECDH bp192r1", EASYM_BPOOL192R1, 192, 10);
    benchAgreement("ECDH bp224r1", EASYM_BPOOL224R1, 224, 10);
    benchAgreement("ECDH bp256r1", EASYM_BPOOL256R1, 256, 10);
    benchAgreement("ECDH bp320r1", EASYM_BPOOL320R1, 320, 5);
    benchAgreement("ECDH bp384r1", EASYM_BPOOL384R1, 384, 5);
    benchAgreement("ECDH bp512r1", EASYM_BPOOL512R1, 512, 5);
    benchAgreement("ECDH bp160t1", EASYM_BPOOL160T1, 160, 10);
    benchAgreement("ECDH bp192t1", EASYM_BPOOL192T1, 192, 10);
    benchAgreement("ECDH bp224t1", EASYM_BPOOL224T1, 224, 10);
    benchAgreement("ECDH bp256t1", EASYM_BPOOL256T1, 256, 10);
    benchAgreement("ECDH bp320t1", EASYM_BPOOL320T1, 320, 5);
    benchAgreement("ECDH bp384t1", EASYM_BPOOL384T1, 384, 5);
    benchAgreement("ECDH bp512t1", EASYM_BPOOL512T1, 512, 5);

    printf("  -- ECDH over GF(2^m) --\n");
    benchAgreement("ECDH B-163", EASYM_B163, 163, 10);
    benchAgreement("ECDH K-163", EASYM_K163, 163, 10);
    benchAgreement("ECDH B-233", EASYM_B233, 233, 10);
    benchAgreement("ECDH K-233", EASYM_K233, 233, 10);
    benchAgreement("ECDH B-283", EASYM_B283, 283, 10);
    benchAgreement("ECDH K-283", EASYM_K283, 283, 10);
    benchAgreement("ECDH B-409", EASYM_B409, 409, 5);
    benchAgreement("ECDH K-409", EASYM_K409, 409, 5);
    benchAgreement("ECDH B-571", EASYM_B571, 571, 5);
    benchAgreement("ECDH K-571", EASYM_K571, 571, 5);

    printf("  -- ML-KEM (FIPS 203) --\n");
    benchKem();

    const std::vector<uint8_t> bulk(BULK_BYTES, 0xa5);

    printf("\n= Hashing, %zu KiB buffer =\n", BULK_BYTES / 1024);
    benchHash("MD4", EHASH_MD4, bulk);
    benchHash("MD5", EHASH_MD5, bulk);
    benchHash("SHA-1", EHASH_SHA1, bulk);
    benchHash("SHA-224", EHASH_SHA224, bulk);
    benchHash("SHA-256", EHASH_SHA256, bulk);
    benchHash("SHA-384", EHASH_SHA384, bulk);
    benchHash("SHA-512", EHASH_SHA512, bulk);
    benchHash("SHA3-256", EHASH_SHA3_256, bulk);
    benchHash("SHA3-512", EHASH_SHA3_512, bulk);
    benchHash("SHAKE-128", EHASH_SHAKE128, bulk);
    benchHash("SHAKE-256", EHASH_SHAKE256, bulk);
    benchHash("BLAKE2s", EHASH_BLAKE2S, bulk);
    benchHash("Streebog-256", EHASH_STREEBOG256, bulk);
    benchHash("Streebog-512", EHASH_STREEBOG512, bulk);

    printf("\n= Block ciphers, CBC, %zu KiB =\n", BULK_BYTES / 1024);
    benchBlockCiphers(bulk);

    printf("\n= AEAD seal, %zu KiB =\n", BULK_BYTES / 1024);
    benchAeads(bulk);

    printf("\n= AEAD seal, 64 B, per record\n");
    benchSmallRecord();

    return 0;
}
