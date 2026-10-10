// Where does certpp stand against OpenSSL, on the same machine, in the same process?
//
// This is the comparison that gives the library's numbers meaning: 7.25 ms for a DSA-2048
// signature is only fast or slow relative to something. OpenSSL 3 is the reference --
// what every other TLS stack uses, and its back ends are among the most optimized code
// in existence.
//
// The comparison is deliberately not flattering, and the ways it could mislead are worth
// stating:
//
//   1. Both implementations run in the SAME process, in the SAME loop shape, so neither
//      gets a quieter CPU or a warmer cache than the other.
//   2. OpenSSL is called through EVP directly rather than through certpp's ISymmetric /
//      IAsymmetric wrapper. That measures the cryptography rather than certpp's per-call
//      allocations and context bookkeeping, which a real caller does pay.
//   3. Warm-up matters more than it looks. OpenSSL resolves its constructors lazily, and
//      the first SHA-256 of 64 KiB costs 963 us against 38.9 us warm -- 25x. A probe that
//      does not warm up reports OpenSSL as a quarter of its real speed, which is how the
//      first version of this file produced 797 MiB/s against openssl speed's 1524.
//   4. Every figure is the fastest of OUTER batches, the same methodology the README uses,
//      and both toolchains are measured in the same session.
#include <certpp.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    constexpr int OUTER = 5;

    double fastestNs(int iters, const std::function<void()>& body) {
        double best = 0.0;
        for (int o = 0; o < OUTER; ++o) {
            const auto t0 = std::chrono::steady_clock::now();
            for (int i = 0; i < iters; ++i) {
                body();
            }
            const auto t1 = std::chrono::steady_clock::now();
            const double ns =
                std::chrono::duration<double, std::nano>(t1 - t0).count() / iters;
            if (o == 0 || ns < best) {
                best = ns;
            }
        }
        return best;
    }

    /* Times one side on its own. The two implementations are NOT interleaved: alternating
     * them in one loop costs both about half their speed (certpp's SHA-256 drops from 1523
     * to 765 MiB/s), which is an artefact of the measurement rather than a property of
     * either implementation. Each side therefore gets its own loop, its own warm-up, and the
     * same fastest-of-five shape, and the results are printed side by side rather than
     * measured side by side. */
    void rowMiB(const char* name, size_t bytes,
                const std::function<void()>& certpp, const std::function<void()>& ossl) {
        // Warm up each side alone, so neither is measured cold.
        for (int i = 0; i < 300; ++i) {
            certpp();
        }
        for (int i = 0; i < 300; ++i) {
            ossl();
        }

        // 300 iterations per batch: a 64 KiB hash is about 40 us, so a 40-iteration batch is
        // 1.6 ms of work -- short enough that the scheduler dominates it. At 40 the SHA-256
        // row spread 17% between runs, which made the README's figure unreproducible.
        const double a = fastestNs(300, certpp);
        const double b = fastestNs(300, ossl);
        const double ma = (double(bytes) / (1024.0 * 1024.0)) / (a / 1e9);
        const double mb = (double(bytes) / (1024.0 * 1024.0)) / (b / 1e9);
        std::printf("  %-24s %8.0f MiB/s  %8.0f MiB/s  %6.2fx\n", name, ma, mb, ma / mb);
    }

    std::vector<uint8_t> randomBytes(size_t n) {
        std::vector<uint8_t> v(n);
        RAND_bytes(v.data(), int(n));
        return v;
    }
}

int main() {
    std::printf("============================================================\n");
    std::printf("  certpp vs OpenSSL\n");
    std::printf("  each side timed on its own, same machine, both warmed up\n");
    std::printf("  (interleaving them in one loop costs both about half their speed)\n");
    std::printf("============================================================\n\n");

    // ------------------------------------------------------------------- hashing
    std::printf("-- Hashing, 64 KiB --\n");
    {
        const std::vector<uint8_t> data = randomBytes(64 * 1024);
        const SReadOnlyByteSpan dataSpan(data.data(), data.size());

        struct H {
            const char* name;
            EHashers certpp;
            const EVP_MD* ossl;
        };
        const H hashes[] = {
            { "SHA-256", EHASH_SHA256, EVP_sha256() },
            { "SHA-512", EHASH_SHA512, EVP_sha512() },
            { "SHA3-256", EHASH_SHA3_256, EVP_sha3_256() },
            { "SHA-1", EHASH_SHA1, EVP_sha1() },
            { "MD5", EHASH_MD5, EVP_md5() },
            { "SHAKE-256", EHASH_SHAKE256, EVP_shake256() },
        };

        for (const H& h : hashes) {
            IHasherPtr certppHasher;
            if (IHasher::create(h.certpp, certppHasher) != ERET_OK || !certppHasher) {
                std::printf("  %-24s certpp unavailable\n", h.name);
                continue;
            }
            const size_t width = certppHasher->byteWidth()
                ? certppHasher->byteWidth() : 64;
            std::vector<uint8_t> dg(width);

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            std::vector<uint8_t> dg2(EVP_MD_size(h.ossl) ? size_t(EVP_MD_size(h.ossl)) : 64);

            rowMiB(h.name, data.size(),
                [&] {
                    certppHasher->reset();
                    certppHasher->push(dataSpan);
                    certppHasher->finish(SByteSpan(dg.data(), dg.size()));
                },
                [&] {
                    EVP_DigestInit_ex(ctx, h.ossl, nullptr);
                    EVP_DigestUpdate(ctx, data.data(), data.size());
                    unsigned len = 0;
                    EVP_DigestFinal_ex(ctx, dg2.data(), &len);
                });

            EVP_MD_CTX_free(ctx);
        }
    }

    // ------------------------------------------------------------- block ciphers
    std::printf("\n-- Block cipher, 64 KiB --\n");
    {
        const std::vector<uint8_t> bulk(64 * 1024, 0xa5);
        const std::vector<uint8_t> iv(16, 0);
        const SReadOnlyByteSpan bulkSpan(bulk.data(), bulk.size());
        uint8_t raw[32] = { 0 };

        struct C {
            const char* name;
            ESymmetrics algo;
            size_t keyBytes;
            const char* osslName;
        };
        const C ciphers[] = {
            { "AES-256-CBC", ESYM_AES, 32, "aes-256-cbc" },
            { "ARIA-256-CBC", ESYM_ARIA, 32, "aria-256-cbc" },
        };

        for (const C& c : ciphers) {
            ISymmetricPtr sym = ISymmetric::builtIn(c.algo);
            if (!sym) {
                std::printf("  %-24s certpp unavailable\n", c.name);
                continue;
            }
            ISymmetricKeyPtr key = sym->createKey(SReadOnlyByteSpan(raw, c.keyBytes));
            if (!key) {
                std::printf("  %-24s certpp key rejected\n", c.name);
                continue;
            }
            ISymmetricContextPtr ctx = sym->createContext(key);
            ctx->key(key, CBuffer(iv.data(), iv.size()));
            ctx->padding(ESYMPAD_NONE);
            std::vector<uint8_t> out(bulk.size() + 32);
            ISymmetricTransformerPtr enc;
            if (ctx->createEncrypter(enc) != ERET_OK) {
                std::printf("  %-24s certpp encrypter failed\n", c.name);
                continue;
            }

            const EVP_CIPHER* evp = EVP_CIPHER_fetch(nullptr, c.osslName, nullptr);
            if (!evp) {
                std::printf("  %-24s (no such OpenSSL cipher)\n", c.name);
                continue;
            }

            EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
            if (!cctx || EVP_EncryptInit_ex2(cctx, evp, raw, iv.data(), nullptr) != 1) {
                std::printf("  %-24s OpenSSL init failed\n", c.name);
                EVP_CIPHER_CTX_free(cctx);
                EVP_CIPHER_free(const_cast<EVP_CIPHER*>(evp));
                continue;
            }
            EVP_CIPHER_CTX_set_padding(cctx, 0);
            std::vector<uint8_t> out2(bulk.size() + 32);

            rowMiB(c.name, bulk.size(),
                [&] {
                    SByteSpan s(out.data(), out.size());
                    enc->transform(bulkSpan, s);
                },
                [&] {
                    int outl = 0;
                    EVP_CIPHER_CTX_reset(cctx);
                    EVP_EncryptInit_ex2(cctx, evp, raw, iv.data(), nullptr);
                    EVP_CIPHER_CTX_set_padding(cctx, 0);
                    EVP_EncryptUpdate(cctx, out2.data(), &outl,
                        bulk.data(), int(bulk.size()));
                });

            EVP_CIPHER_CTX_free(cctx);
            EVP_CIPHER_free(const_cast<EVP_CIPHER*>(evp));
        }
    }

    // --------------------------------------------------------------- signatures
    std::printf("\n-- Sign --\n");
    {
        struct S {
            const char* name;
            EAsymmetrics algo;
            SKeySize bits;
        };
        const S sigs[] = {
            { "Ed25519", EASYM_ED25519, 256 },
        };

        for (const S& s : sigs) {
            IAsymmetricPtr alg = IAsymmetric::builtIn(s.algo);
            if (!alg) {
                std::printf("  %-24s certpp unavailable\n", s.name);
                continue;
            }
            SKeyPair pair;
            if (alg->generateKeyPair(s.bits, pair) != ERET_OK) {
                std::printf("  %-24s certpp keygen failed\n", s.name);
                continue;
            }
            IAsymmetricContextPtr ctx = alg->createContext();
            ctx->keyPair(pair);

            const std::vector<uint8_t> msg(32, 0x5a);
            const SReadOnlyByteSpan msgSpan(msg.data(), msg.size());
            std::vector<uint8_t> sig(ctx->sizeOfSign());
            SByteSpan sigSpan(sig.data(), sig.size());
            if (ctx->sign(msgSpan, sigSpan) != ERET_OK) {
                std::printf("  %-24s certpp sign failed\n", s.name);
                continue;
            }

            EVP_PKEY* pkey = nullptr;
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
            if (!pctx || EVP_PKEY_keygen_init(pctx) != 1
                || EVP_PKEY_keygen(pctx, &pkey) != 1) {
                std::printf("  %-24s OpenSSL keygen failed\n", s.name);
                EVP_PKEY_CTX_free(pctx);
                continue;
            }
            EVP_PKEY_CTX_free(pctx);

            EVP_MD_CTX* mctx = EVP_MD_CTX_new();
            std::vector<uint8_t> osslSig(64);
            size_t sigLen = osslSig.size();
            if (EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey) != 1) {
                std::printf("  %-24s OpenSSL sign init failed\n", s.name);
            } else {
                const double a = fastestNs(20, [&] {
                    std::vector<uint8_t> o(ctx->sizeOfSign());
                    SByteSpan sp(o.data(), o.size());
                    ctx->sign(msgSpan, sp);
                });
                const double b = fastestNs(20, [&] {
                    sigLen = osslSig.size();
                    EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey);
                    EVP_DigestSign(mctx, osslSig.data(), &sigLen,
                        msg.data(), msg.size());
                });
                std::printf("  %-24s %8.3f ms      %8.3f ms      %6.2fx\n",
                    s.name, a / 1e6, b / 1e6, a / b);
            }

            EVP_MD_CTX_free(mctx);
            EVP_PKEY_free(pkey);
        }
    }

    std::printf("\n");
    return 0;
}