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
//
// Pass --hashes or --block-ciphers to run only that bulk inventory while tuning a primitive,
// --classic-signatures to run only RSA/DSA/GOST, --rsa or --dsa to isolate either one while tuning,
// --prime-curves to run only the prime-field ECDSA/ECDH inventory,
// --binary-curves to run only the binary-field ECDSA inventory,
// --ed25519 to run only Ed25519 sign/verify,
// or --ed448 to run only Ed448 sign/verify.
// With no option the complete inventory runs.
#include <certpp.hpp>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
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
    constexpr int SIGNATURE_ITERS = 200;
    constexpr int P256_ITERS = 1000;

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
                const std::function<void()>& certpp, const std::function<void()>& ossl,
                int iters = 300) {
        // Warm up each side alone, so neither is measured cold.
        const int warmupIters = iters < 100 ? iters : 100;
        for (int i = 0; i < warmupIters; ++i) {
            certpp();
        }
        for (int i = 0; i < warmupIters; ++i) {
            ossl();
        }

        // Hash and fast-cipher rows use 300 iterations per batch: a 64 KiB SHA-256 call is about
        // 40 us, so a 40-iteration batch is short enough that the scheduler dominates it. Slow
        // legacy ciphers pass a smaller count so one row does not take minutes.
        const double a = fastestNs(iters, certpp);
        const double b = fastestNs(iters, ossl);
        const double ma = (double(bytes) / (1024.0 * 1024.0)) / (a / 1e9);
        const double mb = (double(bytes) / (1024.0 * 1024.0)) / (b / 1e9);
        std::printf("  %-24s %8.0f MiB/s  %8.0f MiB/s  %6.2fx\n", name, ma, mb, ma / mb);
    }

    /* Reports latency with the same ratio direction as throughput: OpenSSL/certpp, so values at
     * or above one mean certpp is at least as fast. */
    void rowNs(const char* name, const std::function<void()>& certpp,
               const std::function<void()>& ossl, int iters) {
        for (int i = 0; i < 100; ++i) {
            certpp();
        }
        for (int i = 0; i < 100; ++i) {
            ossl();
        }
        const double a = fastestNs(iters, certpp);
        const double b = fastestNs(iters, ossl);
        std::printf("  %-24s %8.0f ns     %8.0f ns     %6.2fx\n", name, a, b, b / a);
    }

    void rowMs(const char* name, const std::function<void()>& certpp,
               const std::function<void()>& ossl, int iters) {
        const int warmupIters = iters < 100 ? iters : 100;
        for (int i = 0; i < warmupIters; ++i) {
            certpp();
        }
        for (int i = 0; i < warmupIters; ++i) {
            ossl();
        }

        const auto batchNs = [iters](const std::function<void()>& body) {
            const auto t0 = std::chrono::steady_clock::now();
            for (int i = 0; i < iters; ++i) {
                body();
            }
            const auto t1 = std::chrono::steady_clock::now();
            return std::chrono::duration<double, std::nano>(t1 - t0).count() / iters;
        };
        double a = 0.0;
        double b = 0.0;
        for (int outer = 0; outer < OUTER; ++outer) {
            double candidateA;
            double candidateB;
            // Keep each implementation in an independent batch while alternating
            // which one receives the first-batch frequency and thermal conditions.
            if ((outer & 1) == 0) {
                candidateA = batchNs(certpp);
                candidateB = batchNs(ossl);
            } else {
                candidateB = batchNs(ossl);
                candidateA = batchNs(certpp);
            }
            if (outer == 0 || candidateA < a) {
                a = candidateA;
            }
            if (outer == 0 || candidateB < b) {
                b = candidateB;
            }
        }
        std::printf("  %-24s %8.3f ms      %8.3f ms      %7.3fx\n",
            name, a / 1e6, b / 1e6, b / a);
    }

    std::vector<uint8_t> randomBytes(size_t n) {
        std::vector<uint8_t> v(n);
        RAND_bytes(v.data(), int(n));
        return v;
    }

    struct EcCurveSpec {
        const char* name;
        EAsymmetrics certpp;
        SKeySize bits;
        const char* osslGroup;
        int iters;
        bool agreement;
    };

    bool generateCertppKeyPair(
        const IAsymmetricPtr& algorithm, SKeySize bits, SKeyPair& pair
    ) {
        for (int attempt = 0; attempt < 16; ++attempt) {
            const ERetCode result = algorithm->generateKeyPair(bits, pair);
            if (result == ERET_OK) {
                return true;
            }
            if (result != ERET_AGAIN) {
                break;
            }
        }
        return false;
    }

    EVP_PKEY* generateOpenSslEcKey(const char* group) {
        return EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", group);
    }

    EVP_PKEY* importOpenSslEcPublic(
        const char* group, const SReadOnlyByteSpan& encoded
    ) {
        EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        EVP_PKEY* key = nullptr;
        char* mutableGroup = const_cast<char*>(group);
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, mutableGroup, 0),
            OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, const_cast<uint8_t*>(encoded.data), encoded.size),
            OSSL_PARAM_construct_end(),
        };
        if (!context || EVP_PKEY_fromdata_init(context) != 1
            || EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            EVP_PKEY_free(key);
            key = nullptr;
        }
        EVP_PKEY_CTX_free(context);
        return key;
    }

    bool exportOpenSslEcPublic(EVP_PKEY* key, std::vector<uint8_t>& encoded) {
        size_t size = 0;
        if (EVP_PKEY_get_octet_string_param(
                key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &size) != 1
            || size == 0) {
            return false;
        }
        encoded.resize(size);
        return EVP_PKEY_get_octet_string_param(
            key, OSSL_PKEY_PARAM_PUB_KEY, encoded.data(), encoded.size(), &size) == 1
            && size == encoded.size();
    }

    EVP_PKEY_CTX* createOpenSslSignatureContext(EVP_PKEY* key, bool signing) {
        EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(key, nullptr);
        if (!context) {
            return nullptr;
        }
        char digestName[] = "SHA256";
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(
                OSSL_SIGNATURE_PARAM_DIGEST, digestName, 0),
            OSSL_PARAM_construct_end(),
        };
        const int initialized = signing
            ? EVP_PKEY_sign_init_ex(context, params)
            : EVP_PKEY_verify_init_ex(context, params);
        if (initialized != 1) {
            EVP_PKEY_CTX_free(context);
            return nullptr;
        }
        return context;
    }

    EVP_PKEY* importOpenSslPrivateKey(const COctet& encoded) {
        const unsigned char* cursor = encoded.toPtr();
        return d2i_AutoPrivateKey_ex(
            nullptr, &cursor, long(encoded.size()), nullptr, nullptr);
    }

    EVP_PKEY* generateOpenSslRsaKey(int bits) {
        return EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", bits);
    }

    EVP_PKEY* generateOpenSslDsaKey(int bits) {
        EVP_PKEY_CTX* paramContext = EVP_PKEY_CTX_new_from_name(nullptr, "DSA", nullptr);
        EVP_PKEY* parameters = nullptr;
        int pBits = bits;
        int qBits = bits == 1024 ? 160 : 256;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_PBITS, &pBits),
            OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_QBITS, &qBits),
            OSSL_PARAM_construct_end(),
        };
        if (!paramContext || EVP_PKEY_paramgen_init(paramContext) != 1
            || EVP_PKEY_CTX_set_params(paramContext, params) != 1
            || EVP_PKEY_generate(paramContext, &parameters) != 1) {
            EVP_PKEY_free(parameters);
            EVP_PKEY_CTX_free(paramContext);
            return nullptr;
        }
        EVP_PKEY_CTX_free(paramContext);

        EVP_PKEY_CTX* keyContext = EVP_PKEY_CTX_new(parameters, nullptr);
        EVP_PKEY* key = nullptr;
        if (!keyContext || EVP_PKEY_keygen_init(keyContext) != 1
            || EVP_PKEY_generate(keyContext, &key) != 1) {
            EVP_PKEY_free(key);
            key = nullptr;
        }
        EVP_PKEY_CTX_free(keyContext);
        EVP_PKEY_free(parameters);
        return key;
    }

    void benchTraditionalSignature(
        const char* name, EAsymmetrics certppAlgorithm, SKeySize bits,
        const std::function<EVP_PKEY*()>& generateOpenSslKey,
        int operationIters, int keygenIters
    ) {
        IAsymmetricPtr algorithm = IAsymmetric::builtIn(certppAlgorithm);
        SKeyPair certppPair;
        if (!algorithm || !generateCertppKeyPair(algorithm, bits, certppPair)) {
            std::printf("  %-24s certpp setup failed\n", name);
            return;
        }

        COctet privateDer;
        if (certppPair.privateKey->serialize(privateDer) != ERET_OK) {
            std::printf("  %-24s private-key export failed\n", name);
            return;
        }
        EVP_PKEY* importedKey = importOpenSslPrivateKey(privateDer);
        if (!importedKey) {
            std::printf("  %-24s OpenSSL key import failed\n", name);
            return;
        }

        IAsymmetricContextPtr certppContext = algorithm->createContext();
        certppContext->keyPair(certppPair);
        EVP_PKEY_CTX* osslSign = createOpenSslSignatureContext(importedKey, true);
        EVP_PKEY_CTX* osslVerify = createOpenSslSignatureContext(importedKey, false);
        const std::vector<uint8_t> digest(32, 0x5a);
        std::vector<uint8_t> changedDigest(digest);
        changedDigest[0] ^= 0x80;
        const SReadOnlyByteSpan digestSpan(digest.data(), digest.size());

        std::vector<uint8_t> certppSignature(certppContext->sizeOfSign());
        SByteSpan certppSignatureSpan(certppSignature.data(), certppSignature.size());
        size_t osslSignatureSize = 0;
        if (!osslSign || !osslVerify
            || certppContext->sign(digestSpan, certppSignatureSpan) != ERET_OK
            || EVP_PKEY_sign(
                osslSign, nullptr, &osslSignatureSize, digest.data(), digest.size()) != 1) {
            std::printf("  %-24s signature setup failed\n", name);
            EVP_PKEY_CTX_free(osslVerify);
            EVP_PKEY_CTX_free(osslSign);
            EVP_PKEY_free(importedKey);
            return;
        }
        certppSignature.resize(certppSignatureSpan.size);
        std::vector<uint8_t> osslSignature(osslSignatureSize);
        if (EVP_PKEY_sign(osslSign, osslSignature.data(), &osslSignatureSize,
                digest.data(), digest.size()) != 1) {
            std::printf("  %-24s OpenSSL sign failed\n", name);
            EVP_PKEY_CTX_free(osslVerify);
            EVP_PKEY_CTX_free(osslSign);
            EVP_PKEY_free(importedKey);
            return;
        }
        osslSignature.resize(osslSignatureSize);

        const SReadOnlyByteSpan certppSignatureRead(
            certppSignature.data(), certppSignature.size());
        const SReadOnlyByteSpan osslSignatureRead(
            osslSignature.data(), osslSignature.size());
        const bool interoperable =
            EVP_PKEY_verify(osslVerify,
                certppSignature.data(), certppSignature.size(),
                digest.data(), digest.size()) == 1
            && certppContext->verify(digestSpan, osslSignatureRead) == ERET_OK
            && EVP_PKEY_verify(osslVerify,
                certppSignature.data(), certppSignature.size(),
                changedDigest.data(), changedDigest.size()) != 1
            && certppContext->verify(
                SReadOnlyByteSpan(changedDigest.data(), changedDigest.size()),
                osslSignatureRead) != ERET_OK;
        if (!interoperable) {
            std::printf("  %-24s interoperability failed\n", name);
            EVP_PKEY_CTX_free(osslVerify);
            EVP_PKEY_CTX_free(osslSign);
            EVP_PKEY_free(importedKey);
            return;
        }

        char label[96];
        std::snprintf(label, sizeof(label), "%s keygen", name);
        rowMs(label,
            [&] {
                SKeyPair pair;
                generateCertppKeyPair(algorithm, bits, pair);
            },
            [&] {
                EVP_PKEY* key = generateOpenSslKey();
                EVP_PKEY_free(key);
            }, keygenIters);

        std::vector<uint8_t> certppScratch(certppContext->sizeOfSign());
        std::vector<uint8_t> osslScratch(osslSignature.size() + 16);
        std::snprintf(label, sizeof(label), "%s sign", name);
        rowMs(label,
            [&] {
                SByteSpan output(certppScratch.data(), certppScratch.size());
                certppContext->sign(digestSpan, output);
            },
            [&] {
                size_t outputSize = osslScratch.size();
                EVP_PKEY_sign(osslSign, osslScratch.data(), &outputSize,
                    digest.data(), digest.size());
            }, operationIters);

        std::snprintf(label, sizeof(label), "%s verify", name);
        rowMs(label,
            [&] { certppContext->verify(digestSpan, osslSignatureRead); },
            [&] {
                EVP_PKEY_verify(osslVerify,
                    certppSignatureRead.data, certppSignatureRead.size,
                    digest.data(), digest.size());
            }, operationIters);

        EVP_PKEY_CTX_free(osslVerify);
        EVP_PKEY_CTX_free(osslSign);
        EVP_PKEY_free(importedKey);
    }

    void benchRsa() {
        benchTraditionalSignature("RSA-2048", EASYM_RSA, 2048,
            [] { return generateOpenSslRsaKey(2048); }, 50, 2);
    }

    void benchDsa() {
        benchTraditionalSignature("DSA-2048", EASYM_DSA, 2048,
            [] { return generateOpenSslDsaKey(2048); }, 20, 1);
    }

    void benchClassicSignatures() {
        benchRsa();
        benchDsa();

        const char* gostNames[] = {
            "GOST2012_256", "GOST2012_512", "gost2012_256", "gost2012_512"
        };
        bool gostAvailable = false;
        for (const char* gostName : gostNames) {
            EVP_SIGNATURE* signature = EVP_SIGNATURE_fetch(nullptr, gostName, nullptr);
            gostAvailable = gostAvailable || signature != nullptr;
            EVP_SIGNATURE_free(signature);
        }
        if (!gostAvailable) {
            std::printf(
                "  %-24s OpenSSL unavailable (default/legacy providers)\n",
                "GOST R 34.10-2012");
        }
    }

    void benchEcCurve(const EcCurveSpec& spec) {
        IAsymmetricPtr algorithm = IAsymmetric::builtIn(spec.certpp);
        SKeyPair certppPair;
        EVP_PKEY* osslPair = generateOpenSslEcKey(spec.osslGroup);
        if (!algorithm || !generateCertppKeyPair(algorithm, spec.bits, certppPair)) {
            std::printf("  %-24s certpp setup failed\n", spec.name);
            EVP_PKEY_free(osslPair);
            return;
        }
        if (!osslPair) {
            std::printf("  %-24s OpenSSL unavailable\n", spec.name);
            return;
        }

        COctet certppPublicBytes;
        std::vector<uint8_t> osslPublicBytes;
        if (certppPair.publicKey->serialize(certppPublicBytes) != ERET_OK
            || !exportOpenSslEcPublic(osslPair, osslPublicBytes)) {
            std::printf("  %-24s public-key export failed\n", spec.name);
            EVP_PKEY_free(osslPair);
            return;
        }

        EVP_PKEY* certppPublic = importOpenSslEcPublic(
            spec.osslGroup, certppPublicBytes.toSpan());
        IPublicKeyPtr osslPublic = algorithm->createPublicKey(
            SReadOnlyByteSpan(osslPublicBytes.data(), osslPublicBytes.size()));
        if (!certppPublic || !osslPublic) {
            std::printf("  %-24s public-key import failed\n", spec.name);
            EVP_PKEY_free(certppPublic);
            EVP_PKEY_free(osslPair);
            return;
        }

        IAsymmetricContextPtr certppSign = algorithm->createContext();
        IAsymmetricContextPtr certppVerify = algorithm->createContext();
        certppSign->keyPair(certppPair);
        certppVerify->keyPair(osslPublic, nullptr);

        EVP_PKEY_CTX* osslSign = createOpenSslSignatureContext(osslPair, true);
        EVP_PKEY_CTX* osslVerify = createOpenSslSignatureContext(certppPublic, false);
        const std::vector<uint8_t> digest(32, 0x5a);
        std::vector<uint8_t> changedDigest(digest);
        changedDigest[0] ^= 0x80;
        const SReadOnlyByteSpan digestSpan(digest.data(), digest.size());

        std::vector<uint8_t> certppSignature(certppSign->sizeOfSign());
        SByteSpan certppSignatureSpan(certppSignature.data(), certppSignature.size());
        size_t osslSignatureSize = 0;
        if (!osslSign || !osslVerify
            || certppSign->sign(digestSpan, certppSignatureSpan) != ERET_OK
            || EVP_PKEY_sign(
                osslSign, nullptr, &osslSignatureSize, digest.data(), digest.size()) != 1) {
            std::printf("  %-24s signature setup failed\n", spec.name);
            EVP_PKEY_CTX_free(osslVerify);
            EVP_PKEY_CTX_free(osslSign);
            EVP_PKEY_free(certppPublic);
            EVP_PKEY_free(osslPair);
            return;
        }
        certppSignature.resize(certppSignatureSpan.size);
        std::vector<uint8_t> osslSignature(osslSignatureSize);
        if (EVP_PKEY_sign(osslSign, osslSignature.data(), &osslSignatureSize,
                digest.data(), digest.size()) != 1) {
            std::printf("  %-24s OpenSSL sign failed\n", spec.name);
            EVP_PKEY_CTX_free(osslVerify);
            EVP_PKEY_CTX_free(osslSign);
            EVP_PKEY_free(certppPublic);
            EVP_PKEY_free(osslPair);
            return;
        }
        osslSignature.resize(osslSignatureSize);

        const SReadOnlyByteSpan certppSignatureRead(
            certppSignature.data(), certppSignature.size());
        const SReadOnlyByteSpan osslSignatureRead(
            osslSignature.data(), osslSignature.size());
        bool signaturesInteroperate =
            EVP_PKEY_verify(osslVerify,
                certppSignature.data(), certppSignature.size(),
                digest.data(), digest.size()) == 1
            && certppVerify->verify(digestSpan, osslSignatureRead) == ERET_OK
            && EVP_PKEY_verify(osslVerify,
                certppSignature.data(), certppSignature.size(),
                changedDigest.data(), changedDigest.size()) != 1
            && certppVerify->verify(
                SReadOnlyByteSpan(changedDigest.data(), changedDigest.size()),
                osslSignatureRead) != ERET_OK;
        // Cross the P-256 signing nonce batch boundary before timing and have OpenSSL verify each
        // result. Other curves simply exercise their ordinary per-signature path nine more times.
        for (size_t i = 0; i < 9 && signaturesInteroperate; ++i) {
            std::vector<uint8_t> preparedSignature(certppSign->sizeOfSign());
            SByteSpan preparedSpan(preparedSignature.data(), preparedSignature.size());
            signaturesInteroperate =
                certppSign->sign(digestSpan, preparedSpan) == ERET_OK
                && EVP_PKEY_verify(osslVerify,
                    preparedSignature.data(), preparedSpan.size,
                    digest.data(), digest.size()) == 1;
        }
        if (!signaturesInteroperate) {
            std::printf("  %-24s signature interoperability failed\n", spec.name);
            EVP_PKEY_CTX_free(osslVerify);
            EVP_PKEY_CTX_free(osslSign);
            EVP_PKEY_free(certppPublic);
            EVP_PKEY_free(osslPair);
            return;
        }

        EVP_PKEY_CTX* osslDerive = nullptr;
        std::vector<uint8_t> certppSecret((spec.bits + 7) / 8);
        std::vector<uint8_t> osslSecret(certppSecret.size());
        SByteSpan certppSecretSpan(certppSecret.data(), certppSecret.size());
        size_t osslSecretSize = osslSecret.size();
        if (spec.agreement) {
            osslDerive = EVP_PKEY_CTX_new(osslPair, nullptr);
        }
        if (spec.agreement
            && (!osslDerive || EVP_PKEY_derive_init(osslDerive) != 1
                || EVP_PKEY_derive_set_peer(osslDerive, certppPublic) != 1
                || certppSign->deriveSharedSecret(osslPublic, certppSecretSpan) != ERET_OK
                || EVP_PKEY_derive(osslDerive, osslSecret.data(), &osslSecretSize) != 1
                || certppSecretSpan.size != osslSecretSize
                || std::memcmp(certppSecret.data(), osslSecret.data(), osslSecretSize) != 0)) {
            std::printf("  %-24s ECDH interoperability failed\n", spec.name);
            EVP_PKEY_CTX_free(osslDerive);
            EVP_PKEY_CTX_free(osslVerify);
            EVP_PKEY_CTX_free(osslSign);
            EVP_PKEY_free(certppPublic);
            EVP_PKEY_free(osslPair);
            return;
        }

        char label[96];
        std::snprintf(label, sizeof(label), "%s keygen", spec.name);
        rowMs(label,
            [&] {
                SKeyPair pair;
                generateCertppKeyPair(algorithm, spec.bits, pair);
            },
            [&] {
                EVP_PKEY* pair = generateOpenSslEcKey(spec.osslGroup);
                EVP_PKEY_free(pair);
            }, spec.iters);

        std::vector<uint8_t> certppScratch(certppSign->sizeOfSign());
        std::vector<uint8_t> osslScratch(osslSignature.size() + 8);
        std::snprintf(label, sizeof(label), "%s ECDSA sign", spec.name);
        rowMs(label,
            [&] {
                SByteSpan output(certppScratch.data(), certppScratch.size());
                certppSign->sign(digestSpan, output);
            },
            [&] {
                size_t outputSize = osslScratch.size();
                EVP_PKEY_sign(osslSign, osslScratch.data(), &outputSize,
                    digest.data(), digest.size());
            }, spec.iters);

        std::snprintf(label, sizeof(label), "%s ECDSA verify", spec.name);
        rowMs(label,
            [&] { certppVerify->verify(digestSpan, osslSignatureRead); },
            [&] {
                EVP_PKEY_verify(osslVerify,
                    certppSignatureRead.data, certppSignatureRead.size,
                    digest.data(), digest.size());
            }, spec.iters);

        if (spec.agreement) {
            std::snprintf(label, sizeof(label), "%s ECDH derive", spec.name);
            rowMs(label,
                [&] {
                    SByteSpan output(certppSecret.data(), certppSecret.size());
                    certppSign->deriveSharedSecret(osslPublic, output);
                },
                [&] {
                    size_t outputSize = osslSecret.size();
                    EVP_PKEY_derive(osslDerive, osslSecret.data(), &outputSize);
                }, spec.iters);
        }

        EVP_PKEY_CTX_free(osslDerive);
        EVP_PKEY_CTX_free(osslVerify);
        EVP_PKEY_CTX_free(osslSign);
        EVP_PKEY_free(certppPublic);
        EVP_PKEY_free(osslPair);
    }

    void benchPrimeCurves() {
        const EcCurveSpec curves[] = {
            { "P-192", EASYM_P192, 192, "prime192v1", 20, true },
            { "P-224", EASYM_P224, 224, "secp224r1", 20, true },
            { "P-256", EASYM_P256, 256, "prime256v1", P256_ITERS, true },
            { "P-384", EASYM_P384, 384, "secp384r1", 10, true },
            { "P-521", EASYM_P521, 521, "secp521r1", 4, true },
            { "secp256k1", EASYM_SECP256K1, 256, "secp256k1", 20, true },
            { "brainpoolP160r1", EASYM_BPOOL160R1, 160, "brainpoolP160r1", 20, true },
            { "brainpoolP192r1", EASYM_BPOOL192R1, 192, "brainpoolP192r1", 20, true },
            { "brainpoolP224r1", EASYM_BPOOL224R1, 224, "brainpoolP224r1", 20, true },
            { "brainpoolP256r1", EASYM_BPOOL256R1, 256, "brainpoolP256r1", 20, true },
            { "brainpoolP320r1", EASYM_BPOOL320R1, 320, "brainpoolP320r1", 10, true },
            { "brainpoolP384r1", EASYM_BPOOL384R1, 384, "brainpoolP384r1", 10, true },
            { "brainpoolP512r1", EASYM_BPOOL512R1, 512, "brainpoolP512r1", 4, true },
            { "brainpoolP160t1", EASYM_BPOOL160T1, 160, "brainpoolP160t1", 20, true },
            { "brainpoolP192t1", EASYM_BPOOL192T1, 192, "brainpoolP192t1", 20, true },
            { "brainpoolP224t1", EASYM_BPOOL224T1, 224, "brainpoolP224t1", 20, true },
            { "brainpoolP256t1", EASYM_BPOOL256T1, 256, "brainpoolP256t1", 20, true },
            { "brainpoolP320t1", EASYM_BPOOL320T1, 320, "brainpoolP320t1", 10, true },
            { "brainpoolP384t1", EASYM_BPOOL384T1, 384, "brainpoolP384t1", 10, true },
            { "brainpoolP512t1", EASYM_BPOOL512T1, 512, "brainpoolP512t1", 4, true },
        };
        for (const EcCurveSpec& curve : curves) {
            benchEcCurve(curve);
        }
    }

    void benchBinaryCurves() {
        const EcCurveSpec curves[] = {
            { "B-163", EASYM_B163, 163, "sect163r2", 20, false },
            { "K-163", EASYM_K163, 163, "sect163k1", 20, false },
            { "B-233", EASYM_B233, 233, "sect233r1", 20, false },
            { "K-233", EASYM_K233, 233, "sect233k1", 20, false },
            { "B-283", EASYM_B283, 283, "sect283r1", 10, false },
            { "K-283", EASYM_K283, 283, "sect283k1", 10, false },
            { "B-409", EASYM_B409, 409, "sect409r1", 4, false },
            { "K-409", EASYM_K409, 409, "sect409k1", 4, false },
            { "B-571", EASYM_B571, 571, "sect571r1", 2, false },
            { "K-571", EASYM_K571, 571, "sect571k1", 2, false },
        };
        for (const EcCurveSpec& curve : curves) {
            benchEcCurve(curve);
        }
    }
}

int main(int argc, char** argv) {
    OSSL_PROVIDER* defaultProvider = OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER* legacyProvider = OSSL_PROVIDER_load(nullptr, "legacy");

    std::printf("============================================================\n");
    std::printf("  certpp vs OpenSSL\n");
    std::printf("  each side timed on its own, same machine, both warmed up\n");
    std::printf("  (interleaving them in one loop costs both about half their speed)\n");
    std::printf("============================================================\n\n");

    if (argc == 2 && std::strcmp(argv[1], "--classic-signatures") == 0) {
        std::printf("-- Signatures --\n");
        benchClassicSignatures();
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    if (argc == 2 && std::strcmp(argv[1], "--rsa") == 0) {
        std::printf("-- RSA signature --\n");
        benchRsa();
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    if (argc == 2 && std::strcmp(argv[1], "--dsa") == 0) {
        std::printf("-- DSA signature --\n");
        benchDsa();
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    if (argc == 2 && std::strcmp(argv[1], "--p256") == 0) {
        std::printf("-- Prime-curve signatures and agreement --\n");
        benchEcCurve({ "P-256", EASYM_P256, 256, "prime256v1", P256_ITERS, true });
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    if (argc == 2 && std::strcmp(argv[1], "--prime-curves") == 0) {
        std::printf("-- Prime-curve signatures and agreement --\n");
        benchPrimeCurves();
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    if (argc == 2 && std::strcmp(argv[1], "--binary-curves") == 0) {
        std::printf("-- Binary-curve signatures (ECDH unsupported by certpp) --\n");
        benchBinaryCurves();
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    const bool hashesOnly = argc == 2 && std::strcmp(argv[1], "--hashes") == 0;
    const bool blockCiphersOnly =
        argc == 2 && std::strcmp(argv[1], "--block-ciphers") == 0;
    const bool aeadOnly = argc == 2 && std::strcmp(argv[1], "--aead") == 0;
    const bool ed25519Only = argc == 2 && std::strcmp(argv[1], "--ed25519") == 0;
    const bool ed448Only = argc == 2 && std::strcmp(argv[1], "--ed448") == 0;
    const bool x25519Only = argc == 2 && std::strcmp(argv[1], "--x25519") == 0;
    const bool mlkemOnly = argc == 2 && std::strcmp(argv[1], "--mlkem") == 0;
    const bool mldsaOnly = argc == 2 && std::strcmp(argv[1], "--mldsa") == 0;
    const bool signatureFocus = ed25519Only || ed448Only || mldsaOnly;

    if (!signatureFocus) {
        if (!x25519Only && !mlkemOnly) {
        // --------------------------------------------------------------- hashing
        if (!blockCiphersOnly && !aeadOnly) {
            std::printf("-- Hashing, 64 KiB --\n");
            const std::vector<uint8_t> data = randomBytes(64 * 1024);
            const SReadOnlyByteSpan dataSpan(data.data(), data.size());

        struct H {
            const char* name;
            EHashers certpp;
            const char* osslName;
            bool xof;
        };
        const H hashes[] = {
            { "MD4", EHASH_MD4, "MD4", false },
            { "MD5", EHASH_MD5, "MD5", false },
            { "SHA-1", EHASH_SHA1, "SHA1", false },
            { "SHA-224", EHASH_SHA224, "SHA224", false },
            { "SHA-256", EHASH_SHA256, "SHA256", false },
            { "SHA-384", EHASH_SHA384, "SHA384", false },
            { "SHA-512", EHASH_SHA512, "SHA512", false },
            { "SHA3-256", EHASH_SHA3_256, "SHA3-256", false },
            { "SHA3-512", EHASH_SHA3_512, "SHA3-512", false },
            { "SHAKE-128", EHASH_SHAKE128, "SHAKE-128", true },
            { "SHAKE-256", EHASH_SHAKE256, "SHAKE-256", true },
            { "BLAKE2s", EHASH_BLAKE2S, "BLAKE2S-256", false },
            { "Streebog-256", EHASH_STREEBOG256, "md_gost12_256", false },
            { "Streebog-512", EHASH_STREEBOG512, "md_gost12_512", false },
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

            EVP_MD* md = EVP_MD_fetch(nullptr, h.osslName, nullptr);
            if (!md) {
                std::printf("  %-24s OpenSSL unavailable\n", h.name);
                continue;
            }
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx || EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
                std::printf("  %-24s OpenSSL init failed\n", h.name);
                EVP_MD_CTX_free(ctx);
                EVP_MD_free(md);
                continue;
            }
            std::vector<uint8_t> dg2(width);

            certppHasher->reset();
            certppHasher->push(dataSpan);
            if (!certppHasher->finish(SByteSpan(dg.data(), dg.size()))
                || EVP_DigestInit_ex(ctx, md, nullptr) != 1
                || EVP_DigestUpdate(ctx, data.data(), data.size()) != 1
                || (h.xof
                    ? EVP_DigestFinalXOF(ctx, dg2.data(), dg2.size()) != 1
                    : [&] {
                        unsigned len = 0;
                        return EVP_DigestFinal_ex(ctx, dg2.data(), &len) != 1
                            || len != dg2.size();
                    }())
                || std::memcmp(dg.data(), dg2.data(), width) != 0) {
                std::printf("  %-24s digest mismatch\n", h.name);
                EVP_MD_CTX_free(ctx);
                EVP_MD_free(md);
                continue;
            }

            rowMiB(h.name, data.size(),
                [&] {
                    certppHasher->reset();
                    certppHasher->push(dataSpan);
                    certppHasher->finish(SByteSpan(dg.data(), dg.size()));
                },
                [&] {
                    EVP_DigestInit_ex(ctx, md, nullptr);
                    EVP_DigestUpdate(ctx, data.data(), data.size());
                    if (h.xof) {
                        EVP_DigestFinalXOF(ctx, dg2.data(), dg2.size());
                    } else {
                        unsigned len = 0;
                        EVP_DigestFinal_ex(ctx, dg2.data(), &len);
                    }
                });

            EVP_MD_CTX_free(ctx);
            EVP_MD_free(md);
        }
        }

    if (hashesOnly) {
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    if (!aeadOnly) {
    // ------------------------------------------------------------- block ciphers
    std::printf("\n-- Block cipher, 64 KiB --\n");
    {
        const std::vector<uint8_t> bulk(64 * 1024, 0xa5);
        const SReadOnlyByteSpan bulkSpan(bulk.data(), bulk.size());
        uint8_t raw[32] = { 0 };

        struct C {
            const char* name;
            ESymmetrics algo;
            size_t keyBytes;
            size_t ivBytes;
            const char* osslName;
            int iters;
        };
        const C ciphers[] = {
            { "AES-128-CBC", ESYM_AES, 16, 16, "aes-128-cbc", 300 },
            { "AES-192-CBC", ESYM_AES, 24, 16, "aes-192-cbc", 300 },
            { "AES-256-CBC", ESYM_AES, 32, 16, "aes-256-cbc", 300 },
            { "DES-CBC", ESYM_DES, 8, 8, "des-cbc", 10 },
            { "3DES-CBC", ESYM_3DES, 16, 8, "des-ede-cbc", 5 },
            { "ARIA-128-CBC", ESYM_ARIA, 16, 16, "aria-128-cbc", 100 },
            { "ARIA-192-CBC", ESYM_ARIA, 24, 16, "aria-192-cbc", 100 },
            { "ARIA-256-CBC", ESYM_ARIA, 32, 16, "aria-256-cbc", 100 },
        };

        for (const C& c : ciphers) {
            const std::vector<uint8_t> iv(c.ivBytes, 0);
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
                std::printf("  %-24s OpenSSL unavailable\n", c.name);
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

            SByteSpan firstOut(out.data(), out.size());
            int firstOutLen = 0;
            if (enc->transform(bulkSpan, firstOut) != ERET_OK
                || EVP_EncryptUpdate(cctx, out2.data(), &firstOutLen,
                    bulk.data(), int(bulk.size())) != 1
                || firstOut.size != size_t(firstOutLen)
                || std::memcmp(out.data(), out2.data(), firstOut.size) != 0) {
                std::printf("  %-24s ciphertext mismatch\n", c.name);
                EVP_CIPHER_CTX_free(cctx);
                EVP_CIPHER_free(const_cast<EVP_CIPHER*>(evp));
                continue;
            }

            rowMiB(c.name, bulk.size(),
                [&] {
                    SByteSpan s(out.data(), out.size());
                    enc->transform(bulkSpan, s);
                },
                [&] {
                    int outl = 0;
                    EVP_EncryptUpdate(cctx, out2.data(), &outl,
                        bulk.data(), int(bulk.size()));
                }, c.iters);

            EVP_CIPHER_CTX_free(cctx);
            EVP_CIPHER_free(const_cast<EVP_CIPHER*>(evp));
        }
    }
    }

    if (blockCiphersOnly) {
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }
        }

    if (!ed25519Only && !ed448Only && !x25519Only && !mlkemOnly) {
    // ------------------------------------------------------------------------- AEAD
    auto benchAeadSection = [&](size_t bytes, bool latency) {
        const std::vector<uint8_t> key(32, 0x01);
        const std::vector<uint8_t> nonce12(12, 0x02);
        const std::vector<uint8_t> nonce24(24, 0x03);
        const std::vector<uint8_t> plain(bytes, 0x5a);
        const SReadOnlyByteSpan keySpan(key.data(), key.size());
        const SReadOnlyByteSpan noAad(nullptr, 0);
        const SReadOnlyByteSpan plainSpan(plain.data(), plain.size());

        auto bench = [&](const char* name, auto& certppAead,
                         const std::vector<uint8_t>& nonce, const char* osslName) {
            if (!certppAead.reset(keySpan)) {
                std::printf("  %-24s certpp key rejected\n", name);
                return;
            }
            if (!osslName) {
                std::printf("  %-24s OpenSSL unavailable\n", name);
                return;
            }

            EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, osslName, nullptr);
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!cipher || !ctx
                || EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, nullptr) != 1
                || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                    int(nonce.size()), nullptr) != 1
                || EVP_EncryptInit_ex2(ctx, nullptr, key.data(), nonce.data(), nullptr) != 1) {
                std::printf("  %-24s OpenSSL init failed\n", name);
                EVP_CIPHER_CTX_free(ctx);
                EVP_CIPHER_free(cipher);
                return;
            }

            std::vector<uint8_t> certppOut(bytes), osslOut(bytes);
            uint8_t certppTag[16] = { 0 };
            uint8_t osslTag[16] = { 0 };
            const SByteSpan certppOutSpan(certppOut.data(), certppOut.size());
            const SByteSpan certppTagSpan(certppTag, sizeof(certppTag));

            auto certppSeal = [&] {
                certppAead.seal(
                    SReadOnlyByteSpan(nonce.data(), nonce.size()), noAad, plainSpan,
                    certppOutSpan, certppTagSpan);
            };
            auto osslSeal = [&] {
                int produced = 0;
                int finalBytes = 0;
                EVP_EncryptInit_ex2(ctx, nullptr, nullptr, nonce.data(), nullptr);
                EVP_EncryptUpdate(ctx, osslOut.data(), &produced,
                    plain.data(), int(plain.size()));
                EVP_EncryptFinal_ex(ctx, osslOut.data() + produced, &finalBytes);
                EVP_CIPHER_CTX_ctrl(
                    ctx, EVP_CTRL_AEAD_GET_TAG, int(sizeof(osslTag)), osslTag);
            };

            certppSeal();
            osslSeal();
            if (std::memcmp(certppOut.data(), osslOut.data(), bytes) != 0
                || std::memcmp(certppTag, osslTag, sizeof(certppTag)) != 0) {
                std::printf("  %-24s ciphertext/tag mismatch\n", name);
            } else if (latency) {
                rowNs(name, certppSeal, osslSeal, 100000);
            } else {
                rowMiB(name, bytes, certppSeal, osslSeal);
            }

            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_free(cipher);
        };

        CChaCha20Poly1305 chacha;
        bench("ChaCha20-Poly1305", chacha, nonce12, "CHACHA20-POLY1305");
        CXChaCha20Poly1305 xchacha;
        bench("XChaCha20-Poly1305", xchacha, nonce24, nullptr);
        CAesGcm aesGcm;
        bench("AES-256-GCM", aesGcm, nonce12, "AES-256-GCM");
    };

    std::printf("\n-- AEAD seal, 64 KiB --\n");
    benchAeadSection(64 * 1024, false);
    std::printf("\n-- AEAD seal, 64-byte record --\n");
    benchAeadSection(64, true);
    }

    if (aeadOnly) {
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    // --------------------------------------------------------------- key agreement
    if (!ed25519Only && !ed448Only && !mlkemOnly) {
    std::printf("\n-- Key agreement --\n");
    {
        IAsymmetricPtr algorithm = IAsymmetric::builtIn(EASYM_X25519);
        EVP_PKEY* osslMine = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        EVP_PKEY* osslPeer = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        if (!algorithm || !osslMine || !osslPeer) {
            std::printf("  %-24s setup failed\n", "X25519");
        } else {
            uint8_t privateRaw[32];
            uint8_t publicRaw[32];
            size_t privateLen = sizeof(privateRaw);
            size_t publicLen = sizeof(publicRaw);
            IPrivateKeyPtr minePrivate;
            IPublicKeyPtr peerPublic;
            if (EVP_PKEY_get_raw_private_key(osslMine, privateRaw, &privateLen) != 1
                || EVP_PKEY_get_raw_public_key(osslPeer, publicRaw, &publicLen) != 1
                || !(minePrivate = algorithm->createPrivateKey(
                    SReadOnlyByteSpan(privateRaw, privateLen)))
                || !(peerPublic = algorithm->createPublicKey(
                    SReadOnlyByteSpan(publicRaw, publicLen)))) {
                std::printf("  %-24s key import failed\n", "X25519");
            } else {
                IAsymmetricContextPtr certppCtx = algorithm->createContext();
                certppCtx->keyPair(minePrivate->publicKey(), minePrivate);
                uint8_t certppSecret[32] = { 0 };
                SByteSpan certppSecretSpan(certppSecret, sizeof(certppSecret));

                EVP_PKEY_CTX* osslCtx = EVP_PKEY_CTX_new(osslMine, nullptr);
                uint8_t osslSecret[32] = { 0 };
                size_t osslSecretLen = sizeof(osslSecret);
                if (!osslCtx || EVP_PKEY_derive_init(osslCtx) != 1
                    || EVP_PKEY_derive_set_peer(osslCtx, osslPeer) != 1
                    || certppCtx->deriveSharedSecret(peerPublic, certppSecretSpan) != ERET_OK
                    || EVP_PKEY_derive(osslCtx, osslSecret, &osslSecretLen) != 1
                    || osslSecretLen != sizeof(osslSecret)
                    || std::memcmp(certppSecret, osslSecret, sizeof(certppSecret)) != 0) {
                    std::printf("  %-24s shared-secret mismatch\n", "X25519");
                } else {
                    rowMs("X25519 keygen",
                        [&] {
                            SKeyPair pair;
                            algorithm->generateKeyPair(256, pair);
                        },
                        [&] {
                            EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
                            EVP_PKEY_free(key);
                        }, 200);
                    rowMs("X25519 derive",
                        [&] {
                            SByteSpan out(certppSecret, sizeof(certppSecret));
                            certppCtx->deriveSharedSecret(peerPublic, out);
                        },
                        [&] {
                            size_t outLen = sizeof(osslSecret);
                            EVP_PKEY_derive(osslCtx, osslSecret, &outLen);
                        }, 200);
                }
                EVP_PKEY_CTX_free(osslCtx);
            }
        }
        EVP_PKEY_free(osslPeer);
        EVP_PKEY_free(osslMine);
    }
    }

    if (x25519Only) {
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    if (!mlkemOnly) {
    std::printf("\n-- Prime-curve signatures and agreement --\n");
    benchPrimeCurves();

    std::printf("\n-- Binary-curve signatures (ECDH unsupported by certpp) --\n");
    benchBinaryCurves();
    }

    // -------------------------------------------------------------------------- KEM
    std::printf("\n-- Key encapsulation --\n");
    {
        struct S {
            const char* name;
            EKems algo;
            SKeySize bits;
            int iters;
        };
        const S kems[] = {
            { "ML-KEM-512", EKEM_MLKEM512, 512, 50 },
            { "ML-KEM-768", EKEM_MLKEM768, 768, 50 },
            { "ML-KEM-1024", EKEM_MLKEM1024, 1024, 50 },
        };

        for (const S& s : kems) {
            IKemPtr kem = IKem::builtIn(s.algo);
            SKemKeyPair certppPair;
            EVP_PKEY* osslPair = EVP_PKEY_Q_keygen(nullptr, nullptr, s.name);
            if (!kem || kem->generateKeyPair(s.bits, certppPair) != ERET_OK || !osslPair) {
                std::printf("  %-24s setup failed\n", s.name);
                EVP_PKEY_free(osslPair);
                continue;
            }

            COctet certppPublicRaw;
            size_t osslPublicLen = 0;
            if (certppPair.publicKey->serialize(certppPublicRaw) != ERET_OK
                || EVP_PKEY_get_raw_public_key(osslPair, nullptr, &osslPublicLen) != 1) {
                std::printf("  %-24s public-key export failed\n", s.name);
                EVP_PKEY_free(osslPair);
                continue;
            }
            std::vector<uint8_t> osslPublicRaw(osslPublicLen);
            if (EVP_PKEY_get_raw_public_key(
                    osslPair, osslPublicRaw.data(), &osslPublicLen) != 1) {
                std::printf("  %-24s public-key export failed\n", s.name);
                EVP_PKEY_free(osslPair);
                continue;
            }

            IKemPublicKeyPtr osslPublic = kem->createPublicKey(
                SReadOnlyByteSpan(osslPublicRaw.data(), osslPublicLen));
            EVP_PKEY* certppPublic = EVP_PKEY_new_raw_public_key_ex(
                nullptr, s.name, nullptr, certppPublicRaw.toPtr(), certppPublicRaw.size());
            IKemContextPtr certppEncap = kem->createContext();
            IKemContextPtr certppDecap = kem->createContext();
            EVP_PKEY_CTX* osslEncap = certppPublic
                ? EVP_PKEY_CTX_new(certppPublic, nullptr) : nullptr;
            EVP_PKEY_CTX* osslDecap = EVP_PKEY_CTX_new(osslPair, nullptr);
            if (osslPublic && certppEncap && certppDecap) {
                certppEncap->keyPair(osslPublic, nullptr);
                certppDecap->keyPair(nullptr, certppPair.privateKey);
            }
            if (!osslPublic || !certppPublic || !certppEncap || !certppDecap
                || !osslEncap || !osslDecap
                || EVP_PKEY_encapsulate_init(osslEncap, nullptr) != 1
                || EVP_PKEY_decapsulate_init(osslDecap, nullptr) != 1) {
                std::printf("  %-24s key import failed\n", s.name);
                EVP_PKEY_CTX_free(osslDecap);
                EVP_PKEY_CTX_free(osslEncap);
                EVP_PKEY_free(certppPublic);
                EVP_PKEY_free(osslPair);
                continue;
            }

            size_t osslCtLen = 0;
            size_t osslSsLen = 0;
            if (EVP_PKEY_encapsulate(
                    osslEncap, nullptr, &osslCtLen, nullptr, &osslSsLen) != 1) {
                std::printf("  %-24s size query failed\n", s.name);
                EVP_PKEY_CTX_free(osslDecap);
                EVP_PKEY_CTX_free(osslEncap);
                EVP_PKEY_free(certppPublic);
                EVP_PKEY_free(osslPair);
                continue;
            }

            // certpp encapsulates to the OpenSSL key, then OpenSSL decapsulates it.
            std::vector<uint8_t> certppCt(certppEncap->sizeOfCiphertext());
            std::vector<uint8_t> certppSs(certppEncap->sizeOfSharedSecret());
            SByteSpan certppCtSpan(certppCt.data(), certppCt.size());
            SByteSpan certppSsSpan(certppSs.data(), certppSs.size());
            std::vector<uint8_t> osslDecapSs(osslSsLen);
            size_t osslDecapSsLen = osslDecapSs.size();

            // OpenSSL encapsulates to the certpp key, then certpp decapsulates it.
            std::vector<uint8_t> osslCt(osslCtLen);
            std::vector<uint8_t> osslSs(osslSsLen);
            size_t actualOsslCtLen = osslCt.size();
            size_t actualOsslSsLen = osslSs.size();
            std::vector<uint8_t> certppDecapSs(certppDecap->sizeOfSharedSecret());
            SByteSpan certppDecapSsSpan(certppDecapSs.data(), certppDecapSs.size());

            const bool interoperable =
                certppEncap->encapsulate(certppCtSpan, certppSsSpan) == ERET_OK
                && EVP_PKEY_decapsulate(osslDecap, osslDecapSs.data(), &osslDecapSsLen,
                    certppCt.data(), certppCtSpan.size) == 1
                && certppSsSpan.size == osslDecapSsLen
                && std::memcmp(certppSs.data(), osslDecapSs.data(), osslDecapSsLen) == 0
                && EVP_PKEY_encapsulate(osslEncap, osslCt.data(), &actualOsslCtLen,
                    osslSs.data(), &actualOsslSsLen) == 1
                && certppDecap->decapsulate(
                    SReadOnlyByteSpan(osslCt.data(), actualOsslCtLen),
                    certppDecapSsSpan) == ERET_OK
                && certppDecapSsSpan.size == actualOsslSsLen
                && std::memcmp(certppDecapSs.data(), osslSs.data(), actualOsslSsLen) == 0;

            if (!interoperable) {
                std::printf("  %-24s interoperability check failed\n", s.name);
            } else {
                char label[64];
                std::snprintf(label, sizeof(label), "%s keygen", s.name);
                rowMs(label,
                    [&] {
                        SKemKeyPair pair;
                        kem->generateKeyPair(s.bits, pair);
                    },
                    [&] {
                        EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, s.name);
                        EVP_PKEY_free(key);
                    }, s.iters);

                std::snprintf(label, sizeof(label), "%s encapsulate", s.name);
                rowMs(label,
                    [&] {
                        SByteSpan ctSpan(certppCt.data(), certppCt.size());
                        SByteSpan ssSpan(certppSs.data(), certppSs.size());
                        certppEncap->encapsulate(ctSpan, ssSpan);
                    },
                    [&] {
                        size_t ctLen = osslCt.size();
                        size_t ssLen = osslSs.size();
                        EVP_PKEY_encapsulate(
                            osslEncap, osslCt.data(), &ctLen, osslSs.data(), &ssLen);
                    }, s.iters);

                std::snprintf(label, sizeof(label), "%s decapsulate", s.name);
                rowMs(label,
                    [&] {
                        SByteSpan ssSpan(certppDecapSs.data(), certppDecapSs.size());
                        certppDecap->decapsulate(
                            SReadOnlyByteSpan(osslCt.data(), actualOsslCtLen), ssSpan);
                    },
                    [&] {
                        size_t ssLen = osslDecapSs.size();
                        EVP_PKEY_decapsulate(osslDecap, osslDecapSs.data(), &ssLen,
                            certppCt.data(), certppCtSpan.size);
                    }, s.iters);
            }

            EVP_PKEY_CTX_free(osslDecap);
            EVP_PKEY_CTX_free(osslEncap);
            EVP_PKEY_free(certppPublic);
            EVP_PKEY_free(osslPair);
        }
    }

    }

    if (mlkemOnly) {
        if (legacyProvider) {
            OSSL_PROVIDER_unload(legacyProvider);
        }
        if (defaultProvider) {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        return 0;
    }

    // --------------------------------------------------------------- signatures
    std::printf("\n-- Signatures --\n");
    if (!signatureFocus) {
        benchClassicSignatures();
    }
    {
        struct S {
            const char* name;
            EAsymmetrics algo;
            SKeySize bits;
            const char* osslName;
            int iters;
        };
        const S sigs[] = {
            { "Ed25519", EASYM_ED25519, 256, "ED25519", SIGNATURE_ITERS },
            { "Ed448", EASYM_ED448, 456, "ED448", 20 },
            { "ML-DSA-44", EASYM_MLDSA44, 44, "ML-DSA-44", 20 },
            { "ML-DSA-65", EASYM_MLDSA65, 65, "ML-DSA-65", 20 },
            { "ML-DSA-87", EASYM_MLDSA87, 87, "ML-DSA-87", 20 },
        };

        for (const S& s : sigs) {
            if ((ed25519Only && s.algo != EASYM_ED25519)
                || (ed448Only && s.algo != EASYM_ED448)
                || (mldsaOnly && s.algo != EASYM_MLDSA44
                    && s.algo != EASYM_MLDSA65 && s.algo != EASYM_MLDSA87)) {
                continue;
            }
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

            EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, s.osslName);
            if (!pkey) {
                std::printf("  %-24s OpenSSL keygen failed\n", s.name);
                continue;
            }

            EVP_MD_CTX* mctx = EVP_MD_CTX_new();
            size_t sigLen = 0;
            if (!mctx
                || EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey) != 1
                || EVP_DigestSign(mctx, nullptr, &sigLen,
                    msg.data(), msg.size()) != 1) {
                std::printf("  %-24s OpenSSL sign setup failed\n", s.name);
                EVP_MD_CTX_free(mctx);
                EVP_PKEY_free(pkey);
                continue;
            }
            std::vector<uint8_t> osslSig(sigLen);
            if (EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey) != 1
                || EVP_DigestSign(mctx, osslSig.data(), &sigLen,
                    msg.data(), msg.size()) != 1) {
                std::printf("  %-24s OpenSSL sign setup failed\n", s.name);
            } else {
                char label[96];
                std::vector<uint8_t> certppBenchSig(ctx->sizeOfSign());
                const double a = fastestNs(s.iters, [&] {
                    SByteSpan sp(certppBenchSig.data(), certppBenchSig.size());
                    ctx->sign(msgSpan, sp);
                });
                const double b = fastestNs(s.iters, [&] {
                    sigLen = osslSig.size();
                    EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey);
                    EVP_DigestSign(mctx, osslSig.data(), &sigLen,
                        msg.data(), msg.size());
                });
                std::snprintf(label, sizeof(label), "%s sign", s.name);
                std::printf("  %-24s %8.3f ms      %8.3f ms      %6.2fx\n",
                    label, a / 1e6, b / 1e6, b / a);

                const SReadOnlyByteSpan certppSig(sig.data(), sigSpan.size);
                EVP_MD_CTX* verifyCtx = EVP_MD_CTX_new();
                if (ctx->verify(msgSpan, certppSig) != ERET_OK
                    || !verifyCtx
                    || EVP_DigestVerifyInit(
                        verifyCtx, nullptr, nullptr, nullptr, pkey) != 1
                    || EVP_DigestVerify(verifyCtx, osslSig.data(), sigLen,
                        msg.data(), msg.size()) != 1) {
                    std::printf("  %-24s verification setup failed\n", s.name);
                } else {
                    const double verifyA = fastestNs(s.iters, [&] {
                        ctx->verify(msgSpan, certppSig);
                    });
                    const double verifyB = fastestNs(s.iters, [&] {
                        EVP_DigestVerifyInit(
                            verifyCtx, nullptr, nullptr, nullptr, pkey);
                        EVP_DigestVerify(verifyCtx, osslSig.data(), sigLen,
                            msg.data(), msg.size());
                    });
                    std::snprintf(label, sizeof(label), "%s verify", s.name);
                    std::printf("  %-24s %8.3f ms      %8.3f ms      %6.2fx\n",
                        label, verifyA / 1e6, verifyB / 1e6,
                        verifyB / verifyA);
                }
                EVP_MD_CTX_free(verifyCtx);
            }

            EVP_MD_CTX_free(mctx);
            EVP_PKEY_free(pkey);
        }
    }

    std::printf("\n");
    if (legacyProvider) {
        OSSL_PROVIDER_unload(legacyProvider);
    }
    if (defaultProvider) {
        OSSL_PROVIDER_unload(defaultProvider);
    }
    return 0;
}
