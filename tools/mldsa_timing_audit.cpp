#include "crypto/asyms/mldsascheme.hpp"

#include <certpp/io/array.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>

using namespace certpp;
using namespace certpp::crypto;

namespace {

    struct SParameterSet {
        const char* name;
        MlDsaParams params;
    };

    uint8_t pattern(size_t sample, size_t offset, uint8_t domain) {
        uint64_t x = uint64_t(sample + 1) * 0x9E3779B97F4A7C15ull;
        x ^= uint64_t(offset + 1) * 0xD1B54A32D192ED03ull;
        x ^= uint64_t(domain) * 0x94D049BB133111EBull;
        x ^= x >> 29;
        x *= 0xBF58476D1CE4E5B9ull;
        return uint8_t(x >> 56);
    }

} // namespace

int main(int argc, char** argv) {
    size_t samples = 32;
    if (argc == 2) {
        const unsigned long parsed = std::strtoul(argv[1], nullptr, 10);
        if (parsed == 0) {
            std::cerr << "sample count must be greater than zero\n";
            return 2;
        }
        samples = size_t(parsed);
    }
    else if (argc != 1) {
        std::cerr << "usage: certpp_mldsa_timing_audit [samples-per-parameter-set]\n";
        return 2;
    }

    const SParameterSet sets[] = {
        { "ML-DSA-44", MlDsaParams::mlDsa44() },
        { "ML-DSA-65", MlDsaParams::mlDsa65() },
        { "ML-DSA-87", MlDsaParams::mlDsa87() },
    };

    std::cout
        << "parameter_set,sample,attempts,z_norm_rejections,low_bits_rejections,"
           "t0_norm_rejections,hint_weight_rejections,nanoseconds,signature_checksum\n";

    for (const SParameterSet& set : sets) {
        uint8_t seed[MlDsaScheme::SEED_BYTES];
        for (size_t i = 0; i < sizeof(seed); ++i) {
            seed[i] = pattern(size_t(set.params.k), i, 0x4B);
        }

        TArray<uint8_t> publicKey;
        TArray<uint8_t> privateKey;
        if (!publicKey.resize(set.params.publicKeyBytes())
            || !privateKey.resize(set.params.privateKeyBytes())
            || !MlDsaScheme::keyGenInternal(
                set.params, SReadOnlyByteSpan(seed, sizeof(seed)),
                SByteSpan(publicKey.begin(), publicKey.size()),
                SByteSpan(privateKey.begin(), privateKey.size())))
        {
            std::cerr << "key generation failed for " << set.name << "\n";
            return 1;
        }

        TArray<uint8_t> signature;
        if (!signature.resize(set.params.signatureBytes())) {
            return 1;
        }

        for (size_t sample = 0; sample < samples; ++sample) {
            uint8_t message[64];
            uint8_t rnd[MlDsaScheme::RND_BYTES];
            for (size_t i = 0; i < sizeof(message); ++i) {
                message[i] = pattern(sample, i, uint8_t(set.params.l));
            }
            for (size_t i = 0; i < sizeof(rnd); ++i) {
                rnd[i] = pattern(sample, i, uint8_t(0x80u + set.params.k));
            }

            MlDsaSignMetrics metrics;
            const auto started = std::chrono::steady_clock::now();
            const bool signedOk = MlDsaScheme::signInternal(
                set.params,
                SReadOnlyByteSpan(privateKey.begin(), privateKey.size()),
                SReadOnlyByteSpan(message, sizeof(message)), SReadOnlyByteSpan(),
                SReadOnlyByteSpan(rnd, sizeof(rnd)),
                SByteSpan(signature.begin(), signature.size()), &metrics);
            const auto finished = std::chrono::steady_clock::now();
            if (!signedOk) {
                std::cerr << "signing failed for " << set.name << " sample " << sample << "\n";
                return 1;
            }

            uint32_t checksum = 2166136261u;
            for (size_t i = 0; i < signature.size(); ++i) {
                checksum = (checksum ^ signature[i]) * 16777619u;
            }

            const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                finished - started).count();
            std::cout << set.name << ',' << sample << ',' << metrics.attempts << ','
                      << metrics.zNormRejections << ',' << metrics.lowBitsRejections << ','
                      << metrics.t0NormRejections << ',' << metrics.hintWeightRejections << ','
                      << elapsed << ',' << checksum << '\n';
        }
    }

    return 0;
}
