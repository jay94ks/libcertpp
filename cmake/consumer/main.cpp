#include <certpp.hpp>

int main() {
    const certpp::SVersion linked = certpp::GetLibraryVersion();
    if (linked != certpp::HEADER_VERSION) {
        return 1;
    }

    return certpp::crypto::CAlgorithmPolicy::allowsGeneration(
        certpp::crypto::CAlgorithmPolicy::classify(certpp::crypto::EHASH_SHA256)) ? 0 : 2;
}
