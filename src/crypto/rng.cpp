#include <certpp/crypto/rng.hpp>
#include <certpp/io/buffer.hpp>
#include <cstring>

#if defined(CERTPP_RNG_FALLBACK)
#include <random>
#endif

#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <cerrno>
#include <cstdio>
#include <sys/random.h>
#else
#include <cstdio>
#endif

namespace certpp {
namespace crypto {

#if defined(CERTPP_RNG_FALLBACK)

    /* Fallback used only if the OS CSPRNG is unavailable; fills out via std::random_device. */
    ERetCode CRng::fillFallback(const SByteSpan& out) {
        try {
            std::random_device rd;

            size_t i = 0;
            while (i < out.size) {
                uint32_t word = rd();
                size_t n = out.size - i < 4 ? out.size - i : 4;

                uint8_t wordBytes[4] = {
                    uint8_t(word), uint8_t(word >> 8), uint8_t(word >> 16), uint8_t(word >> 24)
                };
                std::memcpy(out.data + i, wordBytes, n);

                i += n;
            }
        } catch (...) {
            return ERET_UNKNOWN;
        }

        return ERET_OK;
    }

#else

    /* CERTPP_RNG_FALLBACK is OFF -- the std::random_device fallback is compiled out entirely. */
    ERetCode CRng::fillFallback(const SByteSpan&) {
        return ERET_NOTSUP;
    }

#endif

#if defined(_WIN32)

    /* Fills out with random bytes via bcrypt.lib's BCryptGenRandom, called directly. */
    ERetCode CRng::fill(const SByteSpan& out) {
        if (out.empty()) {
            return ERET_OK;
        }

        NTSTATUS status = BCryptGenRandom(nullptr, out.data, static_cast<ULONG>(out.size),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        return BCRYPT_SUCCESS(status) ? ERET_OK : fillFallback(out);
    }

#elif defined(__linux__)

    /* Fills out with random bytes via the getrandom(2) syscall (Linux 3.17+/glibc 2.25+), which
       draws from the same CSPRNG as /dev/urandom but needs no file descriptor, so it keeps
       working under sandboxes/containers that block filesystem access to /dev. A short read
       (e.g. interrupted by a signal while blocked on an uninitialized entropy pool) just resumes
       for the remaining bytes; any outright failure (ENOSYS on an old kernel or a seccomp filter
       blocking the syscall, EPERM, ...) falls back to /dev/urandom for the bytes not yet filled. */
    ERetCode CRng::fill(const SByteSpan& out) {
        if (out.empty()) {
            return ERET_OK;
        }

        size_t filled = 0;
        while (filled < out.size) {
            ssize_t n = getrandom(out.data + filled, out.size - filled, 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                SByteSpan remaining(out.data + filled, out.size - filled);

                std::FILE* fp = std::fopen("/dev/urandom", "rb");
                if (!fp) {
                    return fillFallback(remaining);
                }

                size_t read = std::fread(remaining.data, 1, remaining.size, fp);
                std::fclose(fp);

                return read == remaining.size ? ERET_OK : fillFallback(remaining);
            }

            filled += size_t(n);
        }

        return ERET_OK;
    }

#else

    /* Fills out with random bytes read from /dev/urandom. */
    ERetCode CRng::fill(const SByteSpan& out) {
        if (out.empty()) {
            return ERET_OK;
        }

        std::FILE* fp = std::fopen("/dev/urandom", "rb");
        if (!fp) {
            return fillFallback(out);
        }

        size_t n = std::fread(out.data, 1, out.size, fp);
        std::fclose(fp);

        return n == out.size ? ERET_OK : fillFallback(out);
    }

#endif

    ERetCode CRng::fillNonZero(const SByteSpan& out) {
        size_t filled = 0;

        while (filled < out.size) {
            size_t need = out.size - filled;

            CBuffer chunk(need);

            ERetCode status = fill(chunk.toSpan());
            if (status != ERET_OK) {
                return status;
            }

            const uint8_t* chunkPtr = chunk.toPtr();
            for (size_t i = 0; i < need && filled < out.size; ++i) {
                if (chunkPtr[i] != 0) {
                    out.data[filled++] = chunkPtr[i];
                }
            }
        }

        return ERET_OK;
    }

} // namespace crypto
} // namespace certpp
