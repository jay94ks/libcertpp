#ifndef __SRC_UTILS_SECUREPOOL_HPP__
#define __SRC_UTILS_SECUREPOOL_HPP__

#include <certpp/common.hpp>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace certpp {

    struct SecurePage;

    struct alignas(std::max_align_t) SecureBlock {
        std::uint64_t magic;
        SecurePage* page;
        SecureBlock* next;
        size_t span;
        void* user;
        bool free;
    };

    struct alignas(std::max_align_t) SecurePage {
        std::uint64_t magic;
        SecurePage* next;
        SecureBlock* first;
        size_t mappingSize;
        size_t liveBlocks;
        bool requiresUnlock;
    };

    struct alignas(std::max_align_t) SecurePrefix {
        std::uint64_t magic;
        SecureBlock* block;
    };

    /**
     * Private page-backed allocator used by CSecure. It owns only operating-system mappings;
     * allocation metadata lives inside the locked pages and contains no secret payload.
     */
    class SecurePool {
    private:
        std::mutex _mutex;
        SecurePage* _pages;
        SecurePage* _emptyPage;
        const size_t _pageSize;
        const size_t _largePageSize;

    private:
        static bool addChecked(size_t first, size_t second, size_t& out);
        static bool alignChecked(size_t value, size_t alignment, size_t& out);
        static size_t platformPageSize();
        static size_t platformLargePageSize();
        static void* mapLockedPages(size_t size, bool largePage, bool& requiresUnlock);
        static bool unlockAndUnmapPages(
            void* mapping, size_t size, bool requiresUnlock
        );

        bool tryAllocate(SecurePage* page, size_t size, size_t alignment, void** out);
        SecurePage* createPage(size_t size, size_t alignment);
        void unlinkPage(SecurePage* page);
        void resetEmptyPage(SecurePage* page);

    public:
        SecurePool();
        ~SecurePool();

        SecurePool(const SecurePool&) = delete;
        SecurePool& operator=(const SecurePool&) = delete;

        static SecurePool& instance();

        ERetCode allocate(void** out, size_t size, size_t alignment);
        ERetCode release(void* ptr);
    };

} // namespace certpp

#endif
