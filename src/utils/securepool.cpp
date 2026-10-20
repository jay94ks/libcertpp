#include "securepool.hpp"
#include <certpp/io/span.hpp>
#include <certpp/utils/secure.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <new>

#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

namespace certpp {

    namespace {

        constexpr std::uint64_t SECURE_PAGE_MAGIC = UINT64_C(0x4353454350414745);
        constexpr std::uint64_t SECURE_BLOCK_MAGIC = UINT64_C(0x43534543424c4f43);
        constexpr std::uint64_t SECURE_PREFIX_MAGIC = UINT64_C(0x4353454350524546);
        constexpr size_t SECURE_BASE_ALIGNMENT = alignof(std::max_align_t);

        constexpr size_t SECURE_PAGE_HEADER_SIZE =
            (sizeof(SecurePage) + SECURE_BASE_ALIGNMENT - 1)
            & ~(SECURE_BASE_ALIGNMENT - 1);
        constexpr size_t SECURE_MIN_BLOCK_SIZE =
            (sizeof(SecureBlock) + sizeof(SecurePrefix) + 1
             + SECURE_BASE_ALIGNMENT - 1)
            & ~(SECURE_BASE_ALIGNMENT - 1);

    } // namespace

    SecurePool::SecurePool()
        : _pages(nullptr), _emptyPage(nullptr), _pageSize(platformPageSize()),
          _largePageSize(platformLargePageSize()) {}

    SecurePool::~SecurePool() {
        SecurePage* page = _pages;
        while (page) {
            SecurePage* next = page->next;
            const size_t mappingSize = page->mappingSize;
            const bool requiresUnlock = page->requiresUnlock;
            CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(page), mappingSize));
            (void)unlockAndUnmapPages(page, mappingSize, requiresUnlock);
            page = next;
        }
    }

    SecurePool& SecurePool::instance() {
        static SecurePool pool;
        return pool;
    }

    bool SecurePool::addChecked(size_t first, size_t second, size_t& out) {
        if (first > std::numeric_limits<size_t>::max() - second) {
            return false;
        }
        out = first + second;
        return true;
    }

    bool SecurePool::alignChecked(size_t value, size_t alignment, size_t& out) {
        size_t withPadding = 0;
        if (!addChecked(value, alignment - 1, withPadding)) {
            return false;
        }
        out = withPadding & ~(alignment - 1);
        return true;
    }

    size_t SecurePool::platformPageSize() {
#if defined(_WIN32)
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        return info.dwPageSize == 0 ? size_t(4096) : size_t(info.dwPageSize);
#else
        const long value = sysconf(_SC_PAGESIZE);
        return value <= 0 ? size_t(4096) : size_t(value);
#endif
    }

    size_t SecurePool::platformLargePageSize() {
#if defined(CERTPP_DISABLE_LARGE_PAGE)
        return 0;
#elif defined(_WIN32)
        return size_t(GetLargePageMinimum());
#elif defined(__linux__) && defined(MAP_HUGETLB)
        std::FILE* file = std::fopen("/proc/meminfo", "r");
        if (!file) {
            return 0;
        }

        char line[256]{};
        unsigned long long kilobytes = 0;
        while (std::fgets(line, sizeof(line), file)) {
            if (std::sscanf(line, "Hugepagesize: %llu kB", &kilobytes) == 1) {
                break;
            }
        }
        std::fclose(file);

        if (kilobytes == 0
            || kilobytes > std::numeric_limits<size_t>::max() / size_t(1024)) {
            return 0;
        }
        return size_t(kilobytes) * size_t(1024);
#else
        return 0;
#endif
    }

    void* SecurePool::mapLockedPages(
        size_t size, bool largePage, bool& requiresUnlock
    ) {
        requiresUnlock = false;
#if defined(_WIN32)
        const DWORD allocationType = MEM_COMMIT | MEM_RESERVE
            | (largePage ? MEM_LARGE_PAGES : DWORD(0));
        void* mapping = VirtualAlloc(nullptr, size, allocationType, PAGE_READWRITE);
        if (!mapping) {
            return nullptr;
        }
        if (largePage) {
            // MEM_LARGE_PAGES mappings are already nonpageable.
            return mapping;
        }
        if (!VirtualLock(mapping, size)) {
            VirtualFree(mapping, 0, MEM_RELEASE);
            return nullptr;
        }
        requiresUnlock = true;
        return mapping;
#else
        #if defined(MAP_ANONYMOUS)
            constexpr int anonymousFlag = MAP_ANONYMOUS;
        #else
            constexpr int anonymousFlag = MAP_ANON;
        #endif
        int flags = MAP_PRIVATE | anonymousFlag;
        #if defined(__linux__) && defined(MAP_HUGETLB)
            if (largePage) {
                flags |= MAP_HUGETLB;
            }
        #else
            if (largePage) {
                return nullptr;
            }
        #endif
        void* mapping = mmap(nullptr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (mapping == MAP_FAILED) {
            return nullptr;
        }
        // Linux HugeTLB mappings are already nonpageable. Standard anonymous mappings
        // need an explicit lock before any allocator metadata or secret reaches them.
        if (!largePage) {
            if (mlock(mapping, size) != 0) {
                munmap(mapping, size);
                return nullptr;
            }
            requiresUnlock = true;
        }
        #if defined(MADV_DONTDUMP)
            // Dump exclusion is additional hardening. Its absence or rejection must not
            // turn a protected allocation into an ordinary heap fallback.
            (void)madvise(mapping, size, MADV_DONTDUMP);
        #endif
        return mapping;
#endif
    }

    bool SecurePool::unlockAndUnmapPages(
        void* mapping, size_t size, bool requiresUnlock
    ) {
#if defined(_WIN32)
        const bool unlocked = !requiresUnlock || VirtualUnlock(mapping, size) != FALSE;
        const bool released = VirtualFree(mapping, 0, MEM_RELEASE) != FALSE;
        return unlocked && released;
#else
        const bool unlocked = !requiresUnlock || munlock(mapping, size) == 0;
        const bool released = munmap(mapping, size) == 0;
        return unlocked && released;
#endif
    }

    bool SecurePool::tryAllocate(
        SecurePage* page, size_t size, size_t alignment, void** out
    ) {
        for (SecureBlock* block = page->first; block; block = block->next) {
            if (!block->free) {
                continue;
            }

            const std::uintptr_t blockAddress = reinterpret_cast<std::uintptr_t>(block);
            const std::uintptr_t dataAddress = blockAddress + sizeof(SecureBlock);
            if (dataAddress > std::numeric_limits<std::uintptr_t>::max()
                              - sizeof(SecurePrefix) - (alignment - 1)) {
                continue;
            }
            const std::uintptr_t userAddress =
                (dataAddress + sizeof(SecurePrefix) + alignment - 1)
                & ~std::uintptr_t(alignment - 1);
            if (userAddress > std::numeric_limits<std::uintptr_t>::max() - size) {
                continue;
            }

            const std::uintptr_t endAddress = userAddress + size;
            if (endAddress < blockAddress || endAddress - blockAddress > block->span) {
                continue;
            }

            size_t consumed = size_t(endAddress - blockAddress);
            if (!alignChecked(consumed, SECURE_BASE_ALIGNMENT, consumed)
                || consumed > block->span) {
                continue;
            }

            const size_t remainder = block->span - consumed;
            if (remainder >= SECURE_MIN_BLOCK_SIZE) {
                auto* next = new (reinterpret_cast<void*>(blockAddress + consumed))
                    SecureBlock{SECURE_BLOCK_MAGIC, page, block->next, remainder, nullptr, true};
                block->next = next;
                block->span = consumed;
            }

            new (reinterpret_cast<void*>(userAddress - sizeof(SecurePrefix)))
                SecurePrefix{SECURE_PREFIX_MAGIC, block};
            block->user = reinterpret_cast<void*>(userAddress);
            block->free = false;
            ++page->liveBlocks;
            *out = block->user;
            return true;
        }
        return false;
    }

    SecurePage* SecurePool::createPage(size_t size, size_t alignment) {
        size_t required = SECURE_PAGE_HEADER_SIZE;
        if (!addChecked(required, sizeof(SecureBlock), required)
            || !addChecked(required, sizeof(SecurePrefix), required)
            || !addChecked(required, alignment - 1, required)
            || !addChecked(required, size, required)) {
            return nullptr;
        }

        size_t mappingSize = 0;
        bool requiresUnlock = false;
        void* mapping = nullptr;
        if (_largePageSize != 0
            && alignChecked(required, _largePageSize, mappingSize)) {
            mapping = mapLockedPages(mappingSize, true, requiresUnlock);
        }
        if (!mapping) {
            if (!alignChecked(required, _pageSize, mappingSize)) {
                return nullptr;
            }
            mapping = mapLockedPages(mappingSize, false, requiresUnlock);
            if (!mapping) {
                return nullptr;
            }
        }

        auto* page = new (mapping)
            SecurePage{
                SECURE_PAGE_MAGIC, _pages, nullptr, mappingSize, 0, requiresUnlock
            };
        auto* first = new (static_cast<uint8_t*>(mapping) + SECURE_PAGE_HEADER_SIZE)
            SecureBlock{SECURE_BLOCK_MAGIC, page, nullptr,
                        mappingSize - SECURE_PAGE_HEADER_SIZE, nullptr, true};
        page->first = first;
        _pages = page;
        return page;
    }

    void SecurePool::unlinkPage(SecurePage* page) {
        SecurePage** current = &_pages;
        while (*current && *current != page) {
            current = &(*current)->next;
        }
        if (*current == page) {
            *current = page->next;
        }
    }

    void SecurePool::resetEmptyPage(SecurePage* page) {
        SecurePage* next = page->next;
        const size_t mappingSize = page->mappingSize;
        const bool requiresUnlock = page->requiresUnlock;

        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(page), mappingSize));
        new (page) SecurePage{
            SECURE_PAGE_MAGIC, next, nullptr, mappingSize, 0, requiresUnlock
        };
        auto* first = new (reinterpret_cast<uint8_t*>(page) + SECURE_PAGE_HEADER_SIZE)
            SecureBlock{SECURE_BLOCK_MAGIC, page, nullptr,
                        mappingSize - SECURE_PAGE_HEADER_SIZE, nullptr, true};
        page->first = first;
    }

    ERetCode SecurePool::allocate(void** out, size_t size, size_t alignment) {
        if (!out) {
            return ERET_INVAL;
        }
        *out = nullptr;
        if (size == 0 || alignment == 0 || (alignment & (alignment - 1)) != 0) {
            return ERET_INVAL;
        }
        if (alignment < SECURE_BASE_ALIGNMENT) {
            alignment = SECURE_BASE_ALIGNMENT;
        }

        std::lock_guard<std::mutex> lock(_mutex);
        for (SecurePage* page = _pages; page; page = page->next) {
            if (tryAllocate(page, size, alignment, out)) {
                if (page == _emptyPage) {
                    _emptyPage = nullptr;
                }
                return ERET_OK;
            }
        }

        SecurePage* page = createPage(size, alignment);
        if (!page) {
            return ERET_NOMEM;
        }
        if (tryAllocate(page, size, alignment, out)) {
            return ERET_OK;
        }

        unlinkPage(page);
        const size_t mappingSize = page->mappingSize;
        const bool requiresUnlock = page->requiresUnlock;
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(page), mappingSize));
        (void)unlockAndUnmapPages(page, mappingSize, requiresUnlock);
        return ERET_UNKNOWN;
    }

    ERetCode SecurePool::release(void* ptr) {
        if (!ptr) {
            return ERET_OK;
        }

        auto* prefix = reinterpret_cast<SecurePrefix*>(
            static_cast<uint8_t*>(ptr) - sizeof(SecurePrefix));
        if (prefix->magic != SECURE_PREFIX_MAGIC || !prefix->block) {
            return ERET_INVAL;
        }

        SecureBlock* block = prefix->block;
        std::lock_guard<std::mutex> lock(_mutex);
        if (block->magic != SECURE_BLOCK_MAGIC || block->free || block->user != ptr
            || !block->page || block->page->magic != SECURE_PAGE_MAGIC) {
            return ERET_INVAL;
        }

        SecurePage* page = block->page;
        CSecure::zero(SByteSpan(
            reinterpret_cast<uint8_t*>(block) + sizeof(SecureBlock),
            block->span - sizeof(SecureBlock)));
        block->user = nullptr;
        block->free = true;
        --page->liveBlocks;

        if (block->next && block->next->free) {
            block->span += block->next->span;
            block->next = block->next->next;
        }

        SecureBlock* previous = nullptr;
        for (SecureBlock* current = page->first;
             current && current != block; current = current->next) {
            previous = current;
        }
        if (previous && previous->free) {
            previous->span += block->span;
            previous->next = block->next;
        }

        if (page->liveBlocks != 0) {
            return ERET_OK;
        }

        // Keep one ordinary page locked and zeroed so short-lived keys do not pay a
        // VirtualLock/mlock plus unlock/unmap round trip on every operation. The cache is
        // bounded to one standard page; large pages and excess empty pages are returned to the
        // operating system immediately. resetEmptyPage() wipes the complete mapping before
        // rebuilding only the allocator metadata needed for reuse.
        if (page->mappingSize == _pageSize && _emptyPage == nullptr) {
            resetEmptyPage(page);
            _emptyPage = page;
            return ERET_OK;
        }

        unlinkPage(page);
        const size_t mappingSize = page->mappingSize;
        const bool requiresUnlock = page->requiresUnlock;
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(page), mappingSize));
        return unlockAndUnmapPages(page, mappingSize, requiresUnlock)
            ? ERET_OK : ERET_UNKNOWN;
    }

} // namespace certpp
