#ifndef __INCLUDE_CERTPP_IO_SPAN_HPP__
#define __INCLUDE_CERTPP_IO_SPAN_HPP__

#include <certpp/common.hpp>
#include <cstring>

namespace certpp {

    /**
     * Represents a span of contiguous memory.
     * Typically used to refer to a sequence of bytes without owning the underlying storage.
     */
    template<typename T>
    struct TSpan {
        T* data;
        size_t size;    // --> Number of elements in the span.

        /**
         * Constructs a span with the given data pointer and size.
         *
         * @param data Pointer to the beginning of the memory span.
         * @param size Size of the memory span in bytes.
         */
        constexpr TSpan(T* data = nullptr, size_t size = 0) noexcept
            : data(data), size(size) {}

        /**
         * Checks if the span is empty.
         *
         * @return True if the span has no data or size is zero, false otherwise.
         */
        constexpr bool empty() const noexcept {
            return data == nullptr || size == 0;
        }

        /** 
         * Checks if the span is not empty.
         *
         * @return True if the span has data and size is non-zero, false otherwise.
         */
        constexpr operator bool() const noexcept {
            return !empty();
        }

        /**
         * Checks if the span is empty.
         *
         * @return True if the span has no data or size is zero, false otherwise.
         */
        constexpr bool operator!() const noexcept {
            return empty();
        }

        /**
         * Checks if two spans are equal.
         *
         * @param other The other span to compare with.
         * @return True if both spans have the same data pointer and size, false otherwise.
         */
        constexpr bool operator==(const TSpan<T>& other) const noexcept {
            if (empty()) {
                return other.empty();
            }

            return data == other.data && size == other.size;
        }

        /**
         * Checks if two spans are not equal.
         *
         * @param other The other span to compare with.
         * @return True if the spans have different data pointers or sizes, false otherwise.
         */
        constexpr bool operator!=(const TSpan<T>& other) const noexcept {
            return !(*this == other);
        }

        /**
         * Returns a pointer to the beginning of the memory span.
         *
         * @return Pointer to the beginning of the memory span.
         */
        constexpr T* begin() const noexcept {
            return data;
        }

        /**
         * Returns a pointer to the end of the memory span.
         *
         * @return Pointer to the end of the memory span.
         */
        constexpr T* end() const noexcept {
            return data + size;
        }

        /**
         * Accesses the element at the specified index.
         *
         * @param index The index of the element to access.
         * @return Reference to the element at the specified index.
         */
        constexpr T& operator[](size_t index) noexcept {
            return data[index];
        }

        /**
         * Accesses the element at the specified index (const version).
         *
         * @param index The index of the element to access.
         * @return Const reference to the element at the specified index.
         */
        constexpr const T& operator[](size_t index) const noexcept {
            return data[index];
        }

        /**
         * Returns a subspan of the memory span starting at the given offset with the specified length.
         *
         * @param offset Offset from the beginning of the memory span.
         * @param length Length of the subspan.
         * @return A new TSpan representing the subspan.
         */
        constexpr TSpan<T> slice(size_t offset, size_t length) const noexcept {
            if (offset >= size) {
                return TSpan(nullptr, 0);
            }

            if (offset + length > size) {
                length = size - offset;
            }

            return TSpan(data + offset, length);
        }

        /**
         * Returns a subspan of the memory span starting at the given offset.
         *
         * @param offset Offset from the beginning of the memory span.
         * @return A new TSpan representing the subspan.
         */
        constexpr TSpan<T> slice(size_t offset) const noexcept {
            if (offset >= size) {
                return TSpan(nullptr, 0);
            }

            return slice(offset, size - offset);
        }

        /**
         * Reinterprets the memory span as a span of a different type.
         *
         * @tparam U The type to reinterpret the memory span as.
         * @return A new TSpan representing the reinterpreted memory span.
         */
        template<typename U>
        constexpr TSpan<U> reinterpret() const noexcept {
            return TSpan<U>(reinterpret_cast<U*>(data), (size * sizeof(T)) / sizeof(U));
        }

        /**
         * Compares this span with another span.
         *
         * @param other The other span to compare with.
         * @return A negative value if this span is less than the other span, zero if they are equal, and a positive value if this span is greater than the other span.
         */
        inline int32_t compare(const TSpan<T>& other) const {
            if (empty()) {
                return other.empty() ? 0 : -1;
            }

            if (other.empty()) {
                return 1;
            }

            size_t min = size < other.size ? size : other.size;
            int cmp = std::memcmp(data, other.data, min * sizeof(T));

            if (cmp != 0) {
                return cmp;
            }

            return static_cast<int32_t>(size) - static_cast<int32_t>(other.size);
        }

        /**
         * Checks if this span is sequentially equal to another span.
         *
         * @param other The other span to compare with.
         * @return True if the spans are sequentially equal, false otherwise.
         */
        inline bool sequencialEqual(const TSpan<T>& other) const noexcept {
            return compare(other) == 0;
        }

        /**
         * Copies the contents of this span to the destination span.
         *
         * @param destination The destination span to copy to.
         * @return The number of elements copied.
         */
        inline size_t copyTo(TSpan<T>& destination) const noexcept {
            if (empty()) {
                return 0;
            }

            size_t min = size < destination.size ? size : destination.size;
            if (min) {
                std::memcpy(destination.data, data, min * sizeof(T));
            }

            return min;
        }

        /**
         * Fills the span with the specified value.
         *
         * @param value The value to fill every element with.
         */
        inline void fill(const T& value) noexcept {
            if (empty()) {
                return;
            }

            // --> memset writes one byte at a time, so it only spells "fill with this value" for
            // a one-byte T; for a wider one it would smear the low byte across every element
            // (fill(1) on a uint32_t span giving 0x01010101, not 1). The byte-wise path stays for
            // the byte spans that are almost every use here, because it is the one the project's
            // bulk-operation convention asks for; the element-wise path is what correctness
            // requires elsewhere, and a compiler vectorizes it into the same store loop.
            if constexpr (sizeof(T) == 1) {
                std::memset(data, int(value), size);
            }
            else {
                for (size_t i = 0; i < size; ++i) {
                    data[i] = value;
                }
            }
        }

        /**
         * Clears the span by setting all elements to zero.
         */
        inline void clear() noexcept {
            if (empty()) {
                return;
            }

            std::memset(data, 0, size * sizeof(T));
        }
    };

    /**
     * Represents a read-only span of memory.
     */
    template<typename T>
    struct TReadOnlySpan {
        const T* data;
        size_t size;

        /**
         * Constructs a span with the given data pointer and size.
         *
         * @param data Pointer to the beginning of the memory span.
         * @param size Size of the memory span in bytes.
         */
        constexpr TReadOnlySpan(const T* data = nullptr, size_t size = 0) noexcept
            : data(data), size(size) {}

        /**
         * Constructs a read-only span from a regular span.
         *
         * @param other The regular span to construct from.
         */
        constexpr TReadOnlySpan(const TSpan<T>& other) noexcept
            : data(other.data), size(other.size) {}

        /**
         * Checks if the span is empty.
         *
         * @return True if the span has no data or size is zero, false otherwise.
         */
        constexpr bool empty() const noexcept {
            return data == nullptr || size == 0;
        }

        /** 
         * Checks if the span is not empty.
         *
         * @return True if the span has data and size is non-zero, false otherwise.
         */
        constexpr operator bool() const noexcept {
            return !empty();
        }

        /**
         * Checks if the span is empty.
         *
         * @return True if the span has no data or size is zero, false otherwise.
         */
        constexpr bool operator!() const noexcept {
            return empty();
        }

        /**
         * Checks if two spans are equal.
         *
         * @param other The other span to compare with.
         * @return True if both spans have the same data pointer and size, false otherwise.
         */
        constexpr bool operator==(const TReadOnlySpan<T>& other) const noexcept {
            if (empty()) {
                return other.empty();
            }

            return data == other.data && size == other.size;
        }

        /**
         * Checks if two spans are not equal.
         *
         * @param other The other span to compare with.
         * @return True if the spans have different data pointers or sizes, false otherwise.
         */
        constexpr bool operator!=(const TReadOnlySpan<T>& other) const noexcept {
            return !(*this == other);
        }

        /**
         * Returns a pointer to the beginning of the memory span.
         *
         * @return Pointer to the beginning of the memory span.
         */
        constexpr const T* begin() const noexcept {
            return data;
        }

        /**
         * Returns a pointer to the end of the memory span.
         *
         * @return Pointer to the end of the memory span.
         */
        constexpr const T* end() const noexcept {
            return data + size;
        }

        /**
         * Accesses the element at the specified index (const version).
         *
         * @param index The index of the element to access.
         * @return Const reference to the element at the specified index.
         */
        constexpr const T& operator[](size_t index) const noexcept {
            return data[index];
        }

        /**
         * Returns a subspan of the memory span starting at the given offset with the specified length.
         *
         * @param offset Offset from the beginning of the memory span.
         * @param length Length of the subspan.
         * @return A new TSpan representing the subspan.
         */
        constexpr TReadOnlySpan<T> slice(size_t offset, size_t length) const noexcept {
            if (offset >= size) {
                return TReadOnlySpan(nullptr, 0);
            }

            if (offset + length > size) {
                length = size - offset;
            }

            return TReadOnlySpan(data + offset, length);
        }

        /**
         * Returns a subspan of the memory span starting at the given offset.
         *
         * @param offset Offset from the beginning of the memory span.
         * @return A new TSpan representing the subspan.
         */
        constexpr TReadOnlySpan<T> slice(size_t offset) const noexcept {
            if (offset >= size) {
                return TReadOnlySpan(nullptr, 0);
            }
            
            return slice(offset, size - offset);
        }

        /**
         * Reinterprets the memory span as a span of a different type.
         *
         * @tparam U The type to reinterpret the memory span as.
         * @return A new TSpan representing the reinterpreted memory span.
         */
        template<typename U>
        constexpr TReadOnlySpan<U> reinterpret() const noexcept {
            return TReadOnlySpan<U>(reinterpret_cast<U*>(data), (size * sizeof(T)) / sizeof(U));
        }

        /**
         * Compares this span with another span.
         *
         * @param other The other span to compare with.
         * @return A negative value if this span is less than the other span, zero if they are equal, and a positive value if this span is greater than the other span.
         */
        inline int32_t compare(const TReadOnlySpan<T>& other) const {
            if (empty()) {
                return other.empty() ? 0 : -1;
            }

            if (other.empty()) {
                return 1;
            }

            size_t min = size < other.size ? size : other.size;
            // --> `min` counts elements, so the byte count memcmp wants is min * sizeof(T). This
            // read it as a byte count until a wiki example put a TReadOnlySpan<wchar_t> through
            // it: the two spans' first half compared equal and the call reported a match. The
            // mutable overload above has always had the multiply, so the two disagreed.
            int cmp = std::memcmp(data, other.data, min * sizeof(T));

            if (cmp != 0) {
                return cmp;
            }

            return static_cast<int32_t>(size) - static_cast<int32_t>(other.size);
        }

        /**
         * Checks if this span is sequentially equal to another span.
         *
         * @param other The other span to compare with.
         * @return True if the spans are sequentially equal, false otherwise.
         */
        inline bool sequencialEqual(const TReadOnlySpan<T>& other) const noexcept {
            return compare(other) == 0;
        }
        
        /**
         * Copies the contents of this span to the destination span.
         *
         * @param destination The destination span to copy to.
         * @return The number of elements copied.
         */
        inline size_t copyTo(TSpan<T>& destination) const noexcept {
            if (empty()) {
                return 0;
            }

            size_t min = size < destination.size ? size : destination.size;
            if (min) {
                std::memcpy(destination.data, data, min * sizeof(T));
            }

            return min;
        }
    };

    /* Byte span. Represents a span of bytes (uint8_t). */
    using SByteSpan = TSpan<uint8_t>;

    /* Read-only byte span. Represents a read-only span of bytes (uint8_t). */
    using SReadOnlyByteSpan = TReadOnlySpan<uint8_t>;

} // namespace certpp

#endif
