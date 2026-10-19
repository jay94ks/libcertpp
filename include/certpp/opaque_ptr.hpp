#ifndef __INCLUDE_CERTPP_OPAQUE_PTR_HPP__
#define __INCLUDE_CERTPP_OPAQUE_PTR_HPP__

#include <certpp/common.hpp>

namespace certpp {
    /**
     * Represents an opaque pointer to an object.
     * Provides a type-safe wrapper around an opaque pointer, allowing comparisons and conversions to raw pointers.
     */
    template<typename T = void>
    struct SOpaquePtr {
        using SelfType = SOpaquePtr<T>;
        uintptr_t p;    // --> Opaque pointer to the object.

        SOpaquePtr() : p(0) {}
        SOpaquePtr(uintptr_t ptr) : p(ptr) {}

        /**
         * Constructs an opaque pointer from a raw pointer of type T*.
         *
         * @param ptr The raw pointer to wrap.
         */
        explicit SOpaquePtr(const T* ptr) : p(uintptr_t(ptr)) {}

        /**
         * Copy constructor and copy assignment operator.
         * These are defaulted to allow copying of opaque pointers.
         */
        SOpaquePtr(const SelfType& other) = default;
        SelfType& operator=(const SelfType& other) = default;

        /**
         * Assigns a raw pointer to the opaque pointer.
         *
         * @param ptr The raw pointer to assign.
         * @return Reference to the current opaque pointer.
         */
        inline SelfType& operator=(uintptr_t ptr) {
            p = ptr;
            return *this;
        }

        /**
         * Assigns a nullptr to the opaque pointer, effectively clearing it.
         *
         * @param ptr The nullptr to assign.
         * @return Reference to the current opaque pointer.
         */
        inline SelfType& operator=(nullptr_t) {
            p = 0;
            return *this;
        }

        /**
         * Resets the opaque pointer to an empty state.
         */
        inline void reset() {
            p = 0;
        }

        /**
         * Checks if the opaque pointer is empty (i.e., not pointing to any object).
         *
         * @return true if the pointer is empty, false otherwise.
         */
        inline bool empty() const {
            return p == 0;
        }

        /**
         * Converts the opaque pointer to an unsafe raw pointer of type T*.
         *
         * @return The raw pointer corresponding to the opaque pointer.
         */
        inline T* toUnsafe() {
            return (T*)p;
        }

        /**
         * Converts the opaque pointer to an unsafe raw pointer of type T*.
         *
         * @return The raw pointer corresponding to the opaque pointer.
         */
        inline const T* toUnsafe() const {
            return (T*)p;
        }

        /**
         * Checks if the opaque pointer is valid (i.e., pointing to an object).
         *
         * @return true if the pointer is valid, false otherwise.
         */
        inline operator bool() const {
            return bool(p);
        }

        /**
         * Checks if the opaque pointer is not valid (i.e., not pointing to any object).
         *
         * @return true if the pointer is not valid, false otherwise.
         */
        inline bool operator!() const {
            return !(p);
        }

        /**
         * Returns true if the opaque pointer is equal to the other opaque pointer, false otherwise.
         * @param other The other opaque pointer to compare with.
         * @return true if the pointers are equal, false otherwise.
         */
        inline bool operator==(const SelfType& other) const {
            return p == other.p;
        }

        /**
         * Returns true if the opaque pointer is not equal to the other opaque pointer, false otherwise.
         * @param other The other opaque pointer to compare with.
         * @return true if the pointers are not equal, false otherwise.
         */
        inline bool operator!=(const SelfType& other) const {
            return p != other.p;
        }

        /**
         * Checks if the opaque pointer is equal to the given raw pointer.
         *
         * @param ptr The raw pointer to compare with.
         * @return true if the opaque pointer is equal to the raw pointer, false otherwise.
         */
        inline bool operator==(uintptr_t ptr) const {
            return p == ptr;
        }

        /**
         * Checks if the opaque pointer is not equal to the given raw pointer.
         *
         * @param ptr The raw pointer to compare with.
         * @return true if the opaque pointer is not equal to the raw pointer, false otherwise.
         */
        inline bool operator!=(uintptr_t ptr) const {
            return p != ptr;
        }

        /**
         * Checks if the opaque pointer is equal to the given raw pointer.
         *
         * @param unsafe The raw pointer to compare with.
         * @return true if the opaque pointer is equal to the raw pointer, false otherwise.
         */
        inline bool operator==(const T* unsafe) const {
            return (T*)p == unsafe;
        }

        /**
         * Checks if the opaque pointer is not equal to the given raw pointer.
         *
         * @param unsafe The raw pointer to compare with.
         * @return true if the opaque pointer is not equal to the raw pointer, false otherwise.
         */
        inline bool operator!=(const T* unsafe) const {
            return (T*)p != unsafe;
        }
    };


} // namespace certpp

#endif