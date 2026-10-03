#ifndef __INCLUDE_CERTPP_IO_OCTET_HPP__
#define __INCLUDE_CERTPP_IO_OCTET_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <utility>

namespace certpp {

    /**
     * Represents octets (8-bit byte) in the certpp library.
     * This is not designed to build dynamically resizable arrays of octets.
     * Commonly, this class is used to represent fixed-size octets.
     */
    class CERTPP_API COctet {
    private:
        uint8_t* _data;
        size_t _size;

    public:
        /**
         * Default constructor.
         * Initializes an empty COctet instance.
         */
        COctet() : _data(nullptr), _size(0) {}

        /**
         * Constructs a COctet instance with the given data.
         * @param data Pointer to the data to store.
         * @param size Size of the data to store.
         */
        COctet(const uint8_t* data, size_t size) : _data(nullptr), _size(0) {
            store(data, size);
        }

        /**
         * Constructs a COctet instance from a read-only byte span.
         * @param span The read-only byte span to store.
         */
        COctet(const SReadOnlyByteSpan& span) : _data(nullptr), _size(0) {
            store(span.data, span.size);
        }

        /**
         * Copy constructor.
         * @param other The COctet instance to copy from.
         */
        COctet(const COctet& other) : _data(nullptr), _size(0) {
            store(other._data, other._size);
        }

        /**
         * Move constructor.
         * @param other The COctet instance to move from.
         */
        COctet(COctet&& other) noexcept : _data(other._data), _size(other._size) {
            other._data = nullptr;
            other._size = 0;
        }

        /**
         * Destructor.
         * Releases the allocated memory for the octet.
         */
        ~COctet() { clear(); }

    public:
        /**
         * Copy assignment operator.
         * @param other The COctet instance to copy from.
         * @return Reference to this instance.
         */
        inline COctet& operator=(const COctet& other) {
            if (this != &other) {
                // --> store() no-ops (returning false) on a null/zero-size source, so an assignment
                // from an empty other must go through clear() instead, or this would keep stale data.
                if (other.empty()) {
                    clear();
                } else {
                    store(other._data, other._size);
                }
            }

            return *this;
        }

        /**
         * Move assignment operator.
         * @param other The COctet instance to move from.
         * @return Reference to this instance.
         */
        inline COctet& operator=(COctet&& other) noexcept {
            if (this != &other) {
                std::swap(_data, other._data);
                std::swap(_size, other._size);
            }

            return *this;
        }
        
    public:
        /**
         * Checks if the octet is not empty.
         * @return True if the octet is not empty, false otherwise.
         */
        inline operator bool() const {
            return !empty();
        }

        /**
         * Checks if the octet is empty using the logical NOT operator.
         * @return True if the octet is empty, false otherwise.
         */
        inline bool operator!() const {
            return empty();
        }

        /**
         * Checks if the octet is empty.
         * @return True if the octet is empty, false otherwise.
         */
        inline bool empty() const {
            return _size == 0;
        }

        /**
         * Retrieves the size of the octet.
         * @return The size of the octet.
         */
        inline size_t size() const {
            return _size;
        }

        /**
         * Retrieves a pointer to the data stored in the octet.
         * @return Pointer to the data.
         */
        inline const uint8_t* toPtr() const {
            return _data;
        }

        /**
         * Retrieves a read-only byte span representing the octet's data.
         * @return The read-only byte span.
         */
        inline SReadOnlyByteSpan toSpan() const {
            return SReadOnlyByteSpan{_data, _size};
        }

        /**
         * Stores the given data into the octet.
         * @param data Pointer to the data to store.
         * @param size Size of the data to store.
         * @return True if the data was successfully stored, false otherwise.
         */
        bool store(const uint8_t* data, size_t size);

        /**
         * Stores the given read-only byte span into the octet.
         * @param span The read-only byte span to store.
         * @return True if the data was successfully stored, false otherwise.
         */
        inline bool store(const SReadOnlyByteSpan& span) {
            return store(span.data, span.size);
        }

        /**
         * Clears the octet, releasing any allocated memory and resetting its size to zero.
         */
        void clear();

        /**
         * Zeroizes the stored bytes, then clears as clear() does.
         *
         * This exists because the bytes a COctet owns are reachable only through the read-only
         * toPtr()/toSpan(), so a caller holding secret material in one -- a PKCS#9
         * `challengePassword`, a decoded private key blob -- cannot wipe it with
         * CSecure::zero() without a const_cast. Opening a mutable pointer instead would let
         * anything rewrite an owned buffer piecemeal, which is the one thing store()'s
         * replace-the-whole-content design is meant to prevent; naming the operation keeps the
         * capability to the single use that needs it.
         *
         * The limitation is the same one CBigNum::secureClear() documents, and it is worth
         * stating rather than implying: this reaches the bytes *this* instance owns, at the
         * moment it is called. It does not reach a copy some earlier assignment made, nor the
         * block store() frees when it replaces content with a different size, nor whatever a
         * caller's own buffer still holds. It shortens the window a secret stays in freed
         * memory; it does not close it.
         */
        void secureClear();
    };

} // namespace certpp

#endif
