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
         * This operation reaches only this instance's current allocation. It cannot erase
         * earlier copies or caller-owned source buffers.
         */
        void secureClear();
    };

    /**
     * Represents fixed-size octets allocated through CSecure.
     * The default build stores them in locked, page-backed memory and wipes the owned allocation
     * before release. CERTPP_DISABLE_SECURE_MEM selects ordinary heap behavior.
     */
    class CERTPP_API CSecureOctet {
    private:
        uint8_t* _data;
        size_t _size;

    public:
        /**
         * Default constructor.
         * Initializes an empty CSecureOctet instance.
         */
        CSecureOctet() : _data(nullptr), _size(0) {}

        /**
         * Constructs a CSecureOctet instance with the given data.
         * @param data Pointer to the data to store.
         * @param size Size of the data to store.
         */
        CSecureOctet(const uint8_t* data, size_t size) : _data(nullptr), _size(0) {
            store(data, size);
        }

        /**
         * Constructs a CSecureOctet instance from a read-only byte span.
         * @param span The read-only byte span to store.
         */
        CSecureOctet(const SReadOnlyByteSpan& span) : _data(nullptr), _size(0) {
            store(span.data, span.size);
        }

        /**
         * Copy constructor.
         * @param other The CSecureOctet instance to copy from.
         */
        CSecureOctet(const CSecureOctet& other) : _data(nullptr), _size(0) {
            store(other._data, other._size);
        }

        /**
         * Move constructor.
         * @param other The CSecureOctet instance to move from.
         */
        CSecureOctet(CSecureOctet&& other) noexcept : _data(other._data), _size(other._size) {
            other._data = nullptr;
            other._size = 0;
        }

        /**
         * Destructor.
         * Releases the allocated memory for the octet.
         */
        ~CSecureOctet() { clear(); }

    public:
        /**
         * Copy assignment operator.
         * @param other The CSecureOctet instance to copy from.
         * @return Reference to this instance.
         */
        inline CSecureOctet& operator=(const CSecureOctet& other) {
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
         * @param other The CSecureOctet instance to move from.
         * @return Reference to this instance.
         */
        inline CSecureOctet& operator=(CSecureOctet&& other) noexcept {
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
         * Stores the data from another secure octet into this octet.
         * @param other The secure octet to copy data from.
         * @return True if the data was successfully stored, false otherwise.
         */
        inline bool storeFrom(const CSecureOctet& other) {
            return store(other.toPtr(), other.size());
        }

        /**
         * Clears the octet, releasing any allocated memory and resetting its size to zero.
         */
        void clear();
    };

} // namespace certpp

#endif
