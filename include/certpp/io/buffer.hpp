#ifndef __INCLUDE_CERTPP_IO_BUFFER_HPP__
#define __INCLUDE_CERTPP_IO_BUFFER_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
    /**
     * Represents a buffer for storing binary data.
     * This is designed to build dynamically resizable buffers.
     * Commonly, this class is used for managing dynamic binary data in memory.
     */
    class CERTPP_API CBuffer {
    private:
        uint8_t* _data;
        size_t _size;

    public:
        /**
         * Default constructor initializes an empty buffer.
         */
        CBuffer() : _data(nullptr), _size(0) { }

        /**
         * Constructs a buffer and stores the given data.
         * @param data A pointer to the data to be stored.
         * @param size The size of the data to be stored.
         */
        CBuffer(const uint8_t* data, size_t size) : _data(nullptr), _size(0) {
            store(data, size);
        }

        /**
         * Constructs a buffer with the specified size.
         * @param size The size of the buffer to be created.
         */
        CBuffer(size_t size) : _data(nullptr), _size(0) {
            resize(size);
        }

        /**
         * Copy constructor creates a buffer by copying the data from another buffer.
         * @param other The buffer to be copied.
         */
        CBuffer(const CBuffer& other) : _data(nullptr), _size(0) {
            store(other._data, other._size);
        }

        /**
         * Move constructor transfers ownership of the data from another buffer.
         * @param other The buffer to be moved.
         */
        CBuffer(CBuffer&& other) noexcept : _data(other._data), _size(other._size) {
            other._data = nullptr;
            other._size = 0;
        }

        /**
         * Destructor releases the allocated memory.
         */
        ~CBuffer() {
            clear();
        }

    public:
        /**
         * Copy assignment operator.
         * @param other The buffer to be copied.
         * @return A reference to this buffer.
         */
        inline CBuffer& operator=(const CBuffer& other) {
            if (this != &other) {
                store(other._data, other._size);
            }

            return *this;
        }

        /**
         * Move assignment operator.
         * @param other The buffer to be moved.
         * @return A reference to this buffer.
         */
        inline CBuffer& operator=(CBuffer&& other) noexcept {
            if (this != &other) {
                swap(_data, other._data);
                swap(_size, other._size);
            }

            return *this;
        }
    
    public:
        /**
         * Checks if the buffer is not empty.
         * @return True if the buffer is not empty, false otherwise.
         */
        inline operator bool() const {
            return !empty();
        }

        /**
         * Checks if the buffer is empty using the logical NOT operator.
         * @return True if the buffer is empty, false otherwise.
         */
        inline bool operator!() const {
            return empty();
        }

        /**
         * Checks if the buffer is empty.
         * @return True if the buffer is empty, false otherwise.
         */
        inline bool empty() const {
            return _size == 0;
        }

        /**
         * Retrieves the size of the buffer.
         * @return The size of the buffer.
         */
        inline size_t size() const {
            return _size;
        }

        /**
         * Clears the buffer by resizing it to zero.
         */
        inline void clear() {
            resize(0);
        }

        /**
         * Resizes the buffer to the specified size.
         * @param size The new size of the buffer.
         * @return True if the buffer was successfully resized, false otherwise.
         */
        bool resize(size_t size);

        /**
         * Retrieves a pointer to the buffer's data.
         * @return A pointer to the buffer's data, or nullptr if the buffer is empty.
         */
        inline uint8_t* toPtr() const {
            return _data;
        }

        /**
         * Retrieves a span representing the buffer's data.
         * @return A span representing the buffer's data.
         */
        inline SByteSpan toSpan() const {
            return SByteSpan(_data, _size);
        }

        /**
         * Provides access to the buffer's data at the specified index.
         * @param index The index of the element to access.
         * @return A reference to the element at the specified index.
         */
        inline uint8_t& operator[](size_t index) {
            return _data[index];
        }

        /**
         * Provides const access to the buffer's data at the specified index.
         * @param index The index of the element to access.
         * @return A const reference to the element at the specified index.
         */
        inline const uint8_t& operator[](size_t index) const {
            return _data[index];
        }

        /**
         * Stores the given data into the buffer.
         * @param data A pointer to the data to be stored.
         * @param size The size of the data to be stored.
         * @return True if the data was successfully stored, false otherwise.
         */
        bool store(const uint8_t* data, size_t size);
        
        /**
         * Fills the buffer with the specified value.
         * @param value The value to fill the buffer with.
         * @return True if the buffer was successfully filled, false otherwise.
         */
        inline bool fill(uint8_t value = 0) {
            if (!_data || _size == 0) {
                return false;
            }

            std::memset(_data, value, _size);
            return true;
        }
    };
}

#endif
