#ifndef __INCLUDE_CERTPP_IO_STREAM_HPP__
#define __INCLUDE_CERTPP_IO_STREAM_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {

    /**
     * Seek mode for input/output streams.
     */
    enum ESeekMode {
        ESEEK_SET = 0,
        ESEEK_CUR,
        ESEEK_END
    };

    /**
     * Stream capabilities.
     */
    enum EStreamCapability {
        ESTREAM_READ = 0x01,
        ESTREAM_WRITE = 0x02,
        ESTREAM_SEEK = 0x04,
    };

    // --> Forward declaration of the IStream interface.
    class IStream;

    /* Shared pointer type for the IStream interface. */
    using IStreamPtr = std::shared_ptr<IStream>;

    /**
     * Interface for input streams.
     */
    class CERTPP_API IStream {
    public:
        virtual ~IStream() = default;

    public:
        /* Type aliases for stream size and offset. */
        using SizeType = uint64_t;
        using OffsetType = int64_t;

        /**
         * The maximum size of the stream.
         */
        static constexpr SizeType MAX_SIZE = static_cast<SizeType>(-1);
        
    public:
        /**
         * Create a memory-based stream with the specified initial capacity.
         * @param initialCap The initial capacity of the memory stream in bytes.
         * @return A shared pointer to the created memory stream.
         */
        static IStreamPtr createMemory(SizeType initialCap = 0);

        /**
         * Create a memory-based stream using the provided buffer.
         * @param buf The buffer to initialize the memory stream with.
         * @return A shared pointer to the created memory stream.
         */
        static IStreamPtr createMemory(const SReadOnlyByteSpan& buf);

    public:
        /**
         * Get the capabilities of the stream.
         * @return The capabilities of the stream as a bitmask of EStreamCapability values.
         */
        virtual uint32_t capabilities() const = 0;

        /**
         * Get the capacity of the stream.
         * @return The capacity of the stream in bytes.
         */
        virtual SizeType capacity() const = 0;

        /**
         * Get the length of the stream.
         * @return The length of the stream in bytes.
         */
        virtual SizeType length() const = 0;

        /**
         * Get the current position within the stream.
         * @return The current position in bytes from the beginning of the stream.
         */
        virtual SizeType position() const = 0;

        /**
         * Trim any excess capacity from the stream.
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode trimExcess() {
            return ERET_NOTIMPL;
        }

        /**
         * Try to set the length of the stream.
         * @param newLen The new length of the stream in bytes.
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode length(SizeType newLen) {
            return ERET_NOTIMPL;
        }

        /**
         * Try to set the current position within the stream.
         * @param newPos The new position in bytes from the beginning of the stream.
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode position(SizeType newPos) {
            return seek(newPos, ESEEK_SET);
        }

        /**
         * Seek to a new position within the stream.
         * @param offset The offset to seek to, relative to the position specified by mode.
         * @param mode The seek mode (ESEEK_SET, ESEEK_CUR, ESEEK_END).
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode seek(OffsetType offset, ESeekMode mode) = 0;

        /**
         * Read data from the stream into the provided buffer.
         * @param buf The buffer to read data into.
         * @param len The maximum number of bytes to read.
         * @return The number of bytes actually read.
         */
        virtual size_t read(uint8_t* buf, size_t len) = 0;

        /**
         * Read data from the stream into the provided SByteSpan buffer.
         * @param buf The SByteSpan buffer to read data into.
         * @return The number of bytes actually read.
         */
        virtual size_t read(SByteSpan& buf) {
            return read(buf.data, buf.size);
        }

        /**
         * Write data to the stream from the provided buffer.
         * @param buf The buffer containing data to write.
         * @param len The maximum number of bytes to write.
         * @return The number of bytes actually written.
         */
        virtual size_t write(const uint8_t* buf, size_t len) = 0;

        /**
         * Write data to the stream from the provided SByteSpan buffer.
         * @param buf The SByteSpan buffer containing data to write.
         * @return The number of bytes actually written.
         */
        virtual size_t write(const SByteSpan& buf) {
            return write(buf.data, buf.size);
        }

        /**
         * Flush any buffered data to the underlying storage.
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode flush() {
            return ERET_NOTIMPL;
        }

        /**
         * Close the stream.
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode close() = 0;
        
    };
}

#endif
