#ifndef __INCLUDE_CERTPP_NET_SOCKSTREAM_HPP__
#define __INCLUDE_CERTPP_NET_SOCKSTREAM_HPP__

#include <certpp/common.hpp>
#include <certpp/net/socket.hpp>
#include <certpp/io/stream.hpp>

namespace certpp {
namespace net {

    /**
     * A non-seekable byte stream that buffers data over a CSocket.
     */
    class CERTPP_API CSocketStream : public IStream {
    private:
        CSocketPtr _socket;

        uint8_t _bufRx[4096];
        uint8_t _bufTx[4096];

        size_t _lenRx;
        size_t _lenTx;
        STimeSpan _pollTimeout;

        ERetCode waitFor(EPollHow how);

    public:
        /**
         * Wraps a shared socket. Closing the stream also closes the underlying socket.
         * @param socket The socket to use for stream I/O; may be empty.
         */
        CSocketStream(const CSocketPtr& socket)
            : _socket(socket), _lenRx(0), _lenTx(0), _pollTimeout(-1) { }

        /**
         * Sets how long read/write/flush wait for the socket after it reports ERET_AGAIN
         * (would-block, interrupted). The default is indefinite, which suits blocking
         * sockets; use zero on a nonblocking socket to return instead of waiting.
         * @param timeout The wait; a negative span waits indefinitely.
         */
        inline void pollTimeout(const STimeSpan& timeout) {
            _pollTimeout = timeout;
        }

        /**
         * Gets the wait applied after ERET_AGAIN.
         * @return The current poll timeout.
         */
        inline STimeSpan pollTimeout() const {
            return _pollTimeout;
        }

        /**
         * Retrieves the underlying CSocket shared pointer.
         * @return The shared pointer to the CSocket instance.
         */
        inline CSocketPtr socket() const {
            return _socket;
        }

        /**
         * Gets the capabilities of the stream.
         * @return The capabilities of the stream as a bitmask of EStreamCapability values.
         */
        virtual uint32_t capabilities() const override {
            return _socket && *_socket ? ESTREAM_READ | ESTREAM_WRITE : 0;
        }

        /**
         * Get the capacity of the stream.
         * @return The capacity of the stream in bytes.
         */
        virtual SizeType capacity() const override {
            return capabilities() ? MAX_SIZE : 0;
        }

        /**
         * Get the length of the stream.
         * @return The length of the stream in bytes.
         */
        virtual SizeType length() const override {
            return capabilities() ? MAX_SIZE : 0;
        }

        /**
         * Get the current position within the stream.
         * @return The current position in bytes from the beginning of the stream.
         */
        virtual SizeType position() const override {
            return 0;
        }

        /**
         * Trim any excess capacity from the stream.
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode trimExcess() override {
            return ERET_NOTSUP;
        }

        /**
         * Try to set the length of the stream.
         * @param newLen The new length of the stream in bytes.
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode length(SizeType newLen) override {
            return ERET_NOTSUP;
        }

        /**
         * Seek to a new position within the stream.
         * @param offset The offset to seek to, relative to the position specified by mode.
         * @param mode The seek mode (ESEEK_SET, ESEEK_CUR, ESEEK_END).
         * @return ERetCode indicating success or failure.
         */
        virtual ERetCode seek(OffsetType offset, ESeekMode mode) override {
            return ERET_NOTSUP;
        }

        /**
         * Read data from the stream into the provided buffer.
         * @param buf The buffer to read data into.
         * @param len The maximum number of bytes to read.
         * @return The number of bytes received. ERET_AGAIN is waited out with poll() (see
         *         pollTimeout()); any other error, or EOF, ends the read short.
         */
        virtual size_t read(uint8_t* buf, size_t len) override;

        /**
         * Write data to the stream from the provided buffer.
         * @param buf The buffer containing data to write.
         * @param len The maximum number of bytes to write.
         * @return The number of bytes accepted, including bytes retained in the transmit buffer.
         */
        virtual size_t write(const uint8_t* buf, size_t len) override;

        /**
         * Flush any buffered data to the underlying socket.
         * @return ERET_OK if all buffered bytes were sent; ERET_AGAIN is waited out with poll(),
         *         and a poll timeout or any other socket error stops the flush with that code.
         */
        virtual ERetCode flush() override;

        /**
         * Close the stream.
         * @return ERET_OK if the socket was closed, or an error if flushing/closing failed.
         */
        virtual ERetCode close() override;
    };

} // namespace net
} // namespace certpp

#endif