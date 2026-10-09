#include <certpp/net/sockstream.hpp>
#include <algorithm>
#include <cstring>

namespace certpp {
namespace net {

    /* Waits for socket readiness after ERET_AGAIN, riding out interruptions. */
    ERetCode CSocketStream::waitFor(EPollHow how) {
        ERetCode result;
        do {
            result = _socket->poll(how, _pollTimeout);
        } while (result == ERET_AGAIN);
        return result;
    }

    /* Reads bytes from the socket, preserving any received bytes when an error follows. */
    size_t CSocketStream::read(uint8_t* buf, size_t len) {
        if (!_socket || !buf || len == 0) {
            return 0;
        }

        size_t total = 0;
        bool stopAfterBufferedData = false;
        while (total < len) {
            if (_lenRx > 0) {
                const size_t copied = std::min(len - total, _lenRx);
                std::memcpy(buf + total, _bufRx, copied);
                
                total += copied;
                _lenRx -= copied;

                if (_lenRx > 0) {
                    std::memmove(_bufRx, _bufRx + copied, _lenRx);
                }
            }

            if (total == len || stopAfterBufferedData) {
                break;
            }

            size_t received = 0;
            const size_t request = std::min(len - total, sizeof(_bufRx));
            const ERetCode result = _socket->recv(_bufRx, request, received);
            _lenRx = received;

            if (_lenRx > 0) {
                stopAfterBufferedData = result != ERET_OK && result != ERET_AGAIN;
                continue;
            }

            if (result != ERET_AGAIN || waitFor(EPOLL_RCV) != ERET_OK) {
                break;
            }
        }

        return total;
    }

    /* Buffers bytes for transmission and reports how many the stream accepted. */
    size_t CSocketStream::write(const uint8_t* buf, size_t len) {
        if (!_socket || !buf || len == 0) {
            return 0;
        }

        size_t accepted = 0;
        while (accepted < len) {
            if (_lenTx == sizeof(_bufTx)) {
                if (flush() != ERET_OK) {
                    break;
                }
            }

            const size_t copied = std::min(len - accepted, sizeof(_bufTx) - _lenTx);
            std::memcpy(_bufTx + _lenTx, buf + accepted, copied);

            _lenTx += copied;
            accepted += copied;

            if (flush() != ERET_OK) {
                break;
            }
        }

        return accepted;
    }

    /* Sends queued bytes and retains any bytes not accepted by the socket. */
    ERetCode CSocketStream::flush() {
        if (!_socket) {
            return ERET_BADREQ;
        }

        while (_lenTx > 0) {
            size_t sent = 0;
            const ERetCode result = _socket->send(_bufTx, _lenTx, sent);

            if (sent > 0) {
                _lenTx -= sent;
                if (_lenTx > 0) {
                    std::memmove(_bufTx, _bufTx + sent, _lenTx);
                }
            }

            if (result == ERET_AGAIN) {
                const ERetCode waited = waitFor(EPOLL_SND);
                if (waited != ERET_OK) {
                    return waited;
                }

                continue;
            }

            if (result != ERET_OK) {
                return result;
            }

            if (sent == 0) {
                return ERET_AGAIN;
            }
        }

        return ERET_OK;
    }

    /* Flushes pending data before closing the socket owned by this stream. */
    ERetCode CSocketStream::close() {
        if (!_socket) {
            return ERET_BADREQ;
        }

        const ERetCode flushResult = flush();
        if (flushResult != ERET_OK) {
            return flushResult;
        }

        const ERetCode closeResult = _socket->close();
        if (closeResult == ERET_OK || closeResult == ERET_ALREADY) {
            _socket.reset();
        }

        return closeResult;
    }

} // namespace net
} // namespace certpp
