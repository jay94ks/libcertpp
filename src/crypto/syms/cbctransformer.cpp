#include "cbctransformer.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    CbcTransformer::CbcTransformer(
        const ISymmetricContextPtr& ctx, bool encrypting, size_t blockBytes,
        SReadOnlyByteSpan iv, ESymPaddings padding, BlockFn blockFn,
        BulkBlockFn bulkBlockFn
    )
        : ISymmetricTransformer(ctx), _encrypting(encrypting), _blockBytes(blockBytes),
          _padding(padding), _blockFn(std::move(blockFn)),
          _bulkBlockFn(std::move(bulkBlockFn))
    {
        blockSize(blockBytes);

        _chain.resize(blockBytes);
        _scratch.resize(blockBytes);

        // --> _chain is zeroed first so any bytes beyond a short iv (shouldn't happen given the
        // callers' blockBytes-length checks, but kept as a safety net) stay deterministically 0
        // rather than whatever CBuffer::resize() left behind -- TArray<uint8_t>::resize() used to
        // guarantee this implicitly by value-initializing new elements.
        uint8_t* chainPtr = _chain.toPtr();
        std::memset(chainPtr, 0, blockBytes);

        size_t copied = iv.size < blockBytes ? iv.size : blockBytes;
        if (copied > 0) {
            std::memcpy(chainPtr, iv.data, copied);
        }
    }

    ERetCode CbcTransformer::processBuffered(bool final, SByteSpan& output) {
        size_t outWritten = 0;
        size_t consumed = 0;
        ERetCode result = ERET_OK;

        // --> _scratch/_chain are sized once in the constructor and never resized, so their raw
        // pointers stay valid for this whole call; _buffer is only reassigned at the very end,
        // past every use below. The per-byte loops that remain are XOR combines, which neither
        // memcpy nor memset can express -- but they still go through a raw pointer rather than
        // CBuffer::operator[], per docs/coding-conventions.md's "Buffer handling".
        uint8_t* scratchPtr = _scratch.toPtr();
        uint8_t* chainPtr = _chain.toPtr();

        if (_encrypting) {
            // --> A bulk run of whole blocks, where the cipher offers one. Everything about
            // the shape stays the same: it still reads from _buffer, it is still bounded by
            // the output space left, it still leaves _chain holding the last ciphertext
            // block, and the per-block loop below still handles whatever it did not take.
            // The bulk function's advantage is internal -- it keeps the chaining value in a
            // register rather than writing it out and reading it back -- so from here the
            // two paths are interchangeable and the choice is invisible to a caller.
            if (_bulkBlockFn) {
                size_t wholeBlocks = (_buffer.size() - consumed) / _blockBytes;
                // Leave the output-space rule intact: a bulk run may not write more than the
                // caller's buffer can hold, and may not run past the end of the input.
                if (wholeBlocks > 0) {
                    const size_t fitting = (output.size - outWritten) / _blockBytes;
                    if (fitting < wholeBlocks) {
                        // Not enough room for every whole block. The per-block loop below
                        // handles this by leaving the rest in _buffer for a later transform(),
                        // which is the contract that keeps a partial output buffer usable
                        // across calls -- so the bulk path must not write more than fits,
                        // whether or not this is the final call. ERET_NOSPC is preserved by
                        // the per-block loop's own check when final leaves nothing to emit.
                        wholeBlocks = fitting;
                    }

                    if (wholeBlocks > 0) {
                        _bulkBlockFn(_buffer.toPtr() + consumed,
                                     output.data + outWritten,
                                     wholeBlocks, chainPtr);
                        outWritten += wholeBlocks * _blockBytes;
                        consumed += wholeBlocks * _blockBytes;
                    }
                }
            }

            while (_buffer.size() - consumed >= _blockBytes) {
                if (output.size - outWritten < _blockBytes) {
                    if (!final) {
                        break; // not enough room yet -- defer to a later call
                    }
                    result = ERET_NOSPC;
                    break;
                }

                const uint8_t* inBlock = _buffer.toPtr() + consumed;
                for (size_t i = 0; i < _blockBytes; ++i) {
                    scratchPtr[i] = uint8_t(inBlock[i] ^ chainPtr[i]);
                }

                uint8_t* blockOut = output.data + outWritten;
                _blockFn(scratchPtr, blockOut);
                std::memcpy(chainPtr, blockOut, _blockBytes);

                outWritten += _blockBytes;
                consumed += _blockBytes;
            }

            if (result == ERET_OK && final && _padding == ESYMPAD_NONE) {
                // --> Unpadded CBC has no final block of its own: the loop above already emitted
                // every whole block, so anything left is a partial block the mode cannot encode.
                if (_buffer.size() != consumed) {
                    result = ERET_BADREQ;
                }
            } else if (result == ERET_OK && final) {
                size_t leftover = _buffer.size() - consumed;
                size_t padByte = _blockBytes - leftover; // 1..blockBytes (always pads, per PKCS#7)

                if (output.size - outWritten < _blockBytes) {
                    result = ERET_NOSPC;
                } else {
                    const uint8_t* inBlock = _buffer.toPtr() + consumed;
                    for (size_t i = 0; i < leftover; ++i) {
                        scratchPtr[i] = uint8_t(inBlock[i] ^ chainPtr[i]);
                    }
                    for (size_t i = leftover; i < _blockBytes; ++i) {
                        scratchPtr[i] = uint8_t(padByte ^ chainPtr[i]);
                    }

                    uint8_t* blockOut = output.data + outWritten;
                    _blockFn(scratchPtr, blockOut);
                    std::memcpy(chainPtr, blockOut, _blockBytes);

                    outWritten += _blockBytes;
                    consumed += leftover;
                }
            }
        } else {
            // --> Under PKCS#7, always holds back the most recently completed block, whether or
            // not this call is final -- a final call still needs it held back so the code below
            // can strip its padding instead of emitting it as an ordinary block. Unpadded, there
            // is nothing to strip and nothing special about the last block, so every whole block
            // is emitted as it completes.
            size_t fullBlocks = (_buffer.size() - consumed) / _blockBytes;
            size_t blocksToEmit = fullBlocks;
            if (_padding == ESYMPAD_PKCS7 && fullBlocks > 0) {
                blocksToEmit = fullBlocks - 1;
            }

            for (size_t b = 0; b < blocksToEmit; ++b) {
                if (output.size - outWritten < _blockBytes) {
                    if (!final) {
                        break;
                    }
                    result = ERET_NOSPC;
                    break;
                }

                const uint8_t* ctBlock = _buffer.toPtr() + consumed;
                uint8_t* blockOut = output.data + outWritten;

                _blockFn(ctBlock, blockOut);
                for (size_t i = 0; i < _blockBytes; ++i) {
                    blockOut[i] ^= chainPtr[i];
                }
                std::memcpy(chainPtr, ctBlock, _blockBytes);

                outWritten += _blockBytes;
                consumed += _blockBytes;
            }

            if (result == ERET_OK && final && _padding == ESYMPAD_NONE) {
                // --> As when encrypting unpadded: every whole block is already out, so a
                // leftover is a truncated ciphertext rather than a final block to unpad.
                if (_buffer.size() != consumed) {
                    result = ERET_BADREQ;
                }
            } else if (result == ERET_OK && final) {
                size_t leftover = _buffer.size() - consumed;

                if (leftover != _blockBytes) {
                    // a validly PKCS#7-padded ciphertext is never empty and always ends on a
                    // whole block -- anything else is a truncated/corrupt ciphertext.
                    result = ERET_BADREQ;
                } else {
                    const uint8_t* ctBlock = _buffer.toPtr() + consumed;
                    _blockFn(ctBlock, scratchPtr);
                    for (size_t i = 0; i < _blockBytes; ++i) {
                        scratchPtr[i] ^= chainPtr[i];
                    }

                    // --> Constant-time PKCS#7 validation: every byte of the block is compared
                    // unconditionally (no early exit, no branch on the pad value or on whether a
                    // byte matches), so the loop's running time and instruction trace don't
                    // depend on *where* (or whether) padding is invalid. A data-dependent
                    // early-out here would be a textbook CBC padding oracle (Vaudenay's attack,
                    // as later exploited by POODLE/Lucky13) for any caller that lets an attacker
                    // observe many decrypt attempts against adaptively chosen ciphertexts.
                    uint8_t pad = scratchPtr[_blockBytes - 1];

                    // good == 0xFF iff 1 <= pad <= _blockBytes, computed without branching on
                    // pad's value: (pad - 1), as an unsigned quantity, wraps to a huge value
                    // when pad == 0, which always compares >= _blockBytes.
                    uint8_t good = uint8_t(-(uint8_t((unsigned(pad) - 1) < _blockBytes)));

                    uint8_t mismatch = 0;
                    for (size_t i = 0; i < _blockBytes; ++i) {
                        // inRegion == 0xFF iff byte i falls within the last `pad` bytes of the
                        // block -- an arithmetic comparison over public loop/field values
                        // (i, _blockBytes), not over the secret plaintext bytes themselves.
                        uint8_t inRegion = uint8_t(-(uint8_t(i + pad >= _blockBytes)));
                        mismatch = uint8_t(mismatch | ((scratchPtr[i] ^ pad) & inRegion));
                    }

                    bool padOk = good != 0 && mismatch == 0;
                    if (!padOk) {
                        result = ERET_BADREQ;
                    } else {
                        size_t plainLen = _blockBytes - pad;
                        if (output.size - outWritten < plainLen) {
                            result = ERET_NOSPC;
                        } else {
                            if (plainLen > 0) {
                                std::memcpy(output.data + outWritten, scratchPtr, plainLen);
                            }
                            outWritten += plainLen;
                            consumed += _blockBytes;
                        }
                    }
                }
            }
        }

        if (consumed > 0) {
            size_t remainderSize = _buffer.size() - consumed;
            CBuffer remainder(remainderSize);
            if (remainderSize > 0) {
                std::memcpy(remainder.toPtr(), _buffer.toPtr() + consumed, remainderSize);
            }
            _buffer = std::move(remainder);
        }

        output = SByteSpan(output.data, outWritten);
        return result;
    }

    ERetCode CbcTransformer::transform(const SReadOnlyByteSpan& input, SByteSpan& output) {
        size_t old = _buffer.size();
        _buffer.resize(old + input.size);

        if (input.size > 0) {
            std::memcpy(_buffer.toPtr() + old, input.data, input.size);
        }

        return processBuffered(false, output);
    }

    ERetCode CbcTransformer::transformFinal(SByteSpan& output) {
        return processBuffered(true, output);
    }

} // namespace crypto
} // namespace certpp
