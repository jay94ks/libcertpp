Drives a reader over bytes that arrive a chunk at a time. The point of the enum is the one distinction a bool cannot carry: EDEC_NEED_MORE means append more input and ask again, and every other non-OK status means this input will never parse however much is appended.

```cpp
// given: IStreamPtr source, CBuffer& sofar, size_t& filled
CTag tag;
SReadOnlyByteSpan content;
size_t bytesRead = 0;

while (true) {
    const EDecoderStatus status = CDecoder::tryReadEncodedValue(
        SReadOnlyByteSpan(sofar.toPtr(), filled), EAENC_DER, tag, content, bytesRead);

    if (status == EDEC_OK) {
        return true;        // content and bytesRead are now meaningful
    }

    if (status != EDEC_NEED_MORE) {
        return false;       // malformed, prohibited under DER, or past a decoder limit
    }

    // Incomplete, not wrong. How much more is not knowable in general -- the length octets
    // may themselves be the truncated part -- so read what the source has and retry.
    if (filled >= sofar.size() && !sofar.resize(sofar.size() * 2 + 64)) {
        return false;
    }

    // --> Named rather than a temporary, because IStream::read() takes its SByteSpan by
    // non-const reference, and C++ will not bind a non-const lvalue reference to a
    // temporary. MSVC accepts that; GCC and Clang reject it, so the example built on one
    // toolchain and not the other.
    SByteSpan chunk(sofar.toPtr() + filled, sofar.size() - filled);
    const size_t got = source->read(chunk);
    if (got == 0) {
        return false;       // the source ended mid-value: truncated for good
    }

    filled += got;
}
```
