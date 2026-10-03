Selects what a seek() offset is measured from. ESEEK_END with a negative offset reads a trailer without first asking for the stream's length; every mode clamps into [0, length] rather than parking the position out of range.

```cpp
// given: const IStreamPtr& stream
if (!stream || (stream->capabilities() & ESTREAM_SEEK) == 0) {
    return;
}

if (stream->seek(-4, ESEEK_END) != ERET_OK) {
    return;
}

uint8_t trailer[4] = {};
if (stream->read(trailer, sizeof(trailer)) != sizeof(trailer)) {
    return;
}

// ESEEK_CUR is relative to where that read left the position, so this re-reads the same
// four bytes; ESEEK_SET would be relative to the start.
if (stream->seek(-4, ESEEK_CUR) != ERET_OK) {
    return;
}
```
