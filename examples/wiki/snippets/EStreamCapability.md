A bitmask of what a stream supports, not a single value: test the bit you are about to rely on. A memory stream reports all three, but a stream handed in from elsewhere may be read-only or unseekable, and the calls it cannot do fail at run time rather than at compile time.

```cpp
// given: const IStreamPtr& stream
if (!stream) {
    return;
}

const uint32_t caps = stream->capabilities();
if ((caps & ESTREAM_WRITE) == 0) {
    return;
}

const uint8_t marker[] = { 0x30, 0x82 };
if (stream->write(marker, sizeof(marker)) != sizeof(marker)) {
    return;
}

// Reading back what was just written needs both bits, not just ESTREAM_READ.
const uint32_t both = uint32_t(ESTREAM_READ | ESTREAM_SEEK);
if ((caps & both) == both && stream->seek(0, ESEEK_SET) != ERET_OK) {
    return;
}
```
