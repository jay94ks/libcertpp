Obtains a stream from the IStream::createMemory() factory, which is the only way to get one. createMemory() with no argument starts empty, and a write leaves the position at the end -- so reading back what you just wrote needs an explicit seek(), unlike the span overload, which starts already rewound.

```cpp
// given: SReadOnlyByteSpan content
IStreamPtr stream = IStream::createMemory();
if (!stream) {
    return;
}

if (stream->write(content.data, content.size) != content.size) {
    return;
}

if (stream->seek(0, ESEEK_SET) != ERET_OK) {
    return;
}

uint8_t head[8] = {};
SByteSpan into(head, sizeof(head));
const size_t got = stream->read(into);
if (got == 0) {
    return;   // a short read reports the count; there is no error code on read()
}

if (stream->close() != ERET_OK) {
    return;
}
```
