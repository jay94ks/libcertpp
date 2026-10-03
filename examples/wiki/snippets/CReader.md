Descends into a DER SEQUENCE read from a stream. A failed typed read leaves the cursor exactly where it was, which is what makes probing an OPTIONAL or DEFAULT field safe: try the type the field would have, and if it is not there, read on as if nothing had happened.

```cpp
// given: const IStreamPtr& der
CReader reader(der, EAENC_DER);

CReader members;
if (!reader.readSequence(members)) {
    return;
}

int64_t version = 0;
if (!members.readInteger(version)) {
    version = 1;    // absent: the cursor still points at the next field
}

CWideString label;
if (!members.readString(EAUTAG_STRING_UTF8, label)) {
    return;
}

while (!members.atEnd()) {
    CTag tag;
    SReadOnlyByteSpan content;
    if (!members.readNextElement(tag, content)) {
        return;
    }
}
```
