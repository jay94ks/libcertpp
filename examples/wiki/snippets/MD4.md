Derives the NTLM/EAP-MSCHAPv2 NT hash, which is MD4 of the UTF-16LE password. That protocol requirement is the only reason MD4 is in this library; nothing new should hash with it.

```cpp
// given: const SReadOnlyByteSpan& passwordUtf16le, SByteSpan ntHash
if (ntHash.size < 16) {
    return;
}

MD4 hasher;
hasher.push(passwordUtf16le);
if (!hasher.finish(ntHash)) {
    return;
}

// The NT hash is a password equivalent -- anything that can replay it can authenticate --
// so treat it as key material and clear it rather than letting it fall out of scope.
CSecure::zero(SByteSpan(ntHash.data, 16));
```
