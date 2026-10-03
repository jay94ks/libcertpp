Writes a collection as a PKCS#12/PFX container and reads one back. Unlike PEM, this format encrypts, so the password is load-bearing rather than ignored -- needsPassword() returns true. The iteration count is a constructor argument because it is a cost/strength trade-off only the caller can make; the default is 600,000, against RFC 7292's 1024 and OpenSSL's 2048.

```cpp
// given: const CCertCollection& collection, const SReadOnlyByteSpan& password
IChainFormatPtr pfx = IChainFormat::builtIn(ECHAINFMT_PFX);
if (!pfx) {
    return;
}

CBuffer container;
if (pfx->save(collection, password, container) != ERET_OK) {
    return;         // ERET_BADREQ for an empty collection or an empty password
}

// Reading back verifies the MAC before decrypting anything, so a wrong password or a
// tampered container fails without any plaintext having been produced.
CCertCollection loaded;
ERetCode rc = pfx->load(
    SReadOnlyByteSpan(container.toPtr(), container.size()), password, loaded);
if (rc != ERET_OK) {
    // ERET_KEY_ERROR: the MAC did not verify -- wrong password, or the file was altered.
    // ERET_NOTSUP: a legacy PBES1 cipher (RC2, 3DES) this format deliberately will not read.
    return;
}

// Confirm a loaded key really belongs to its certificate, by signing rather than by
// comparing serialized keys -- which only works for some algorithms.
loaded.checkKeyPairing(0);
```
