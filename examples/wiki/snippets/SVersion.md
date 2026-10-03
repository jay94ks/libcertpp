Compares the header the caller compiled against with the library actually loaded.

```cpp
SVersion lib = GetLibraryVersion();
if (lib != HEADER_VERSION) {
    // built against one version of the headers, linked against another
}
```
