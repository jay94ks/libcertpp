The interface every x509/exts/ builder implements, which is what lets one policy table hand back extensions of different types. build() reports a field it cannot DER-encode by returning null rather than throwing, and a null entry in CCertBuilder::extensions fails the whole build.

```cpp
// given: CCertBuilder& issuing
auto ku = std::make_shared<CKeyUsagesExtensionBuilder>();
ku->setBits(EKUSE_DIGITAL_SIGNATURE | EKUSE_KEY_ENCIPHERMENT);

auto eku = std::make_shared<CEkuExtensionBuilder>();
eku->addPurpose(CEkuExtension::OID_SERVER_AUTH);

IExtensionBuilderPtr policy[] = { ku, eku };

for (const IExtensionBuilderPtr& builder : policy) {
    IExtensionPtr ext = builder->build();
    if (!ext) {
        return;
    }

    ext->critical(true);
    issuing.extensions.add(ext);
}
```
