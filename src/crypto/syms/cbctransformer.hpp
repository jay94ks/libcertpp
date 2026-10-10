#ifndef __SRC_CRYPTO_SYMS_CBCTRANSFORMER_HPP__
#define __SRC_CRYPTO_SYMS_CBCTRANSFORMER_HPP__

#include <certpp/crypto/sym.hpp>
#include <certpp/io/buffer.hpp>
#include <functional>

namespace certpp {
namespace crypto {

    /* CBC-mode block cipher transformer shared by AES/DES/3DES's ISymmetricContext
     * implementations -- the only thing that differs between them is the per-block
     * encrypt/decrypt function and the block size, both supplied by the caller, so none of them
     * need their own copy of this buffering/chaining/padding logic.
     *
     * Padding is PKCS#7 or none, per the ESymPaddings the caller passes (which every caller takes
     * from its context's padding(), so it is the context's choice, defaulting to PKCS#7 and
     * therefore unchanged for anyone who never asks).
     *
     * With PKCS#7, decrypting always holds back the most recently completed block rather than
     * emitting it immediately, since that block might turn out to be the final one (requiring its
     * padding to be located and stripped) -- it's only emitted, unpadded, once transformFinal()
     * confirms it really is the last block. Encrypting has no such ambiguity (padding is only
     * ever added in transformFinal(), after which the transformer is no longer usable), so
     * every complete block is encrypted and emitted as soon as it's buffered.
     *
     * With ESYMPAD_NONE neither direction has anything to hold back or strip: every whole block
     * is emitted as soon as it is buffered, and transformFinal() produces nothing, failing with
     * ERET_BADREQ if a partial block is left over -- unpadded CBC cannot represent a length that
     * isn't a multiple of the block size, so a caller feeding one has made a mistake that must
     * not be silently rounded up. */
    class CbcTransformer : public ISymmetricTransformer {
    public:
        /* Encrypts/decrypts exactly one block (in and out may alias the same buffer). */
        using BlockFn = std::function<void(const uint8_t* in, uint8_t* out)>;

        /* Encrypts a run of whole blocks, holding the chaining value in a register.
         *
         * Offered by AES, where the per-block path costs ~84 cycles a block against ~45
         * here because the chaining value would otherwise be written to `_chain` and read
         * back for the next block -- pure addition to a serial chain's critical path. See
         * AesCore::encryptCbcBulk() for the measurement.
         *
         * Optional, and empty for every cipher that cannot supply one, in which case
         * processBuffered() uses the per-block path exactly as before. The bulk function
         * replaces only the whole-block loop's body: the output-space check, the chain
         * write-back, the remainder handling and the PKCS#7 logic all stay where they are,
         * so a bulk run is indistinguishable from an equivalent run of single blocks
         * except in speed.
         *
         * --> Keep the two paths byte-identical. Round-trip tests prove the two directions
         * agree with each other but cannot tell you the ciphertext is *right* -- two matching
         * errors still round-trip -- so tests/crypto/syms/aes.cpp holds the bulk path against
         * AesCore::encryptBlockPortable() directly. Keep that passing.
         *
         * --> `chain` is the transformer's own chain buffer, so the bulk function reads it
         * on entry and writes it back on exit -- the same state the per-block path leaves,
         * which is what lets a later transform() call continue without knowing which path
         * produced the blocks before it. */
        using BulkBlockFn = std::function<
            void(const uint8_t* in, uint8_t* out, size_t blocks, uint8_t* chain)
        >;

    private:
        bool _encrypting;
        size_t _blockBytes;
        ESymPaddings _padding;
        BlockFn _blockFn;
        BulkBlockFn _bulkBlockFn;   // --> empty when the cipher offers no bulk path.
        CBuffer _chain;      // --> current chaining value; IV until the first block.
        CBuffer _buffer;     // --> input not yet consumed.
        CBuffer _scratch;    // --> one block of scratch space, reused per block.

        ERetCode processBuffered(bool final, SByteSpan& output);

    public:
        /**
         * @param ctx The context this transformer was created from.
         * @param encrypting true to encrypt (pad on finalize); false to decrypt (strip padding
         * on finalize).
         * @param blockBytes The cipher's block size, in bytes.
         * @param iv The initialization vector; must be exactly blockBytes long.
         * @param padding ESYMPAD_PKCS7 to pad/strip the final block, ESYMPAD_NONE to require the
         * input to be a whole number of blocks already.
         * @param blockFn Encrypts (if encrypting) or decrypts (otherwise) one raw blockBytes-long
         * block, with no chaining/padding of its own -- this transformer applies CBC chaining and
         * whatever padding `padding` selects around it.
         * @param bulkBlockFn Optional: encrypts a run of whole blocks with the chaining value in
         * a register, reading and writing the transformer's own chain buffer. Empty means the
         * per-block function is used for everything, which is how every cipher but AES calls
         * this. Supplying both makes the bulk path handle whole blocks and the per-block path
         * handle the remainder, so the two must produce identical output.
         */
        CbcTransformer(
            const ISymmetricContextPtr& ctx, bool encrypting, size_t blockBytes,
            SReadOnlyByteSpan iv, ESymPaddings padding, BlockFn blockFn,
            BulkBlockFn bulkBlockFn = nullptr
        );

        ERetCode transform(const SReadOnlyByteSpan& input, SByteSpan& output) override;
        ERetCode transformFinal(SByteSpan& output) override;
    };

} // namespace crypto
} // namespace certpp

#endif
