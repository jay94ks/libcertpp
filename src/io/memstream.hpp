#ifndef __SRC_IO_MEMSTREAM_HPP__
#define __SRC_IO_MEMSTREAM_HPP__

#include <certpp/io/stream.hpp>

namespace certpp {

    /**
     * Memory-based implementation of the IStream interface.
     */
    class MemStream : public IStream {
    private:
        /**
         * The alignment size for memory allocation.
         */
        static constexpr SizeType SIZE_ALIGN = 1024;

        /**
         * The initial flag configuration for the memory stream.
         */
        static constexpr uint32_t FLAG_INIT 
            = ESTREAM_READ 
            | ESTREAM_WRITE 
            | ESTREAM_SEEK
            ;

    private:
        uint32_t _flags;
        SByteSpan _span;
        SizeType _pos;
        SizeType _cap;

    public:
        /**
         * Constructor for the memory stream.
         * @param initialCap The initial capacity of the memory stream.
         */
        MemStream(SizeType initialCap = 0);

        /**
         * Destructor for the memory stream.
         */
        virtual ~MemStream() {
            close();
        }

    public:
        uint32_t capabilities() const override { return _flags; }
        SizeType capacity() const override { return _cap; }
        SizeType length() const override { return _span.size; }
        SizeType position() const override { return _pos; }

        ERetCode trimExcess() override;
        ERetCode reserve(SizeType newCap);

        ERetCode length(SizeType newLen) override;
        ERetCode seek(OffsetType offset, ESeekMode mode) override;
        size_t read(uint8_t* buf, size_t len) override;
        size_t write(const uint8_t* buf, size_t len) override;
        ERetCode flush() override;
        ERetCode close() override;
    
    };

}

#endif
