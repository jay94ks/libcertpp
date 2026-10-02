#include <certpp/io/stream.hpp>
#include "memstream.hpp"

namespace certpp {
    
    /* Create a memory-based stream with the specified initial size. */
    IStreamPtr IStream::createMemory(SizeType initialCap) {
        return std::make_shared<MemStream>(initialCap);
    }

    /* Create a memory-based stream using the provided buffer. */
    IStreamPtr IStream::createMemory(const SReadOnlyByteSpan& buf) {
        auto s = std::make_shared<MemStream>();

        s->write(buf.data, buf.size);
        s->seek(0, ESEEK_SET);
        
        return s;
    }
} // namespace certpp
