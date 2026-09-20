#include "Types.h"
#include <cstring>

namespace of {

size_t ReadRegionChunks(IReader &reader, Address base, size_t size,
                        std::vector<uint8_t> &out,
                        std::vector<bool> *validMap, size_t chunkSize) {
  out.assign(size, 0);
  if (validMap) validMap->assign(size, false);
  size_t total = 0;
  for (size_t off = 0; off < size; off += chunkSize) {
    const size_t want = (off + chunkSize <= size) ? chunkSize : size - off;
    if (reader.Read(base + off, out.data() + off, want)) {
      total += want;
      if (validMap)
        for (size_t i = off; i < off + want; ++i) (*validMap)[i] = true;
      continue;
    }
    // Chunk failed: fall back to page granularity so a few bad pages do not
    // black out a whole region.
    for (size_t p = off; p < off + want; p += 0x1000) {
      const size_t pw = (p + 0x1000 <= size) ? 0x1000 : size - p;
      if (reader.Read(base + p, out.data() + p, pw)) {
        total += pw;
        if (validMap)
          for (size_t i = p; i < p + pw; ++i) (*validMap)[i] = true;
      }
    }
  }
  return total;
}

} // namespace of
