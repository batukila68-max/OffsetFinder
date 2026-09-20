#include "PointerChain.h"
#include <cstring>

namespace of {

bool ResolvePointerChain(IReader &reader, Address base,
                         const std::vector<uint32_t> &offsets,
                         Address &out) {
  Address cur = base;
  for (size_t i = 0; i < offsets.size(); ++i) {
    uint64_t next = 0;
    if (!reader.Read(cur, &next, sizeof(next))) return false;
    cur = (Address)next + offsets[i];
  }
  out = cur;
  return true;
}

bool ReadScalar(IReader &reader, Address addr, size_t size, uint64_t &out) {
  uint8_t buf[8] = {};
  if (size > 8) size = 8;
  if (!reader.Read(addr, buf, size)) return false;
  out = 0;
  std::memcpy(&out, buf, size);
  return true;
}

} // namespace of
