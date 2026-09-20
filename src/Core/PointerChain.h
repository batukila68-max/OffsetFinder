#pragma once
// Pointer-chain evaluation: base + series of u32 offsets read through IReader.
// Used live to verify a found offset chain still lands where expected.
#include "Types.h"
#include <vector>

namespace of {

// Follows the chain: reads u64 at `base`, adds offsets[i], repeats. The final
// offset is added without a trailing read. Returns false if any read fails.
bool ResolvePointerChain(IReader &reader, Address base,
                         const std::vector<uint32_t> &offsets,
                         Address &out);

// Reads a typed value at `addr` for display; size must be <= 8.
bool ReadScalar(IReader &reader, Address addr, size_t size, uint64_t &out);

} // namespace of
