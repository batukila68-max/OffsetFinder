#pragma once
// Pattern scan across process regions, and RIP-relative resolution so a
// signature hit on `mov rax, [rip+X]` maps back to the module offset of the
// referenced global — the classic "dw* offset" workflow.
#include "Pattern.h"
#include "Types.h"
#include <functional>
#include <vector>

namespace of {

struct SigHit {
  Address address = 0;      // where the pattern matched
  Address resolved = 0;     // absolute target after RIP-relative resolution
  bool hasResolved = false;
};

// Scans readable committed regions (optionally only ones tagged with a module
// name containing `moduleFilter`). `relOffset`/`instrSize` describe a
// RIP-relative instruction inside the pattern: when relOffset >= 0 the i32 at
// (hit + relOffset) is added to (hit + instrSize) to produce `resolved`.
std::vector<SigHit> SigScanRegions(
    IReader &reader, const std::vector<Region> &regions,
    const std::vector<PatternByte> &pattern,
    const std::string &moduleFilter, int relOffset, int instrSize,
    const std::function<bool(double)> &progress, size_t maxHits = 4096);

// For a single buffer (module dump / file) instead of a live process.
std::vector<size_t> SigScanBuffer(const uint8_t *data, size_t size,
                                  const std::vector<PatternByte> &pattern);

} // namespace of
