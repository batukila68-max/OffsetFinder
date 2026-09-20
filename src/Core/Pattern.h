#pragma once
// Signature pattern parsing and matching. Pure logic: no OS calls, so it is
// unit-tested on the host. Patterns use the IDA convention: hex byte pairs
// separated by spaces, "?" or "??" for wildcard nibbles/bytes.
#include <cstdint>
#include <string>
#include <vector>

namespace of {

struct PatternByte {
  uint8_t value;
  uint8_t mask; // 0xFF = exact, 0x00 = wildcard, 0xF0/0x0F = nibble wildcard
};

// Parses "48 8B 05 ? ? ? ? 48 8B" / "48 8B 05 ?? ?? ?? ??" / "F3 0F1x".
// Returns false on malformed input; error receives a short reason.
bool ParsePattern(const std::string &text, std::vector<PatternByte> &out,
                  std::string &error);

// Returns the 0-based offset of the first match inside [data, data+size),
// or SIZE_MAX. Forward-compatible with scanning chunk overlaps: callers add
// the chunk base.
size_t FindPattern(const uint8_t *data, size_t size,
                   const std::vector<PatternByte> &pattern);

// Finds every match, appending absolute indices to out.
void FindPatternAll(const uint8_t *data, size_t size,
                    const std::vector<PatternByte> &pattern,
                    std::vector<size_t> &out);

} // namespace of
