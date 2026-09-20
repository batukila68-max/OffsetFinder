#include "Pattern.h"
#include <cctype>

namespace of {

static int HexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool ParsePattern(const std::string &text, std::vector<PatternByte> &out,
                  std::string &error) {
  out.clear();
  size_t i = 0, n = text.size();
  while (i < n) {
    char c = text[i];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { ++i; continue; }
    // token = one byte worth of hex/wildcards
    char a = c;
    int hi = -2, lo = -2; // -2 = unset
    if (a == '?') {
      hi = -1;
      ++i;
      lo = (i < n && text[i] == '?') ? -1 : (i < n ? HexNibble(text[i]) : -1);
      if (i < n && (text[i] == '?' || HexNibble(text[i]) >= 0)) ++i;
      else if (lo == -1) { /* single '?' */ }
    } else {
      hi = HexNibble(a);
      if (hi < 0) { error = std::string("bad byte at ") + std::to_string(i); return false; }
      ++i;
      if (i < n && text[i] == '?') { lo = -1; ++i; }
      else if (i < n && HexNibble(text[i]) >= 0) { lo = HexNibble(text[i]); ++i; }
      else { error = "odd nibble count"; return false; }
    }
    PatternByte pb{};
    if (hi == -1 && lo == -1) { pb.mask = 0x00; pb.value = 0; }
    else if (lo == -1)        { pb.mask = 0xF0; pb.value = (uint8_t)(hi << 4); }
    else if (hi == -1)        { pb.mask = 0x0F; pb.value = (uint8_t)lo; }
    else                      { pb.mask = 0xFF; pb.value = (uint8_t)((hi << 4) | lo); }
    out.push_back(pb);
  }
  if (out.empty()) { error = "empty pattern"; return false; }
  return true;
}

size_t FindPattern(const uint8_t *data, size_t size,
                   const std::vector<PatternByte> &pattern) {
  const size_t plen = pattern.size();
  if (plen == 0 || size < plen) return SIZE_MAX;
  const size_t limit = size - plen;
  for (size_t i = 0; i <= limit; ++i) {
    size_t j = 0;
    for (; j < plen; ++j) {
      if ((data[i + j] & pattern[j].mask) != (pattern[j].value & pattern[j].mask))
        break;
    }
    if (j == plen) return i;
  }
  return SIZE_MAX;
}

void FindPatternAll(const uint8_t *data, size_t size,
                    const std::vector<PatternByte> &pattern,
                    std::vector<size_t> &out) {
  const size_t plen = pattern.size();
  if (plen == 0 || size < plen) return;
  const size_t limit = size - plen;
  for (size_t i = 0; i <= limit; ++i) {
    size_t j = 0;
    for (; j < plen; ++j) {
      if ((data[i + j] & pattern[j].mask) != (pattern[j].value & pattern[j].mask))
        break;
    }
    if (j == plen) out.push_back(i);
  }
}

} // namespace of
