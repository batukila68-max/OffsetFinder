#include "SigScan.h"
#include <algorithm>
#include <cstring>

namespace of {

static bool ReadableRegion(const Region &r) {
#ifdef _WIN32
  if (r.state != 0x1000 /*MEM_COMMIT*/) return false;
  const uint32_t p = r.protect & 0xFF;
  if (p == 0x01 /*NOACCESS*/) return false;
  if (r.protect & 0x100 /*GUARD*/) return false;
  // include all readable pages; scanning is read-only anyway
#endif
  return true;
}

std::vector<SigHit> SigScanRegions(
    IReader &reader, const std::vector<Region> &regions,
    const std::vector<PatternByte> &pattern, const std::string &moduleFilter,
    int relOffset, int instrSize,
    const std::function<bool(double)> &progress, size_t maxHits) {
  std::vector<SigHit> hits;
  if (pattern.empty()) return hits;
  const size_t overlap = pattern.size() - 1;
  std::vector<uint8_t> buf, prevTail;
  size_t total = 0;
  for (const auto &r : regions)
    if (ReadableRegion(r) &&
        (moduleFilter.empty() || r.tag.find(moduleFilter) != std::string::npos))
      total += r.size;
  size_t done = 0;

  for (const Region &r : regions) {
    if (!ReadableRegion(r)) continue;
    if (!moduleFilter.empty() &&
        r.tag.find(moduleFilter) == std::string::npos)
      continue;
    const size_t chunk = 4 * 1024 * 1024;
    prevTail.clear();
    for (size_t off = 0; off < r.size; off += chunk) {
      const size_t want = std::min(chunk, r.size - off);
      buf.resize(want);
      if (!reader.Read(r.base + off, buf.data(), want)) {
        // failed chunk: retry per-page, zero-fill gaps so pattern can't
        // false-positive across a gap
        buf.assign(want, 0);
        for (size_t p = 0; p < want; p += 0x1000) {
          const size_t pw = std::min((size_t)0x1000, want - p);
          reader.Read(r.base + off + p, buf.data() + p, pw);
        }
      }
      // prepend overlap tail from previous chunk
      std::vector<size_t> rel;
      if (!prevTail.empty()) {
        std::vector<uint8_t> joined(prevTail.size() + want);
        memcpy(joined.data(), prevTail.data(), prevTail.size());
        memcpy(joined.data() + prevTail.size(), buf.data(), want);
        FindPatternAll(joined.data(), joined.size(), pattern, rel);
        for (size_t idx : rel) {
          if (idx >= prevTail.size()) break; // inside current chunk, re-found
          if (idx + pattern.size() <= prevTail.size()) continue; // dup
          SigHit h; h.address = r.base + off - prevTail.size() + idx;
          hits.push_back(h);
        }
      }
      rel.clear();
      FindPatternAll(buf.data(), want, pattern, rel);
      for (size_t idx : rel) {
        SigHit h; h.address = r.base + off + idx;
        hits.push_back(h);
        if (hits.size() >= maxHits) return hits;
      }
      prevTail.assign(buf.end() - std::min(overlap, want), buf.end());
    }
    done += r.size;
    if (progress && !progress(total ? (double)done / total : 1.0))
      return hits;
  }
  // resolve RIP-relative targets
  if (relOffset >= 0 && instrSize > 0) {
    for (SigHit &h : hits) {
      int32_t rel = 0;
      if (reader.Read(h.address + relOffset, &rel, 4)) {
        h.resolved = h.address + instrSize + (int64_t)rel;
        h.hasResolved = true;
      }
    }
  }
  return hits;
}

std::vector<size_t> SigScanBuffer(const uint8_t *data, size_t size,
                                  const std::vector<PatternByte> &pattern) {
  std::vector<size_t> out;
  FindPatternAll(data, size, pattern, out);
  return out;
}

} // namespace of
