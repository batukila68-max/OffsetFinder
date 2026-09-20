#include "Scanner.h"
#include "Pattern.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace of {

static size_t TypeSize(ValueType t, const std::string &s) {
  switch (t) {
  case ValueType::U8: case ValueType::I8: return 1;
  case ValueType::U16: case ValueType::I16: return 2;
  case ValueType::U32: case ValueType::I32: case ValueType::F32: return 4;
  case ValueType::U64: case ValueType::I64: case ValueType::F64: return 8;
  case ValueType::Bytes: {
    std::vector<PatternByte> p; std::string e;
    return ParsePattern(s, p, e) ? p.size() : 0;
  }
  case ValueType::StringA: return s.size() ? s.size() + 1 : 0;
  case ValueType::StringW: return s.size() ? (s.size() + 1) * 2 : 0;
  }
  return 0;
}

static double ReadFloat(const uint8_t *mem, ValueType t) {
  if (t == ValueType::F32) { float x = 0; memcpy(&x, mem, 4); return x; }
  double x = 0; memcpy(&x, mem, 8); return x;
}

static bool Readable(const Region &r) {
#ifdef _WIN32
  return r.state == 0x1000 /*MEM_COMMIT*/ &&
         !(r.protect & (0x01 /*NOACCESS*/ | 0x100 /*GUARD*/));
#else
  return true;
#endif
}

Scanner::Scanner(IReader &r, std::vector<Region> regs)
    : reader(r), regions(std::move(regs)) {
  regions.erase(std::remove_if(regions.begin(), regions.end(),
                             [](const Region &x) { return !Readable(x); }),
                regions.end());
}

void Scanner::Reset() { hits.clear(); prevBytes.clear(); }

bool Scanner::ParseValue(const ScanValue &v, std::vector<uint8_t> &needle,
                         uint64_t &u, double &f) const {
  needle.clear(); u = 0; f = 0;
  auto parseNum = [&](const std::string &t, uint64_t &out) -> bool {
    if (t.empty()) return false;
    char *end = nullptr;
    out = v.hex ? std::strtoull(t.c_str(), &end, 16)
                : std::strtoull(t.c_str(), &end, 0);
    return end != t.c_str();
  };
  uint64_t tmp;
  if (!parseNum(v.text, tmp)) return false;
  u = tmp;
  f = std::strtod(v.text.c_str(), nullptr);
  switch (v.type) {
  case ValueType::U8: case ValueType::I8: needle.resize(1); needle[0] = (uint8_t)u; break;
  case ValueType::U16: case ValueType::I16: { uint16_t x = (uint16_t)u; needle.resize(2); memcpy(needle.data(), &x, 2); } break;
  case ValueType::U32: case ValueType::I32: { uint32_t x = (uint32_t)u; needle.resize(4); memcpy(needle.data(), &x, 4); } break;
  case ValueType::U64: case ValueType::I64: { needle.resize(8); memcpy(needle.data(), &u, 8); } break;
  case ValueType::F32: { float x = (float)f; needle.resize(4); memcpy(needle.data(), &x, 4); } break;
  case ValueType::F64: { double x = f; needle.resize(8); memcpy(needle.data(), &x, 8); } break;
  case ValueType::Bytes: {
    std::vector<PatternByte> p; std::string e;
    if (!ParsePattern(v.text, p, e)) return false;
    needle.resize(p.size());
    for (size_t i = 0; i < p.size(); ++i) needle[i] = p[i].value;
    // wildcard bits are excluded from exact compare via Matches()
  } break;
  case ValueType::StringA:
    needle.assign(v.text.begin(), v.text.end()); needle.push_back(0); break;
  case ValueType::StringW:
    for (char c : v.text) { needle.push_back((uint8_t)c); needle.push_back(0); }
    needle.push_back(0); needle.push_back(0); break;
  }
  return true;
}

bool Scanner::Matches(const uint8_t *mem, const ScanValue &v, ScanType type) const {
  if (v.type == ValueType::Bytes) {
    std::vector<PatternByte> p; std::string e;
    if (!ParsePattern(v.text, p, e)) return false;
    for (size_t i = 0; i < p.size(); ++i)
      if ((mem[i] & p[i].mask) != (p[i].value & p[i].mask)) return false;
    return true;
  }
  std::vector<uint8_t> needle; uint64_t u = 0; double f = 0;
  if (!ParseValue(v, needle, u, f)) return false;
  switch (type) {
  case ScanType::Exact: {
    if (v.type == ValueType::F32 || v.type == ValueType::F64)
      return ReadFloat(mem, v.type) == f;
    return memcmp(mem, needle.data(), valueSize) == 0;
  }
  case ScanType::Greater: case ScanType::Less: case ScanType::Between: {
    uint64_t cur = 0; memcpy(&cur, mem, valueSize);
    uint64_t lo = 0; memcpy(&lo, needle.data(), std::min(needle.size(), (size_t)8));
    if (v.type == ValueType::F32 || v.type == ValueType::F64) {
      double curF = ReadFloat(mem, v.type);
      double loF = std::strtod(v.text.c_str(), nullptr);
      double hiF = v.text2.empty() ? loF : std::strtod(v.text2.c_str(), nullptr);
      if (type == ScanType::Greater) return curF > loF;
      if (type == ScanType::Less) return curF < loF;
      return curF >= loF && curF <= hiF;
    }
    uint64_t hi = lo;
    if (type == ScanType::Between) {
      std::string dummy = v.text2; char *e = nullptr;
      hi = v.hex ? std::strtoull(dummy.c_str(), &e, 16)
                 : std::strtoull(dummy.c_str(), &e, 0);
    }
    // signed compare for signed types
    const bool sign = (v.type == ValueType::I8 || v.type == ValueType::I16 ||
                       v.type == ValueType::I32 || v.type == ValueType::I64);
    auto lt = [&](uint64_t a, uint64_t b) {
      if (!sign) return a < b;
      switch (valueSize) {
      case 1: return (int8_t)a < (int8_t)b;
      case 2: return (int16_t)a < (int16_t)b;
      case 4: return (int32_t)a < (int32_t)b;
      default: return (int64_t)a < (int64_t)b;
      }
    };
    if (type == ScanType::Greater) return lt(lo, cur);
    if (type == ScanType::Less) return lt(cur, lo);
    return !lt(cur, lo) && !lt(hi, cur);
  }
  case ScanType::Unknown: return true;
  }
  return false;
}

bool Scanner::FirstScan(const ScanValue &v, ScanType type, Progress progress) {
  Reset();
  valueType = v.type;
  valueSize = TypeSize(v.type, v.text);
  if (valueSize == 0 && type != ScanType::Unknown) return false;

  std::vector<uint8_t> buf;
  std::vector<bool> valid;
  const size_t overlap = valueSize > 1 ? valueSize - 1 : 0;
  size_t total = 0; for (auto &r : regions) total += r.size;
  size_t done = 0;

  for (const Region &r : regions) {
    if (ReadRegionChunks(reader, r.base, r.size, buf, &valid) == 0) {
      done += r.size;
      continue;
    }
    if (type == ScanType::Unknown) {
      for (size_t i = 0; i + valueSize <= r.size; i += valueSize) {
        if (!valid[i]) continue;
        ScanHit h; h.address = r.base + i;
        memcpy(&h.u64, buf.data() + i, std::min(valueSize, (size_t)8));
        h.valid = true; hits.push_back(h);
      }
    } else {
      for (size_t i = 0; i + valueSize <= r.size; ++i) {
        if (!valid[i]) { i = (i & ~(size_t)0xFFF) + 0xFFF - 1; continue; }
        if (!Matches(buf.data() + i, v, type)) continue;
        ScanHit h; h.address = r.base + i;
        memcpy(&h.u64, buf.data() + i, std::min(valueSize, (size_t)8));
        if (v.type == ValueType::F32 || v.type == ValueType::F64)
          h.f64 = ReadFloat(buf.data() + i, v.type);
        h.valid = true; hits.push_back(h);
      }
    }
    done += r.size;
    if (progress && !progress(total ? (double)done / total : 1.0)) return false;
  }
  // store previous bytes for Changed/Same filters on variable-size types
  prevBytes.assign(hits.size() * valueSize, 0);
  for (size_t i = 0; i < hits.size(); ++i)
    memcpy(prevBytes.data() + i * valueSize, &hits[i].u64,
           std::min(valueSize, (size_t)8));
  if (valueSize > 8) {
    for (size_t i = 0; i < hits.size(); ++i)
      reader.Read(hits[i].address, prevBytes.data() + i * valueSize, valueSize);
  }
  return true;
}

bool Scanner::CompareNext(uint64_t cur, uint64_t prev, double curF, double prevF,
                          const ScanValue &v, NextFilter filter) const {
  // compare using the type locked in by FirstScan, not the current UI combo
  const bool flt = (valueType == ValueType::F32 || valueType == ValueType::F64);
  switch (filter) {
  case NextFilter::Exact: {
    ScanValue sv = v;
    sv.type = valueType;
    std::vector<uint8_t> needle; uint64_t u = 0; double f = 0;
    if (!ParseValue(sv, needle, u, f)) return false;
    return flt ? curF == f : cur == u;
  }
  case NextFilter::Same:    return flt ? curF == prevF : cur == prev;
  case NextFilter::Changed: return flt ? curF != prevF : cur != prev;
  case NextFilter::Increased: {
    if (flt) return curF > prevF;
    if (valueType == ValueType::I8 || valueType == ValueType::I16 ||
        valueType == ValueType::I32 || valueType == ValueType::I64) {
      switch (valueSize) {
      case 1: return (int8_t)cur > (int8_t)prev;
      case 2: return (int16_t)cur > (int16_t)prev;
      case 4: return (int32_t)cur > (int32_t)prev;
      default: return (int64_t)cur > (int64_t)prev;
      }
    }
    return cur > prev;
  }
  case NextFilter::Decreased: {
    if (flt) return curF < prevF;
    if (valueType == ValueType::I8 || valueType == ValueType::I16 ||
        valueType == ValueType::I32 || valueType == ValueType::I64) {
      switch (valueSize) {
      case 1: return (int8_t)cur < (int8_t)prev;
      case 2: return (int16_t)cur < (int16_t)prev;
      case 4: return (int32_t)cur < (int32_t)prev;
      default: return (int64_t)cur < (int64_t)prev;
      }
    }
    return cur < prev;
  }
  }
  return false;
}

bool Scanner::NextScan(const ScanValue &v, NextFilter filter, Progress progress) {
  if (hits.empty()) return false;
  std::vector<ScanHit> kept;
  kept.reserve(hits.size());
  std::vector<uint8_t> newPrev(hits.size() * valueSize, 0);
  size_t done = 0;
  for (const ScanHit &h : hits) {
    uint8_t buf[16] = {};
    bool ok = reader.Read(h.address, buf, valueSize <= 16 ? valueSize : 16);
    uint64_t prev = h.u64; double prevF = h.f64;
    if (valueSize > 8) {
      size_t idx = &h - hits.data();
      memcpy(&prev, prevBytes.data() + idx * valueSize, 8);
    }
    if (ok) {
      uint64_t cur = 0; double curF = 0;
      memcpy(&cur, buf, std::min(valueSize, (size_t)8));
      if (valueType == ValueType::F32 || valueType == ValueType::F64)
        curF = ReadFloat(buf, valueType);
      if (CompareNext(cur, prev, curF, prevF, v, filter)) {
        ScanHit nh = h; nh.u64 = cur; nh.f64 = curF; nh.valid = true;
        size_t idx = kept.size();
        kept.push_back(nh);
        memcpy(newPrev.data() + idx * valueSize, buf,
               std::min(valueSize, (size_t)16));
        if (valueSize > 16)
          reader.Read(h.address, newPrev.data() + idx * valueSize, valueSize);
      }
    }
    ++done;
    if ((done & 0xFFF) == 0 && progress && !progress((double)done / hits.size()))
      return false;
  }
  hits.swap(kept);
  prevBytes.swap(newPrev);
  return true;
}

void Scanner::RefreshValues(size_t count) {
  const size_t n = std::min(count, hits.size());
  for (size_t i = 0; i < n; ++i) {
    uint8_t buf[8] = {};
    if (reader.Read(hits[i].address, buf, std::min(valueSize, (size_t)8))) {
      memcpy(&hits[i].u64, buf, 8);
      if (valueType == ValueType::F32 || valueType == ValueType::F64)
        hits[i].f64 = ReadFloat(buf, valueType);
      hits[i].valid = true;
    } else hits[i].valid = false;
  }
}

} // namespace of
