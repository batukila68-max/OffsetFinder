#pragma once
// Value scanning engine (Cheat-Engine style). Two-phase model:
//   FirstScan: walk every readable region, emit hits into a compact snapshot.
//   NextScan:  re-read only the snapshot addresses and filter.
// The snapshot is a flat byte array + hit count so the UI can render without
// locking the whole scan buffer.
#include "Types.h"
#include <functional>
#include <string>
#include <vector>

namespace of {

enum class ScanType { Exact, Greater, Less, Between, Unknown };
enum class ValueType { U8, I8, U16, I16, U32, I32, U64, I64, F32, F64, Bytes, StringA, StringW };
enum class NextFilter { Same, Changed, Increased, Decreased, Exact };

struct ScanValue {
  ValueType type = ValueType::U32;
  std::string text;   // user-typed literal (decimal/hex/string)
  std::string text2;  // upper bound for Between
  bool hex = false;
};

struct ScanHit {
  Address address;
  uint64_t u64 = 0; // value reinterpreted to u64/f64 for compare/display
  double f64 = 0;
  bool valid = false;
};

class Scanner {
public:
  // progress(fraction) lets the UI show a bar; return false to abort.
  using Progress = std::function<bool(double)>;

  Scanner(IReader &reader, std::vector<Region> regions);

  bool FirstScan(const ScanValue &value, ScanType type, Progress progress);
  bool NextScan(const ScanValue &value, NextFilter filter, Progress progress);

  const std::vector<ScanHit> &Hits() const { return hits; }
  size_t HitCount() const { return hits.size(); }
  size_t ValueSize() const { return valueSize; }

  // Re-read current values for the first `count` hits (for live display).
  void RefreshValues(size_t count);

  void Reset();

private:
  bool Matches(const uint8_t *mem, const ScanValue &value, ScanType type) const;
  bool CompareNext(uint64_t cur, uint64_t prev, double curF, double prevF,
                   const ScanValue &value, NextFilter filter) const;
  bool ParseValue(const ScanValue &value, std::vector<uint8_t> &needle,
                  uint64_t &u, double &f) const;

  IReader &reader;
  std::vector<Region> regions;
  std::vector<ScanHit> hits;
  size_t valueSize = 4;
  ValueType valueType = ValueType::U32;
  std::vector<uint8_t> prevBytes; // parallel to hits when Bytes/String
};

} // namespace of
