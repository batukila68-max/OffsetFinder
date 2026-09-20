// Host-side unit tests for the scanning engine (run on Linux CI).
// A FakeReader serves an in-memory buffer so Scanner/SigScan run unmodified.
#include "../src/Core/Pattern.h"
#include "../src/Core/Scanner.h"
#include "../src/Core/SigScan.h"
#include "../src/Core/PointerChain.h"
#include "../src/Core/Export.h"
#include "../src/Core/Process.h"
#include <cstdio>
#include <cstring>
#include <vector>

using namespace of;

static int failures = 0;
#define CHECK(cond, msg)                                                     \
  do {                                                                       \
    if (!(cond)) {                                                           \
      std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg);               \
      ++failures;                                                            \
    }                                                                        \
  } while (0)

class FakeReader final : public IReader {
public:
  std::vector<uint8_t> mem;
  Address base = 0x10000;
  explicit FakeReader(size_t size) : mem(size, 0) {}
  template <typename T> void Put(size_t off, T v) {
    std::memcpy(mem.data() + off, &v, sizeof(v));
  }
  bool Read(Address a, void *out, size_t n) override {
    if (a < base || a - base + n > mem.size()) return false;
    std::memcpy(out, mem.data() + (a - base), n);
    return true;
  }
  bool IsValid() const override { return true; }
};

static void TestPatternParse() {
  std::vector<PatternByte> p;
  std::string err;
  CHECK(ParsePattern("48 8B 05 ? ? ? ?", p, err), "parse wildcards");
  CHECK(p.size() == 7 && p[3].mask == 0 && p[0].mask == 0xFF && p[0].value == 0x48,
        "wildcard masks");
  CHECK(ParsePattern("48 8B ?? ??", p, err) && p.size() == 4, "double-? form");
  CHECK(ParsePattern("F3 0F1?", p, err) && p.size() == 3 && p[2].mask == 0xF0 &&
            p[2].value == 0x10,
        "nibble wildcard");
  CHECK(!ParsePattern("48 8", p, err), "odd nibble rejected");
  CHECK(!ParsePattern("", p, err), "empty rejected");
}

static void TestPatternFind() {
  uint8_t mem[] = {0xAA, 0x48, 0x8B, 0x05, 1, 2, 3, 4, 0x90, 0x48, 0x8B, 0x05,
                   9, 9, 9, 9};
  std::vector<PatternByte> p;
  std::string err;
  ParsePattern("48 8B 05 ? ? ? ?", p, err);
  std::vector<size_t> hits;
  FindPatternAll(mem, sizeof(mem), p, hits);
  CHECK(hits.size() == 2 && hits[0] == 1 && hits[1] == 9, "two sig hits");
  CHECK(FindPattern(mem, sizeof(mem), p) == 1, "first hit index");
}

static void TestValueScan() {
  FakeReader r(0x10000);
  uint32_t want = 0xDEADBEEF;
  r.Put<uint32_t>(0x100, want);
  r.Put<uint32_t>(0x200, want);
  r.Put<uint32_t>(0x300, 42);
  Region region{r.base, r.mem.size(), 0, 0, 0, ""};
  Scanner sc(r, {region});
  ScanValue v{ValueType::U32, "DEADBEEF", "", true};
  CHECK(sc.FirstScan(v, ScanType::Exact, nullptr), "first scan");
  CHECK(sc.HitCount() == 2, "exact match count");
  // mutate one hit, run "unchanged"
  r.Put<uint32_t>(0x100, 7);
  ScanValue dummy{ValueType::U32, "0", "", false};
  CHECK(sc.NextScan(dummy, NextFilter::Same, nullptr), "next scan same");
  CHECK(sc.HitCount() == 1, "same filter keeps stable hit");
  CHECK(sc.Hits()[0].address == r.base + 0x200, "correct survivor");
}

static void TestValueScanFloat() {
  FakeReader r(0x1000);
  float fv = 3.5f;
  r.Put<float>(0x40, fv);
  Region region{r.base, r.mem.size(), 0, 0, 0, ""};
  Scanner sc(r, {region});
  ScanValue v{ValueType::F32, "3.5", "", false};
  CHECK(sc.FirstScan(v, ScanType::Exact, nullptr), "float scan");
  bool found = false;
  for (const auto &h : sc.Hits())
    if (h.address == r.base + 0x40 && h.f64 == 3.5) found = true;
  CHECK(found, "float hit decoded");
}

static void TestPointerChain() {
  FakeReader r(0x1000);
  r.Put<uint64_t>(0x100, r.base + 0x200); // *base -> 0x200
  r.Put<uint64_t>(0x210, r.base + 0x300); // *(0x200+0x10) -> 0x300
  Address out = 0;
  CHECK(ResolvePointerChain(r, r.base + 0x100, {0x10, 0x0}, out),
        "chain resolves");
  CHECK(out == r.base + 0x300, "chain lands on target");
}

static void TestResolveAddress() {
  std::vector<Module> mods{{"client.dll", "/g/client.dll", 0x140000000,
                            0x1000000}};
  std::string s = ResolveAddress(mods, 0x140000000 + 0x1A2B3C);
  CHECK(s == "client.dll+0x1A2B3C", "module+offset format");
  CHECK(ResolveAddress(mods, 0x7FFF0000) == "0x7FFF0000", "bare VA fallback");
}

int main() {
  std::setbuf(stdout, nullptr);
  TestPatternParse();
  TestPatternFind();
  TestValueScan();
  TestValueScanFloat();
  TestPointerChain();
  TestResolveAddress();
  if (!failures) std::puts("all core tests passed");
  return failures ? 1 : 0;
}
