#pragma once
// Shared types for the scanning engine. The engine is agnostic to how memory
// is read (internal memcpy inside the injected DLL vs ReadProcessMemory in the
// external analyzer) — callers provide an IReader implementation.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace of {

using Address = uint64_t;

struct Region {
  Address base = 0;
  size_t size = 0;
  uint32_t protect = 0;   // PAGE_* on Windows, VMA flags on Linux
  uint32_t state = 0;     // MEM_COMMIT etc.
  uint32_t type = 0;      // MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED
  std::string tag;        // module name or mapping label when known
};

struct Module {
  std::string name; // "client.dll"
  std::string path;
  Address base = 0;
  size_t size = 0;
};

// Minimal read interface so the engine works for both the injected DLL
// (direct memcpy) and the external analyzer (ReadProcessMemory), and for
// host-side unit tests (buffer-backed fake).
class IReader {
public:
  virtual ~IReader() = default;
  virtual bool Read(Address address, void *out, size_t size) = 0;
  virtual bool IsValid() const = 0;
};

// Reads a region in chunks, skipping sub-ranges that fail. Returns bytes read.
size_t ReadRegionChunks(IReader &reader, Address base, size_t size,
                        std::vector<uint8_t> &out,
                        std::vector<bool> *validMap = nullptr,
                        size_t chunkSize = 64 * 1024);

} // namespace of
