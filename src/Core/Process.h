#pragma once
// OS-facing layer: process enumeration, open/attach, module + region lists,
// and the two IReader implementations. Windows-only parts live behind
// _WIN32; on other platforms the external reader returns false so the code
// still compiles for host tests.
#include "Types.h"
#include <memory>
#include <string>
#include <vector>

namespace of {

struct ProcessInfo {
  uint32_t pid = 0;
  std::string name;   // exe basename, e.g. "cs2.exe"
  std::string title;  // main window title when present
};

// Lists running processes (Windows: Toolhelp32 + window titles).
std::vector<ProcessInfo> ListProcesses();

// Reader over the address space this code runs in (used by the injected DLL).
class InternalReader final : public IReader {
public:
  bool Read(Address address, void *out, size_t size) override;
  bool IsValid() const override { return true; }
};

// Reader over a foreign process (used by the analyzer EXE).
class ExternalReader final : public IReader {
public:
  ExternalReader();
  ~ExternalReader() override;
  bool Open(uint32_t pid);
  void Close();
  bool Read(Address address, void *out, size_t size) override;
  bool IsValid() const override;
  uint32_t Pid() const { return pid; }
  void *Handle() const { return handle; }
private:
  void *handle = nullptr;
  uint32_t pid = 0;
};

// Enumerates loaded modules of the target. For InternalReader pass nullptr
// to mean "this process".
std::vector<Module> ListModules(IReader &reader);
// Enumerates committed memory regions of the target.
std::vector<Region> ListRegions(IReader &reader);
// Resolves an absolute VA to "module+0x1234" when it lands inside a module.
std::string ResolveAddress(const std::vector<Module> &mods, Address addr);

} // namespace of
