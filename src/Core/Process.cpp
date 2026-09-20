#include "Process.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <cstring>

namespace of {

std::vector<ProcessInfo> ListProcesses() {
  std::vector<ProcessInfo> out;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return out;
  PROCESSENTRY32W pe{sizeof(pe)};
  if (Process32FirstW(snap, &pe)) {
    do {
      ProcessInfo pi;
      pi.pid = pe.th32ProcessID;
      int len = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nullptr, 0,
                                    nullptr, nullptr);
      if (len > 0) {
        std::string s(len - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, s.data(), len,
                            nullptr, nullptr);
        pi.name = std::move(s);
      }
      out.push_back(std::move(pi));
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  // attach window titles
  struct Ctx { std::vector<ProcessInfo> *list; } ctx{&out};
  EnumWindows(
      [](HWND hwnd, LPARAM lp) -> BOOL {
        auto *c = (Ctx *)lp;
        if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER))
          return TRUE;
        wchar_t t[256];
        int n = GetWindowTextW(hwnd, t, 256);
        if (!n) return TRUE;
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        for (auto &p : *c->list) {
          if (p.pid != pid || !p.title.empty()) continue;
          int len = WideCharToMultiByte(CP_UTF8, 0, t, n, nullptr, 0, nullptr,
                                        nullptr);
          if (len > 0) {
            p.title.resize(len);
            WideCharToMultiByte(CP_UTF8, 0, t, n, p.title.data(), len, nullptr,
                                nullptr);
          }
          break;
        }
        return TRUE;
      },
      (LPARAM)&ctx);
  std::sort(out.begin(), out.end(),
            [](const ProcessInfo &a, const ProcessInfo &b) {
              if (!a.title.empty() != !b.title.empty())
                return !a.title.empty();
              return a.name < b.name;
            });
  return out;
}

bool InternalReader::Read(Address address, void *out, size_t size) {
  // VirtualQuery guard instead of __try/__except so MinGW builds work too:
  // only copy ranges that are committed and readable (not NOACCESS/GUARD).
  Address end = address + size;
  for (Address p = address; p < end;) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi)) || !mbi.RegionSize)
      return false;
    const DWORD prot = mbi.Protect & 0xFF;
    const bool readable =
        mbi.State == MEM_COMMIT && prot != PAGE_NOACCESS &&
        !(mbi.Protect & PAGE_GUARD);
    if (!readable) return false;
    p = (Address)mbi.BaseAddress + mbi.RegionSize;
  }
  memcpy(out, (const void *)address, size);
  return true;
}

ExternalReader::ExternalReader() = default;
ExternalReader::~ExternalReader() { Close(); }

bool ExternalReader::Open(uint32_t p) {
  Close();
  handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, p);
  if (!handle)
    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                         FALSE, p);
  pid = handle ? p : 0;
  return handle != nullptr;
}

void ExternalReader::Close() {
  if (handle) CloseHandle(handle);
  handle = nullptr;
  pid = 0;
}

bool ExternalReader::IsValid() const { return handle != nullptr; }

bool ExternalReader::Read(Address address, void *out, size_t size) {
  if (!handle) return false;
  SIZE_T got = 0;
  return ReadProcessMemory(handle, (LPCVOID)address, out, size, &got) &&
         got == size;
}

static DWORD SnapPid(IReader &r) {
  if (auto *ext = dynamic_cast<ExternalReader *>(&r)) return ext->Pid();
  return GetCurrentProcessId();
}

std::vector<Module> ListModules(IReader &reader) {
  std::vector<Module> out;
  DWORD pid = SnapPid(reader);
  HANDLE snap = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE) return out;
  MODULEENTRY32W me{sizeof(me)};
  if (Module32FirstW(snap, &me)) {
    do {
      Module m;
      m.base = (Address)me.modBaseAddr;
      m.size = me.modBaseSize;
      int len = WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, nullptr, 0,
                                    nullptr, nullptr);
      if (len > 0) {
        m.name.resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, m.name.data(), len,
                            nullptr, nullptr);
      }
      len = WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, nullptr, 0,
                               nullptr, nullptr);
      if (len > 0) {
        m.path.resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, m.path.data(), len,
                            nullptr, nullptr);
      }
      out.push_back(std::move(m));
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return out;
}

std::vector<Region> ListRegions(IReader &reader) {
  std::vector<Region> out;
  const auto mods = ListModules(reader);
  auto *ext = dynamic_cast<ExternalReader *>(&reader);
  Address addr = 0;
  const Address ceiling = 0x00007FFFFFF8FFFFULL;
  while (addr < ceiling) {
    MEMORY_BASIC_INFORMATION64 mbi{};
    SIZE_T n = ext
        ? VirtualQueryEx(ext->Handle(), (LPCVOID)addr,
                         (MEMORY_BASIC_INFORMATION *)&mbi, sizeof(mbi))
        : VirtualQuery((LPCVOID)addr, (MEMORY_BASIC_INFORMATION *)&mbi,
                       sizeof(mbi));
    if (!n) {
      addr += 0x1000;
      continue;
    }
    Region r;
    r.base = (Address)mbi.BaseAddress;
    r.size = (size_t)mbi.RegionSize;
    r.protect = (uint32_t)mbi.Protect;
    r.state = (uint32_t)mbi.State;
    r.type = (uint32_t)mbi.Type;
    if (r.size == 0) break;
    if (r.state == MEM_COMMIT) {
      for (const Module &m : mods) {
        if (r.base >= m.base && r.base < m.base + m.size) {
          r.tag = m.name;
          break;
        }
      }
      out.push_back(std::move(r));
    }
    addr = r.base + r.size;
  }
  return out;
}

std::string ResolveAddress(const std::vector<Module> &mods, Address addr) {
  for (const Module &m : mods) {
    if (addr >= m.base && addr < m.base + m.size) {
      char buf[256];
      std::snprintf(buf, sizeof(buf), "%s+0x%llX", m.name.c_str(),
                    (unsigned long long)(addr - m.base));
      return buf;
    }
  }
  char buf[64];
  std::snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)addr);
  return buf;
}

} // namespace of

#else // !_WIN32 — host-test stubs; the real tool is Windows-only today.

#include <cstdio>
#include <cstring>
namespace of {
std::vector<ProcessInfo> ListProcesses() { return {}; }
bool InternalReader::Read(Address a, void *out, size_t n) {
  std::memcpy(out, (const void *)(uintptr_t)a, n);
  return true;
}
ExternalReader::ExternalReader() = default;
ExternalReader::~ExternalReader() = default;
bool ExternalReader::Open(uint32_t) { return false; }
void ExternalReader::Close() {}
bool ExternalReader::IsValid() const { return false; }
bool ExternalReader::Read(Address, void *, size_t) { return false; }
std::vector<Module> ListModules(IReader &) { return {}; }
std::vector<Region> ListRegions(IReader &) { return {}; }
std::string ResolveAddress(const std::vector<Module> &mods, Address addr) {
  for (const Module &m : mods) {
    if (addr >= m.base && addr < m.base + m.size) {
      char buf[256];
      std::snprintf(buf, sizeof(buf), "%s+0x%llX", m.name.c_str(),
                    (unsigned long long)(addr - m.base));
      return buf;
    }
  }
  char buf[64];
  std::snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)addr);
  return buf;
}
} // namespace of
#endif // _WIN32
