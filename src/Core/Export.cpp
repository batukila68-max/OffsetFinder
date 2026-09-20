#include "Export.h"
#include <cctype>
#include <cstdio>
#include <sstream>

namespace of {

static std::string Sanitize(const std::string &s) {
  std::string r;
  for (char c : s)
    r += (isalnum((unsigned char)c) || c == '_') ? c : '_';
  return r;
}

std::string RowsToJson(const std::vector<ExportRow> &rows) {
  std::ostringstream o;
  o << "{\n";
  std::string lastMod;
  bool first = true;
  for (const ExportRow &r : rows) {
    if (!first) o << ",\n";
    first = false;
    if (r.module != lastMod) {
      lastMod = r.module;
      o << "  // " << (lastMod.empty() ? "<no module>" : lastMod) << "\n";
    }
    o << "  \"" << (r.name.empty() ? Sanitize(r.module) : r.name) << "\": "
      << r.offset;
  }
  o << "\n}\n";
  return o.str();
}

std::string RowsToHeader(const std::vector<ExportRow> &rows) {
  std::ostringstream o;
  o << "#pragma once\n#include <cstdint>\n\nnamespace offsets {\n";
  for (const ExportRow &r : rows) {
    char line[256];
    std::snprintf(line, sizeof(line),
                  "constexpr uintptr_t %s = 0x%llX; // %s+0x%llX",
                  Sanitize(r.name.empty() ? "offset" : r.name).c_str(),
                  (unsigned long long)r.offset, r.module.c_str(),
                  (unsigned long long)r.offset);
    o << line << "\n";
  }
  o << "} // namespace offsets\n";
  return o.str();
}

std::string RowsToLines(const std::vector<ExportRow> &rows) {
  std::ostringstream o;
  for (const ExportRow &r : rows) {
    char line[320];
    std::snprintf(line, sizeof(line), "%s = %s+0x%llX (VA 0x%llX)",
                  r.name.empty() ? "offset" : r.name.c_str(),
                  r.module.empty() ? "?" : r.module.c_str(),
                  (unsigned long long)r.offset, (unsigned long long)r.address);
    o << line << "\n";
  }
  return o.str();
}

} // namespace of
