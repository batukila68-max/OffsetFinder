#pragma once
// Export helpers shared by the DLL overlay and the analyzer EXE:
// render hits as JSON (cs2-dumper style), as a C++ header, or plain lines.
#include "Types.h"
#include <string>
#include <vector>

namespace of {

struct ExportRow {
  std::string name;    // label user gave or auto "dwXXX"
  Address address = 0; // absolute VA
  std::string module;  // owning module name, "" if none
  uint64_t offset = 0; // address - module base
};

std::string RowsToJson(const std::vector<ExportRow> &rows);
std::string RowsToHeader(const std::vector<ExportRow> &rows);
std::string RowsToLines(const std::vector<ExportRow> &rows);

} // namespace of
