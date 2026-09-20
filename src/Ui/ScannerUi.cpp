#include "ScannerUi.h"
#include "imgui.h"
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace of {

static const char *kValueTypes[] = {"u8",  "i8",    "u16", "i16",   "u32",
                                    "i32", "u64",   "i64", "float", "double",
                                    "bytes", "string", "wstring"};
static const char *kScanTypes[] = {"exact", "greater than", "less than",
                                   "between", "unknown initial"};
static const char *kNextFilters[] = {"exact value", "unchanged", "changed",
                                     "increased", "decreased"};

static ValueType VT(int i) {
  static const ValueType t[] = {ValueType::U8,  ValueType::I8,
                                ValueType::U16, ValueType::I16,
                                ValueType::U32, ValueType::I32,
                                ValueType::U64, ValueType::I64,
                                ValueType::F32, ValueType::F64,
                                ValueType::Bytes, ValueType::StringA,
                                ValueType::StringW};
  return t[i < 0 ? 0 : (i > 12 ? 12 : i)];
}

void ScannerUi::SetReader(IReader *r) {
  reader = r;
  modules.clear();
  regions.clear();
  scanner.reset();
  sigHits.clear();
  regionsLoadedAt = 0;
}

void ScannerUi::StartTask(std::function<void()> fn) {
  StopTask();
  cancel = false;
  progress = 0;
  busy = true;
  worker = std::thread([this, fn] {
    fn();
    busy = false;
  });
}

void ScannerUi::StopTask() {
  if (worker.joinable()) {
    cancel = true;
    worker.join();
  }
}

static void StatusLine(const std::string &s, double p, bool busy,
                       std::atomic<bool> &cancelFlag) {
  ImGui::TextUnformatted(s.c_str());
  if (busy) {
    ImGui::SameLine();
    ImGui::ProgressBar((float)p, ImVec2(180, 0));
    ImGui::SameLine();
    if (ImGui::SmallButton("cancel")) cancelFlag = true;
  }
}

void ScannerUi::Draw(bool external) {
  if (!reader) {
    ImGui::TextUnformatted("Attach to a process first.");
    return;
  }
  now = ImGui::GetTime();
  if (regions.empty() || now - regionsLoadedAt > 5.0) {
    regions = ListRegions(*reader);
    if (modules.empty()) modules = ListModules(*reader);
    regionsLoadedAt = now;
  }
  if (ImGui::BeginTabBar("of_tabs")) {
    if (ImGui::BeginTabItem("Scanner")) {
      DrawScannerTab();
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Signatures")) {
      DrawSignatureTab();
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Modules")) {
      DrawModulesTab();
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Pointer chain")) {
      DrawPointerTab();
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Export")) {
      DrawExportTab();
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
  StatusLine(status, progress, busy, cancel);
}

void ScannerUi::DrawScannerTab() {
  ImGui::Combo("type", &valueTypeIdx, kValueTypes, IM_ARRAYSIZE(kValueTypes));
  ImGui::SameLine();
  ImGui::Checkbox("hex", &valueHex);
  const bool needsValue = scanTypeIdx != 4;
  if (needsValue) {
    ImGui::InputText("value", valueText, sizeof(valueText));
    if (scanTypeIdx == 3)
      ImGui::InputText("to", valueText2, sizeof(valueText2));
  }
  ImGui::Combo("scan", &scanTypeIdx, kScanTypes, IM_ARRAYSIZE(kScanTypes));

  const bool haveScanner = scanner && scanner->HitCount() > 0;
  if (ImGui::Button("first scan") && !busy) {
    ScanValue v{VT(valueTypeIdx), valueText, valueText2, valueHex};
    auto regs = regions;
    IReader *r = reader;
    Scanner *sc = (scanner = std::make_unique<Scanner>(*r, regs)).get();
    StartTask([this, sc, v]() {
      {
        std::lock_guard<std::mutex> l(statusMtx);
        status = "first scan running";
      }
      int st = scanTypeIdx;
      sc->FirstScan(v, (ScanType)st, [this](double p) {
        progress = p;
        return !cancel.load();
      });
      std::lock_guard<std::mutex> l(statusMtx);
      char b[96];
      std::snprintf(b, sizeof(b), "%zu hits", sc->HitCount());
      status = b;
    });
  }
  ImGui::SameLine();
  if (haveScanner) {
    ImGui::Combo("filter", &nextFilterIdx, kNextFilters,
                 IM_ARRAYSIZE(kNextFilters));
    ImGui::SameLine();
    if (ImGui::Button("next scan") && !busy) {
      ScanValue v{VT(valueTypeIdx), valueText, valueText2, valueHex};
      Scanner *sc = scanner.get();
      StartTask([this, sc, v]() {
        sc->NextScan(v, (NextFilter)nextFilterIdx, [this](double p) {
          progress = p;
          return !cancel.load();
        });
        std::lock_guard<std::mutex> l(statusMtx);
        char b[96];
        std::snprintf(b, sizeof(b), "%zu hits", sc->HitCount());
        status = b;
      });
    }
    ImGui::SameLine();
    if (ImGui::Button("reset")) scanner.reset();
  }

  if (!haveScanner) {
    ImGui::TextUnformatted(
        "Pick a type + value, run a first scan, then narrow with next scans.");
    return;
  }
  if (now - lastValueRefresh > 0.5) {
    scanner->RefreshValues(showHits);
    lastValueRefresh = now;
  }
  ImGui::Separator();
  ImGui::Text("hits: %zu (showing %zu)", scanner->HitCount(),
              std::min(showHits, scanner->HitCount()));
  ImGui::SameLine();
  ImGui::SetNextItemWidth(120);
  ImGui::InputScalar("max", ImGuiDataType_U64, &showHits);

  if (ImGui::BeginTable("hits", 4,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_Resizable,
                        ImVec2(0, 320))) {
    ImGui::TableSetupColumn("address");
    ImGui::TableSetupColumn("module+offset");
    ImGui::TableSetupColumn("value");
    ImGui::TableSetupColumn("actions");
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin((int)std::min(showHits, scanner->HitCount()));
    while (clip.Step()) {
      for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
        const ScanHit &h = scanner->Hits()[i];
        ImGui::PushID(i);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        char a[32];
        std::snprintf(a, sizeof(a), "0x%llX", (unsigned long long)h.address);
        ImGui::TextUnformatted(a);
        ImGui::TableNextColumn();
        std::string r = ResolveAddress(modules, h.address);
        ImGui::TextUnformatted(r.c_str());
        ImGui::TableNextColumn();
        if (valueTypeIdx == 8 || valueTypeIdx == 9)
          ImGui::Text("%.6g", h.f64);
        else if (valueHex)
          ImGui::Text("0x%llX", (unsigned long long)h.u64);
        else
          ImGui::Text("%lld", (long long)h.u64);
        ImGui::TableNextColumn();
        if (ImGui::SmallButton("copy off"))
          ImGui::SetClipboardText(r.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("+export"))
          CollectRow(exportName, h.address);
        ImGui::PopID();
      }
    }
    ImGui::EndTable();
  }
}

void ScannerUi::DrawSignatureTab() {
  ImGui::InputTextWithHint("pattern", "48 8B 05 ? ? ? ? 48 89", patternText,
                           sizeof(patternText));
  ImGui::InputTextWithHint("module filter", "client.dll (empty = all)",
                           moduleFilter, sizeof(moduleFilter));
  ImGui::Checkbox("resolve rel32", &autoResolve);
  if (autoResolve) {
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90);
    ImGui::InputInt("rel off", &relOffset);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90);
    ImGui::InputInt("instr size", &instrSize);
    if (relOffset < 0) relOffset = 3;
  }
  ImGui::SameLine();
  ImGui::TextDisabled("(mov r,[rip+X]: rel=3 size=7)");

  std::vector<PatternByte> pat;
  std::string err;
  const bool patOk = ParsePattern(patternText, pat, err);
  if (!patOk && patternText[0])
    ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "pattern: %s", err.c_str());

  if (ImGui::Button("scan") && patOk && !busy) {
    auto regs = regions;
    IReader *r = reader;
    std::string mf = moduleFilter;
    int ro = autoResolve ? relOffset : -1;
    int is = instrSize;
    StartTask([this, r, regs, pat, mf, ro, is]() {
      {
        std::lock_guard<std::mutex> l(statusMtx);
        status = "signature scan running";
      }
      std::vector<SigHit> out = SigScanRegions(
          *r, regs, pat, mf, ro, is,
          [this](double p) {
            progress = p;
            return !cancel.load();
          });
      sigHits = std::move(out);
      std::lock_guard<std::mutex> l(statusMtx);
      char b[96];
      std::snprintf(b, sizeof(b), "%zu sig hits", sigHits.size());
      status = b;
    });
  }

  if (sigHits.empty()) return;
  ImGui::Separator();
  if (ImGui::BeginTable("sighits", 3,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY,
                        ImVec2(0, 320))) {
    ImGui::TableSetupColumn("match VA");
    ImGui::TableSetupColumn("resolved");
    ImGui::TableSetupColumn("module+offset");
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin((int)sigHits.size());
    while (clip.Step()) {
      for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
        const SigHit &h = sigHits[i];
        ImGui::PushID(i);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("0x%llX", (unsigned long long)h.address);
        ImGui::TableNextColumn();
        if (h.hasResolved) {
          ImGui::Text("0x%llX", (unsigned long long)h.resolved);
        } else ImGui::TextUnformatted("-");
        ImGui::TableNextColumn();
        const Address shown = h.hasResolved ? h.resolved : h.address;
        std::string r = ResolveAddress(modules, shown);
        if (ImGui::SmallButton(r.c_str())) ImGui::SetClipboardText(r.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("+export")) CollectRow(exportName, shown);
        ImGui::PopID();
      }
    }
    ImGui::EndTable();
  }
}

void ScannerUi::DrawModulesTab() {
  if (ImGui::Button("refresh")) {
    modules = ListModules(*reader);
    regions = ListRegions(*reader);
  }
  ImGui::SameLine();
  ImGui::Text("%zu modules", modules.size());
  if (ImGui::BeginTable("mods", 3,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY,
                        ImVec2(0, 400))) {
    ImGui::TableSetupColumn("module");
    ImGui::TableSetupColumn("base");
    ImGui::TableSetupColumn("size");
    ImGui::TableHeadersRow();
    for (const Module &m : modules) {
      ImGui::TableNextRow();
      ImGui::TableNextColumn();
      if (ImGui::SmallButton(m.name.c_str()))
        ImGui::SetClipboardText(m.name.c_str());
      ImGui::TableNextColumn();
      ImGui::Text("0x%llX", (unsigned long long)m.base);
      ImGui::TableNextColumn();
      ImGui::Text("0x%zX", m.size);
    }
    ImGui::EndTable();
  }
}

void ScannerUi::DrawPointerTab() {
  ImGui::InputTextWithHint("base", "client.dll+0x1A2B3C or 0x7FF..", chainBase,
                           sizeof(chainBase));
  ImGui::InputTextWithHint("offsets", "10, 8, 238", chainOffsets,
                           sizeof(chainOffsets));
  if (ImGui::Button("resolve") && reader) {
    Address base = 0;
    std::string b = chainBase;
    auto plus = b.find('+');
    if (plus != std::string::npos) {
      std::string mod = b.substr(0, plus);
      uint64_t off = std::strtoull(b.c_str() + plus + 1, nullptr, 16);
      for (const Module &m : modules)
        if (m.name == mod) base = m.base + off;
    } else {
      base = std::strtoull(b.c_str(), nullptr, 16);
    }
    std::vector<uint32_t> offs;
    {
      char tmp[256];
      std::snprintf(tmp, sizeof(tmp), "%s", chainOffsets);
      for (char *tok = std::strtok(tmp, ", ;"); tok;
           tok = std::strtok(nullptr, ", ;"))
        offs.push_back((uint32_t)std::strtoul(tok, nullptr, 16));
    }
    Address out = 0;
    if (base && ResolvePointerChain(*reader, base, offs, out))
      std::snprintf(chainResult, sizeof(chainResult), "-> 0x%llX (%s)",
                    (unsigned long long)out,
                    ResolveAddress(modules, out).c_str());
    else
      std::snprintf(chainResult, sizeof(chainResult), "failed");
  }
  ImGui::TextUnformatted(chainResult);
}

void ScannerUi::CollectRow(const char *name, Address addr) {
  ExportRow row;
  row.address = addr;
  row.name = name;
  for (const Module &m : modules)
    if (addr >= m.base && addr < m.base + m.size) {
      row.module = m.name;
      row.offset = addr - m.base;
      break;
    }
  rows.push_back(row);
}

void ScannerUi::DrawExportTab() {
  ImGui::InputText("name", exportName, sizeof(exportName));
  ImGui::Text("%zu collected offsets", rows.size());
  if (ImGui::Button("clear")) rows.clear();
  ImGui::SameLine();
  if (ImGui::Button("copy json"))
    ImGui::SetClipboardText(RowsToJson(rows).c_str());
  ImGui::SameLine();
  if (ImGui::Button("copy header"))
    ImGui::SetClipboardText(RowsToHeader(rows).c_str());
  ImGui::SameLine();
  if (ImGui::Button("copy lines"))
    ImGui::SetClipboardText(RowsToLines(rows).c_str());
  if (ImGui::BeginTable("rows", 3, ImGuiTableFlags_Borders |
                                     ImGuiTableFlags_RowBg)) {
    ImGui::TableSetupColumn("name");
    ImGui::TableSetupColumn("module");
    ImGui::TableSetupColumn("offset");
    ImGui::TableHeadersRow();
    for (const ExportRow &r : rows) {
      ImGui::TableNextRow();
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r.name.c_str());
      ImGui::TableNextColumn(); ImGui::TextUnformatted(r.module.c_str());
      ImGui::TableNextColumn();
      ImGui::Text("0x%llX", (unsigned long long)r.offset);
    }
    ImGui::EndTable();
  }
}

void DrawScannerUi(ScannerUi &ui, bool external) { ui.Draw(external); }

} // namespace of
