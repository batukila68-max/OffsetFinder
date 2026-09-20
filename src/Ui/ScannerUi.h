#pragma once
// ImGui front-end shared by the standalone analyzer EXE and the injected DLL
// overlay. The host supplies an IReader (external RPM or internal memcpy) and
// calls Draw() every frame.
#include "../Core/Pattern.h"
#include "../Core/PointerChain.h"
#include "../Core/Process.h"
#include "../Core/Scanner.h"
#include "../Core/SigScan.h"
#include "../Core/Export.h"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace of {

class ScannerUi {
public:
  ~ScannerUi() { StopTask(); }

  // external=false -> DLL overlay (reader = this process)
  // external=true  -> analyzer EXE (reader = attached process)
  void Draw(bool external);

  // EXE: called when the user picks a different process.
  void SetReader(IReader *r);
  IReader *GetReader() const { return reader; }

private:
  void DrawScannerTab();
  void DrawSignatureTab();
  void DrawModulesTab();
  void DrawPointerTab();
  void DrawExportTab();
  void StartTask(std::function<void()> fn);
  void StopTask();
  void CollectRow(const char *name, Address addr);

  IReader *reader = nullptr;
  double now = 0;
  std::vector<Module> modules;
  std::vector<Region> regions;
  double regionsLoadedAt = 0;

  // value scan state
  std::unique_ptr<Scanner> scanner;
  char valueText[128] = "100";
  char valueText2[128] = "";
  int valueTypeIdx = 2;   // U32
  int scanTypeIdx = 0;    // Exact
  int nextFilterIdx = 1;  // Changed
  bool valueHex = false;
  size_t showHits = 500;
  double lastValueRefresh = 0;

  // signature scan state
  char patternText[512] = "";
  char moduleFilter[128] = "";
  int relOffset = -1;
  int instrSize = 7;
  bool autoResolve = true;
  std::vector<SigHit> sigHits;

  // pointer chain state
  char chainBase[256] = "";
  char chainOffsets[256] = "0";
  char chainResult[128] = "";

  // export
  std::vector<ExportRow> rows;
  char exportName[128] = "dwOffset";

  // async task plumbing
  std::thread worker;
  std::atomic<double> progress{0};
  std::atomic<bool> cancel{false};
  std::atomic<bool> busy{false};
  std::string status = "idle";
  std::mutex statusMtx;
};

void DrawScannerUi(ScannerUi &ui, bool external);

} // namespace of
