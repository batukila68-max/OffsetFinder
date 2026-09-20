#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

void OffsetFinderInstall(HMODULE self);

BOOL WINAPI DllMain(HMODULE mod, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(mod);
    OffsetFinderInstall(mod);
  }
  return TRUE;
}
