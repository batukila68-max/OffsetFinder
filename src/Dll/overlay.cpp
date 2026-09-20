// Injected overlay host: hooks IDXGISwapChain::Present of the game process
// and renders the OffsetFinder UI inside the game's frame. Input comes through
// a WndProc hook on the game window. INSERT toggles, END unloads.
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <algorithm>
#include <cstdio>
#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include "MinHook.h"
#include "../Core/Process.h"
#include "../Ui/ScannerUi.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT,
                                                           WPARAM, LPARAM);

namespace {
typedef HRESULT(STDMETHODCALLTYPE *PresentFn)(IDXGISwapChain *, UINT, UINT);
typedef HRESULT(STDMETHODCALLTYPE *ResizeFn)(IDXGISwapChain *, UINT, UINT,
                                           UINT, DXGI_FORMAT, UINT);
PresentFn oPresent = nullptr;
ResizeFn oResize = nullptr;
ID3D11Device *device = nullptr;
ID3D11DeviceContext *context = nullptr;
ID3D11RenderTargetView *target = nullptr;
HWND gameWindow = nullptr;
WNDPROC oWndProc = nullptr;
bool ready = false;
bool visible = true;
bool wantUnload = false;
HMODULE selfModule = nullptr;
of::InternalReader reader;
of::ScannerUi *ui = nullptr;

bool BlockInput(UINT msg, const ImGuiIO &io) {
  if (msg == WM_SETCURSOR) return true;
  switch (msg) {
  case WM_LBUTTONDOWN: case WM_LBUTTONUP: case WM_LBUTTONDBLCLK:
  case WM_RBUTTONDOWN: case WM_RBUTTONUP: case WM_RBUTTONDBLCLK:
  case WM_MBUTTONDOWN: case WM_MBUTTONUP: case WM_MBUTTONDBLCLK:
  case WM_XBUTTONDOWN: case WM_XBUTTONUP: case WM_XBUTTONDBLCLK:
  case WM_MOUSEWHEEL:
#ifdef WM_MOUSEHWHEEL
  case WM_MOUSEHWHEEL:
#endif
  case WM_MOUSEMOVE:
    return true;
  default: break;
  }
  if (msg == WM_KEYDOWN || msg == WM_KEYUP || msg == WM_SYSKEYDOWN ||
      msg == WM_SYSKEYUP || msg == WM_CHAR)
    return io.WantCaptureKeyboard || io.WantTextInput;
  return false;
}

LRESULT CALLBACK WndProcHook(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
  if (ready) {
    if (msg == WM_KEYUP && (w == VK_INSERT || w == VK_F11))
      visible = !visible;
    if (msg == WM_KEYUP && w == VK_END)
      wantUnload = true;
    if (visible && msg == WM_SETCURSOR) {
      SetCursor(LoadCursor(nullptr, IDC_ARROW));
      return 1;
    }
    ImGui_ImplWin32_WndProcHandler(hwnd, msg, w, l);
    if (visible && msg == WM_INPUT) {
      DefWindowProcW(hwnd, msg, w, l);
      return 0;
    }
    if (visible && BlockInput(msg, ImGui::GetIO()))
      return 1;
  }
  return CallWindowProcW(oWndProc, hwnd, msg, w, l);
}

void CreateTarget(IDXGISwapChain *sc) {
  ID3D11Texture2D *back = nullptr;
  if (SUCCEEDED(sc->GetBuffer(0, __uuidof(ID3D11Texture2D), (void **)&back))) {
    device->CreateRenderTargetView(back, nullptr, &target);
    back->Release();
  }
}

void InitOnce(IDXGISwapChain *sc) {
  DXGI_SWAP_CHAIN_DESC desc{};
  sc->GetDesc(&desc);
  gameWindow = desc.OutputWindow;
  sc->GetDevice(__uuidof(ID3D11Device), (void **)&device);
  device->GetImmediateContext(&context);
  CreateTarget(sc);

  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  io.IniFilename = nullptr;
  io.LogFilename = nullptr;
  ImGui::StyleColorsDark();
  ImGui_ImplWin32_Init(gameWindow);
  ImGui_ImplDX11_Init(device, context);

  ui = new of::ScannerUi();
  ui->SetReader(&reader); // internal reader scans the host process directly
  oWndProc = (WNDPROC)SetWindowLongPtrW(gameWindow, GWLP_WNDPROC,
                                      (LONG_PTR)WndProcHook);
  ready = true;
}

void Unload() {
  // Remove the hook first so no new Present call enters our frame path,
  // then let one in-flight frame settle before tearing down D3D objects.
  ready = false;
  MH_DisableHook(MH_ALL_HOOKS);
  Sleep(100);
  if (gameWindow && oWndProc)
    SetWindowLongPtrW(gameWindow, GWLP_WNDPROC, (LONG_PTR)oWndProc);
  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  if (ImGui::GetCurrentContext()) ImGui::DestroyContext();
  if (target) { target->Release(); target = nullptr; }
  if (context) { context->Release(); context = nullptr; }
  if (device) { device->Release(); device = nullptr; }
  delete ui;
  ui = nullptr;
  MH_Uninitialize();
  FreeLibraryAndExitThread(selfModule, 0);
}

HRESULT STDMETHODCALLTYPE HookPresent(IDXGISwapChain *sc, UINT sync,
                                      UINT flags) {
  if (!ready)
    InitOnce(sc);
  if (ready && device && context && target) {
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    if (visible && ui) {
      RECT rc{};
      GetClientRect(gameWindow, &rc);
      ImGui::SetNextWindowSize(ImVec2(860, 560), ImGuiCond_FirstUseEver);
      ImGui::Begin("OffsetFinder", &visible, ImGuiWindowFlags_NoCollapse);
      of::DrawScannerUi(*ui, false);
      ImGui::End();
    }
    ImGui::Render();
    context->OMSetRenderTargets(1, &target, nullptr);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
  }
  HRESULT hr = oPresent(sc, sync, flags);
  if (wantUnload) {
    wantUnload = false;
    CreateThread(nullptr, 0,
                 [](LPVOID) -> DWORD { Unload(); return 0; }, nullptr, 0,
                 nullptr);
  }
  return hr;
}

HRESULT STDMETHODCALLTYPE HookResize(IDXGISwapChain *sc, UINT count, UINT w,
                                     UINT h, DXGI_FORMAT format, UINT flags) {
  if (target) { target->Release(); target = nullptr; }
  HRESULT hr = oResize(sc, count, w, h, format, flags);
  if (SUCCEEDED(hr) && device) CreateTarget(sc);
  return hr;
}

HWND FindGameWindow() {
  struct Ctx { DWORD pid; HWND best; } ctx{GetCurrentProcessId(), nullptr};
  EnumWindows(
      [](HWND hwnd, LPARAM lp) -> BOOL {
        auto *c = (Ctx *)lp;
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != c->pid || !IsWindowVisible(hwnd) ||
            GetWindow(hwnd, GW_OWNER) || GetWindowTextLengthW(hwnd) == 0)
          return TRUE;
        RECT a{}, b{};
        GetWindowRect(hwnd, &a);
        if (c->best) GetWindowRect(c->best, &b);
        long area = (a.right - a.left) * (a.bottom - a.top),
             bestArea = (b.right - b.left) * (b.bottom - b.top);
        if (!c->best || area > bestArea) c->best = hwnd;
        return TRUE;
      },
      (LPARAM)&ctx);
  return ctx.best;
}

DWORD WINAPI InstallThread(LPVOID) {
  HWND host = nullptr;
  for (int i = 0; i < 600 && !host; i++) {
    host = FindGameWindow();
    if (!host) Sleep(500);
  }
  if (!host) return 1;

  // Temporary device+swapchain to read the shared vtable addresses.
  WNDCLASSEXW wc{sizeof(wc), CS_CLASSDC, DefWindowProcW,
                 0,          0,          GetModuleHandleW(nullptr),
                 nullptr,    nullptr,    nullptr,
                 nullptr,    L"OffsetFinderHookWindow", nullptr};
  RegisterClassExW(&wc);
  HWND temp = CreateWindowW(wc.lpszClassName, L"", WS_OVERLAPPED, 0, 0, 8, 8,
                            nullptr, nullptr, wc.hInstance, nullptr);
  DXGI_SWAP_CHAIN_DESC sd{};
  sd.BufferCount = 1;
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = temp;
  sd.SampleDesc.Count = 1;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
  IDXGISwapChain *sc = nullptr;
  ID3D11Device *dev = nullptr;
  ID3D11DeviceContext *ctx = nullptr;
  D3D_FEATURE_LEVEL level;
  D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
  HRESULT hr = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
      D3D11_SDK_VERSION, &sd, &sc, &dev, &level, &ctx);
  if (FAILED(hr))
    hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2,
        D3D11_SDK_VERSION, &sd, &sc, &dev, &level, &ctx);
  if (FAILED(hr)) return 2;
  void **vt = *(void ***)sc;
  void *present = vt[8];
  void *resize = vt[13];
  sc->Release();
  dev->Release();
  ctx->Release();
  DestroyWindow(temp);
  UnregisterClassW(wc.lpszClassName, wc.hInstance);

  if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED)
    return 3;
  MH_CreateHook(present, (LPVOID)&HookPresent, (void **)&oPresent);
  MH_CreateHook(resize, (LPVOID)&HookResize, (void **)&oResize);
  MH_EnableHook(MH_ALL_HOOKS);
  return 0;
}
} // namespace

void OffsetFinderInstall(HMODULE self) {
  selfModule = self;
  // Pin the module so FreeLibrary from a loader can't drop it under us.
  HMODULE pin = nullptr;
  GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                         GET_MODULE_HANDLE_EX_FLAG_PIN,
                     (LPCWSTR)self, &pin);
  CreateThread(nullptr, 0, InstallThread, nullptr, 0, nullptr);
}
