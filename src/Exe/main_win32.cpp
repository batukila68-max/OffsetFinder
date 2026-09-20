// OffsetFinder.exe — standalone external analyzer.
// Win32 + DX11 + ImGui window; attaches to any process via OpenProcess and
// scans its memory with ReadProcessMemory.
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <d3d11.h>
#include <algorithm>
#include <string>
#include <vector>
#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include "../Core/Process.h"
#include "../Ui/ScannerUi.h"

static ID3D11Device *device = nullptr;
static ID3D11DeviceContext *context = nullptr;
static IDXGISwapChain *swapChain = nullptr;
static ID3D11RenderTargetView *target = nullptr;
static UINT resizeW = 0, resizeH = 0;

static void DestroyTarget() {
  if (target) { target->Release(); target = nullptr; }
}
static bool CreateTarget() {
  ID3D11Texture2D *back = nullptr;
  if (FAILED(swapChain->GetBuffer(0, IID_PPV_ARGS(&back)))) return false;
  HRESULT hr = device->CreateRenderTargetView(back, nullptr, &target);
  back->Release();
  return SUCCEEDED(hr);
}
static void Cleanup() {
  DestroyTarget();
  if (swapChain) swapChain->Release();
  if (context) context->Release();
  if (device) device->Release();
}
static bool CreateDevice(HWND window) {
  DXGI_SWAP_CHAIN_DESC sd{};
  sd.BufferCount = 2;
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = window;
  sd.SampleDesc.Count = 1;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
  const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0,
                                      D3D_FEATURE_LEVEL_10_0};
  D3D_FEATURE_LEVEL level;
  HRESULT hr = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
      D3D11_SDK_VERSION, &sd, &swapChain, &device, &level, &context);
  if (hr == DXGI_ERROR_UNSUPPORTED)
    hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
                                       0, levels, 2, D3D11_SDK_VERSION, &sd,
                                       &swapChain, &device, &level, &context);
  return SUCCEEDED(hr) && CreateTarget();
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT,
                                                           WPARAM, LPARAM);
static LRESULT WINAPI WndProc(HWND h, UINT msg, WPARAM w, LPARAM l) {
  if (ImGui_ImplWin32_WndProcHandler(h, msg, w, l)) return 1;
  switch (msg) {
  case WM_SIZE:
    if (w != SIZE_MINIMIZED) { resizeW = LOWORD(l); resizeH = HIWORD(l); }
    return 0;
  case WM_SYSCOMMAND:
    if ((w & 0xfff0) == SC_KEYMENU) return 0;
    break;
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(h, msg, w, l);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
  WNDCLASSEXW wc{sizeof(wc),  CS_CLASSDC, WndProc, 0, 0, instance,
                 nullptr,     LoadCursor(nullptr, IDC_ARROW),
                 nullptr,     nullptr, L"OffsetFinderUI", nullptr};
  RegisterClassExW(&wc);
  RECT r = {0, 0, 980, 640};
  AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
  HWND hwnd = CreateWindowW(
      wc.lpszClassName, L"OffsetFinder", WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top,
      nullptr, nullptr, instance, nullptr);
  if (!hwnd || !CreateDevice(hwnd)) {
    MessageBoxW(nullptr, L"DirectX 11 init failed.", L"OffsetFinder",
                MB_OK | MB_ICONERROR);
    return 1;
  }
  ImGui::CreateContext();
  ImGuiIO &io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  ImGui::StyleColorsDark();
  ImGui_ImplWin32_Init(hwnd);
  ImGui_ImplDX11_Init(device, context);
  ShowWindow(hwnd, SW_SHOWDEFAULT);
  UpdateWindow(hwnd);

  of::ExternalReader reader;
  of::ScannerUi ui;
  std::vector<of::ProcessInfo> procs;
  char procFilter[128] = "";
  int selected = -1;
  double lastRefresh = 0;
  char status[128] = "no process attached";

  bool done = false;
  while (!done) {
    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
      if (msg.message == WM_QUIT) done = true;
    }
    if (done) break;
    if (IsIconic(hwnd)) { Sleep(20); continue; }
    if (resizeW && resizeH) {
      DestroyTarget();
      swapChain->ResizeBuffers(0, resizeW, resizeH, DXGI_FORMAT_UNKNOWN, 0);
      resizeW = resizeH = 0;
      CreateTarget();
    }
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::Begin("##main", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

    // --- process attach bar ---
    ImGui::InputTextWithHint("filter", "process name...", procFilter,
                             sizeof(procFilter));
    ImGui::SameLine();
    if (ImGui::Button("refresh") || (procs.empty() &&
        ImGui::GetTime() - lastRefresh > 1.0)) {
      procs = of::ListProcesses();
      lastRefresh = ImGui::GetTime();
    }
    ImGui::SameLine();
    std::string preview = selected >= 0 && selected < (int)procs.size()
        ? procs[selected].name + " (" + std::to_string(procs[selected].pid) + ")"
        : "<none>";
    if (ImGui::BeginCombo("process", preview.c_str())) {
      for (int i = 0; i < (int)procs.size(); ++i) {
        if (procFilter[0] &&
            procs[i].name.find(procFilter) == std::string::npos &&
            procs[i].title.find(procFilter) == std::string::npos)
          continue;
        std::string label = procs[i].name;
        if (!procs[i].title.empty()) label += "  —  " + procs[i].title;
        label += "##" + std::to_string(procs[i].pid);
        if (ImGui::Selectable(label.c_str(), i == selected))
          selected = i;
      }
      ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button("attach") && selected >= 0) {
      if (reader.Open(procs[selected].pid)) {
        ui.SetReader(&reader);
        std::snprintf(status, sizeof(status), "attached: %s (pid %u)",
                      procs[selected].name.c_str(), procs[selected].pid);
      } else {
        std::snprintf(status, sizeof(status),
                      "OpenProcess failed for pid %u (run as admin / wrong arch?)",
                      procs[selected].pid);
      }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%s", status);
    ImGui::Separator();

    of::DrawScannerUi(ui, true);
    ImGui::End();

    ImGui::Render();
    const float clear[] = {0.07f, 0.07f, 0.07f, 1.f};
    context->OMSetRenderTargets(1, &target, nullptr);
    context->ClearRenderTargetView(target, clear);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    HRESULT hr = swapChain->Present(1, 0);
    if (hr == DXGI_STATUS_OCCLUDED) Sleep(20);
    if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET) break;
  }
  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();
  Cleanup();
  DestroyWindow(hwnd);
  UnregisterClassW(wc.lpszClassName, instance);
  return 0;
}
