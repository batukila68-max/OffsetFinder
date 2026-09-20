# OffsetFinder

Универсальный поиск оффсетов для **любой** игры/процесса. Два бинарника:

| Файл | Что это |
|------|---------|
| `OffsetFinder.exe` | Внешний анализатор: выбираешь процесс, читает память через `ReadProcessMemory` |
| `OffsetFinder.dll` | Инжектируемая DLL: оверлей ImGui поверх игры (хук `IDXGISwapChain::Present`), читает память напрямую |

## Возможности

- **Scanner** — поиск значений (u8…u64, float/double, байты, строки ANSI/UTF-16): exact, greater/less, between, unknown initial + next-сканы (unchanged / changed / increased / decreased / exact).
- **Signatures** — IDA-стиль паттерны (`48 8B 05 ? ? ? ?`), фильтр по модулю, авто-резолв rel32 → `module.dll+0xXXXXXX` (классические `dw*` оффсеты).
- **Modules** — список модулей процесса с base/size.
- **Pointer chain** — проверка цепочек `base + off -> ptr + off -> ...` в реальном времени.
- **Export** — собранные оффсеты экспортируются в JSON (формат cs2-dumper), C++ header (`constexpr uintptr_t`) или plain text.

## Использование

**EXE:** запусти от администратора → фильтр процесса → attach → вкладка нужного скана.

**DLL:** инжекти в процесс любым инжектором → **INSERT** открывает/прячет оверлей, **END** выгружает (хуки снимаются).

## Сборка

**Visual Studio 2022 (x64):**
```
cmake -B Build -G "Visual Studio 17 2022" -A x64
cmake --build Build --config Release
```

**MinGW (кросс-компиляция из Linux):**
```
cmake -B Build -DCMAKE_TOOLCHAIN_FILE=mingw-toolchain.cmake
cmake --build Build
```

## Тесты движка (Linux/macOS)

```
cmake -B Build && cmake --build Build && ctest --test-dir Build
```

Стек: C++17, Dear ImGui, MinHook, Win32/DX11. Ядро сканера (`src/Core`) платформенно-независимое — чтение памяти за интерфейсом `IReader` (внутренний memcpy для DLL, `ReadProcessMemory` для EXE).
