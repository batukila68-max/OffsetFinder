cmake_minimum_required(VERSION 3.20)
project(OffsetFinder LANGUAGES C CXX)

if(NOT WIN32)
    message(STATUS "Non-Windows host: building host tests only (the tool itself is Windows/DX11-only).")
    option(OF_HOST_TESTS "Build host-side unit tests" ON)
    if(OF_HOST_TESTS)
        enable_testing()
        add_executable(of_tests Tests/core_tests.cpp
            src/Core/Pattern.cpp src/Core/Scanner.cpp src/Core/Types.cpp
            src/Core/SigScan.cpp src/Core/PointerChain.cpp src/Core/Export.cpp
            src/Core/Process.cpp)
        target_include_directories(of_tests PRIVATE src)
        target_compile_features(of_tests PRIVATE cxx_std_17)
        add_test(NAME core COMMAND of_tests)
    endif()
    return()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui)
add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp)
target_include_directories(imgui PUBLIC ${IMGUI_DIR})
target_compile_definitions(imgui PRIVATE UNICODE _UNICODE NOMINMAX)

set(MINHOOK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook)
add_library(minhook STATIC
    ${MINHOOK_DIR}/src/buffer.c ${MINHOOK_DIR}/src/hook.c
    ${MINHOOK_DIR}/src/trampoline.c
    ${MINHOOK_DIR}/src/hde/hde32.c ${MINHOOK_DIR}/src/hde/hde64.c)
target_include_directories(minhook PUBLIC ${MINHOOK_DIR}/include)

set(CORE_SOURCES
    src/Core/Pattern.cpp src/Core/Scanner.cpp src/Core/Types.cpp
    src/Core/SigScan.cpp src/Core/PointerChain.cpp src/Core/Export.cpp
    src/Core/Process.cpp)
set(UI_SOURCES src/Ui/ScannerUi.cpp)
set(OF_LIBS imgui d3d11 dxgi d3dcompiler dwmapi)

add_executable(OffsetFinder WIN32 src/Exe/main_win32.cpp
    ${CORE_SOURCES} ${UI_SOURCES})
add_library(OffsetFinderDll SHARED src/Dll/dllmain.cpp src/Dll/overlay.cpp
    ${CORE_SOURCES} ${UI_SOURCES})

foreach(target OffsetFinder OffsetFinderDll)
    target_include_directories(${target} PRIVATE src)
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE NOMINMAX)
    target_link_libraries(${target} PRIVATE ${OF_LIBS})
endforeach()
target_link_libraries(OffsetFinderDll PRIVATE minhook)

if(MSVC)
    foreach(target imgui minhook OffsetFinder OffsetFinderDll)
        target_compile_options(${target} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/utf-8>")
        set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endforeach()
    target_compile_options(OffsetFinder PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/W4>")
    target_compile_options(OffsetFinderDll PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/W4>")
    target_link_options(OffsetFinder PRIVATE /MANIFEST:NO)
endif()

if(MINGW)
    target_link_options(OffsetFinder PRIVATE -municode -static -static-libgcc -static-libstdc++)
    target_link_options(OffsetFinderDll PRIVATE -static -static-libgcc -static-libstdc++)
endif()

set_target_properties(OffsetFinder PROPERTIES OUTPUT_NAME "OffsetFinder")
set_target_properties(OffsetFinderDll PROPERTIES OUTPUT_NAME "OffsetFinder" PREFIX "")
