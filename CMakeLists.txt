project(frame_count)
message(--------------------------------)
message("replace the boost locate")
include_directories(. D:/Opensource/boost_1_78_0)
link_directories(D:/Opensource/boost_1_78_0/stage/lib)
message(--------------------------------)


if(WIN32)
add_compile_definitions(/std:c++17)
aux_source_directory(dbghelp code)
set(code hook/win32_hooks.cpp)
else()
set(code hook/linux_hooks.cpp)
endif()

add_executable(frame_count frame.cpp)
add_library(hook_dll SHARED ${code})
target_link_libraries(hook_dll imagehlp.lib)