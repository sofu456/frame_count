project(frame_count)

if(WIN32)
aux_source_directory(dbghelp code)
set(code hook/win32_hooks.cpp)
else()
set(code hook/linux_hooks.cpp)
endif()

include_directories(. D:/Opensource/boost_1_78_0)
link_directories(D:/Opensource/boost_1_78_0/stage/lib)
add_executable(frame_count frame.cpp)
add_library(hook_dll SHARED ${code})