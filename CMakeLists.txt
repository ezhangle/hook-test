project (hook_test)

cmake_minimum_required (VERSION 3.3)

include (axl_cmake.cmake)

include_directories (${AXL_INC_DIR})
link_directories (${AXL_LIB_DIR})

add_executable (
	hook_test
	main.cpp
	pch.cpp
	pch.h
	thunk_x86.asm
	thunk_amd64_msc.asm
	thunk_amd64_gcc.asm
	)

axl_set_pch(
	hook_test
	pch.h
	pch.cpp
	)

target_link_libraries (
	hook_test
	axl_io
	axl_core
	)

if (WIN32)
	target_link_libraries (
		hook_test
		dbghelp
		)
else()
	target_link_libraries (
		hook_test
		pthread
		)
endif()
