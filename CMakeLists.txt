project (cpp_test)

cmake_minimum_required (VERSION 3.3)

include (axl_cmake.cmake)

include_directories (${AXL_INC_DIR})
link_directories (${AXL_LIB_DIR})

add_executable (
	cpp_test 
	main.cpp
	thunk.asm
	)

target_link_libraries (
	cpp_test
	axl_io
	axl_core
	dbghelp
	)